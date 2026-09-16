//! The field table: name, raw bytes, decoded value, and a status gutter.

use crate::app::{App, Focus};
use crate::rows::{self};
use crate::theme;
use blktamper_core::render::{render_raw, render_value};
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let focused = super::is_focused(app, Focus::Table);
    if !app.has_regions() {
        draw_nothing_found(f, area, app, focused);
        return;
    }
    let title = breadcrumb(app);
    let ctx = app.render_ctx();

    // Reserve the bottom for diagnostics of the selected row, when there are any.
    let diag_lines = app
        .selected_node()
        .map(|n| n.diags.len().min(3) as u16)
        .unwrap_or(0);
    let (table_area, diag_area) = if diag_lines > 0 && area.height > diag_lines + 4 {
        let split = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(diag_lines + 1)])
            .split(area);
        (split[0], Some(split[1]))
    } else {
        (area, None)
    };

    let root = app.session.regions[app.region].root_mut().clone();
    let elide_at: std::collections::HashMap<usize, usize> =
        app.rowset.elisions.iter().map(|e| (e.after_row, e.hidden)).collect();

    let mut rows: Vec<Row> = Vec::with_capacity(app.rowset.rows.len());
    for (i, r) in app.rowset.rows.iter().enumerate() {
        if let Some(hidden) = elide_at.get(&i) {
            rows.push(Row::new(vec![
                Cell::from(" "),
                Cell::from(Span::styled(
                    format!("{}... {hidden} empty hidden", "  ".repeat(r.depth)),
                    theme::DIM,
                )),
                Cell::from(""),
                Cell::from(""),
            ]));
        }
        let Some(node) = rows::node_at(&root, &r.index_path) else { continue };
        let indent = "  ".repeat(r.depth);
        let arrow = if r.expandable {
            if r.expanded {
                "v "
            } else {
                "> "
            }
        } else {
            "  "
        };
        let raw = render_raw(node, 8);
        let val = render_value(node, &ctx);
        rows.push(Row::new(vec![
            Cell::from(Span::styled(
                theme::gutter(node).to_string(),
                theme::status_style(node.deep_status()),
            )),
            Cell::from(Span::styled(
                format!("{indent}{arrow}{}", node.label),
                theme::label_style(node),
            )),
            Cell::from(Span::styled(raw, theme::DIM)),
            Cell::from(Span::styled(val, theme::value_style(node))),
        ]));
    }

    // The decoded column carries the meaning, so it gets what is left rather than a
    // fixed share: on a narrow terminal it is the raw bytes that should give way.
    let widths = [
        Constraint::Length(1),
        Constraint::Length(34),
        Constraint::Length(26),
        Constraint::Min(20),
    ];
    let header = Row::new(vec![
        Cell::from(" "),
        Cell::from(Span::styled("Field", theme::HEADER)),
        Cell::from(Span::styled("Raw", theme::HEADER)),
        Cell::from(Span::styled("Decoded", theme::HEADER)),
    ]);

    // Elision rows shift the visual index; map the logical selection onto it.
    let visual = app.row + app.rowset.elisions.iter().filter(|e| e.after_row <= app.row).count();
    let mut state = TableState::default();
    state.select(Some(visual));

    let table = Table::new(rows, widths)
        .header(header)
        .block(super::pane_block(&title, focused))
        .row_highlight_style(theme::HIGHLIGHT);
    f.render_stateful_widget(table, table_area, &mut state);

    if let Some(da) = diag_area {
        draw_diags(f, da, app);
    }
}

fn draw_diags(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(node) = app.selected_node() else { return };
    let mut lines = Vec::new();
    for d in node.diags.iter().take(3) {
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", d.status.glyph()), theme::status_style(d.status)),
            Span::styled(d.message.clone(), theme::status_style(d.status)),
        ]));
        if let Some(h) = &d.hint {
            lines.push(Line::from(Span::styled(format!("   {h}"), theme::DIM)));
        }
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

/// Nothing was recognised. Say exactly that, and say what to do next — a blank
/// pane would imply the device is empty, which is a different claim entirely.
fn draw_nothing_found(f: &mut Frame, area: Rect, app: &App, focused: bool) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  No known structure was recognised on this device.",
            theme::status_style(blktamper_core::Status::Warn),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  That is a statement about the metadata, not about the data: the bytes",
            theme::DIM,
        )),
        Line::from(Span::styled(
            "  are still there and still shown in the hex pane below.",
            theme::DIM,
        )),
        Line::from(""),
        Line::from(Span::styled("  :0x1000        look at a byte offset", theme::DIM)),
        Line::from(Span::styled("  :probe         what, if anything, matches there", theme::DIM)),
        Line::from(Span::styled(
            format!(
                "  :as <format>   force an interpretation  ({})",
                app.session
                    .registry
                    .probes()
                    .iter()
                    .map(|p| p.id().0)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            theme::DIM,
        )),
        Line::from(Span::styled(
            "  :sector 4096   if this image came off a 4Kn disk",
            theme::DIM,
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).block(super::pane_block("nothing recognised", focused)),
        area,
    );
}

fn breadcrumb(app: &App) -> String {
    let region = app
        .session
        .regions
        .get(app.region)
        .map(|r| r.label.clone())
        .unwrap_or_default();
    match app.rowset.rows.get(app.row) {
        Some(r) => {
            let p = r.path.to_string();
            let short: Vec<&str> = p.split('.').rev().take(3).collect();
            let short: Vec<&str> = short.into_iter().rev().collect();
            format!("{region} > {}", short.join(" > "))
        }
        None => region,
    }
}
