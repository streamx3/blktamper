//! Drawing. Three panes, always the same three: where am I (region tree), what is
//! here (field table), what bytes is that (hex). See doc/05-tui-design.md.

mod detail;
mod help;
mod hex;
mod table;
mod tree;

use crate::app::{App, Focus, Popup};
use crate::theme;
use blktamper_core::render::fmt_offset;
use blktamper_core::value::human_size;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Stylize;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Below this width the tree pane costs more than it gives; collapse to a
/// breadcrumb (doc/05-tui-design.md, "80x24 must work").
const NARROW: u16 = 100;
const TREE_WIDTH: u16 = 30;
const HEX_ROWS: u16 = 6;

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let show_hex = app.hex_visible && area.height >= 18;
    let show_tree = !app.wide && area.width >= NARROW;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),                                    // title
            Constraint::Min(5),                                       // body
            Constraint::Length(if show_hex { HEX_ROWS + 2 } else { 0 }), // hex
            Constraint::Length(1),                                    // status
        ])
        .split(area);

    draw_title(f, chunks[0], app);

    let body = if show_tree {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(TREE_WIDTH), Constraint::Min(20)])
            .split(chunks[1]);
        tree::draw(f, cols[0], app);
        cols[1]
    } else {
        chunks[1]
    };
    table::draw(f, body, app);

    if show_hex {
        hex::draw(f, chunks[2], app);
    }
    draw_status(f, chunks[3], app);

    match app.popup.clone() {
        Popup::Help => help::draw(f, area),
        Popup::Detail => detail::draw(f, area, app),
        Popup::Interpret { at, options, sel } => {
            detail::draw_interpret(f, area, at, &options, sel)
        }
        Popup::Command { buffer } => draw_command(f, chunks[3], &buffer),
        Popup::None => {}
    }
}

fn draw_title(f: &mut Frame, area: Rect, app: &App) {
    let i = &app.session.info;
    // Order matters: everything that must survive truncation on a narrow terminal
    // comes first, and "READ-ONLY" is the single most important fact on the screen.
    let name = i
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| i.path.display().to_string());
    let mut spans = vec![
        Span::styled("blktamper", theme::HEADER),
        Span::raw(" "),
        Span::styled("READ-ONLY", theme::DIM),
        Span::raw("  "),
        Span::raw(name),
        Span::raw("  "),
        Span::raw(human_size(i.len)),
        Span::raw("  "),
        Span::raw(format!("{}/{} B", app.session.sector_size, i.physical_sector_size)),
    ];
    if app.session.sector_size != i.logical_sector_size {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("sector size overridden (device says {})", i.logical_sector_size),
            theme::WARN_BANNER,
        ));
    }
    if i.is_mounted() {
        let names: Vec<String> =
            i.mounts.iter().map(|m| format!("{} on {}", m.device, m.mount_point)).collect();
        spans.push(Span::raw("  "));
        spans.push(Span::styled(format!(" MOUNTED: {} ", names.join(", ")), theme::WARN_BANNER));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_status(f: &mut Frame, area: Rect, app: &mut App) {
    let path = app.selected_path();
    let filter = app.filter.label();
    let node_bits = match app.selected_node() {
        Some(n) => {
            let loc = n
                .extent
                .first()
                .map(|s| {
                    if s.is_byte_aligned() {
                        format!("{} ({} B)", fmt_offset(s.start_byte()), s.byte_len())
                    } else {
                        format!("{}.{} ({} bit)", fmt_offset(s.start_byte()), s.start_bit % 8, s.len_bits)
                    }
                })
                .unwrap_or_else(|| "computed".into());
            loc.to_string()
        }
        None => String::new(),
    };

    let left = format!(" {path}   {node_bits}   filter:{filter} ");
    let right = if app.message.is_empty() {
        "  ? help   : command   q quit ".to_string()
    } else {
        format!("  {} ", app.message)
    };

    let pad = (area.width as usize).saturating_sub(left.len() + right.len());
    let line = Line::from(vec![
        Span::raw(left),
        Span::raw(" ".repeat(pad)),
        Span::styled(right, if app.message.is_empty() { theme::DIM } else { theme::HEADER }),
    ]);
    f.render_widget(Paragraph::new(line).on_black(), area);
}

fn draw_command(f: &mut Frame, area: Rect, buffer: &str) {
    let line = Line::from(vec![Span::styled(format!(":{buffer}_"), theme::HEADER)]);
    f.render_widget(Paragraph::new(line), area);
}

/// Centre a box of the given size inside `area`, clamped to fit.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(2));
    let h = h.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

pub fn popup_block(title: &str) -> Block<'_> {
    Block::default().borders(Borders::ALL).title(format!(" {title} ")).title_style(theme::HEADER)
}

/// Focus-aware border title, so it is always obvious which pane keys go to.
pub fn pane_block(title: &str, focused: bool) -> Block<'_> {
    let b = Block::default().borders(Borders::ALL).title(format!(" {title} "));
    if focused {
        b.title_style(theme::HEADER).border_style(theme::HEADER)
    } else {
        b.border_style(theme::DIM)
    }
}

pub fn is_focused(app: &App, f: Focus) -> bool {
    app.focus == f
}
