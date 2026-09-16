//! The scrub and commit dialogs.
//!
//! Both exist to make the blast radius visible before it happens. The scrub dialog
//! says what the record holds, what survives, and what it will *not* touch; the
//! commit dialog says which sectors get rewritten in full and asks for the device
//! name to be typed (ADR-011, doc/07-write-safety.md).

use crate::app::App;
use crate::theme;
use blktamper_core::render::fmt_offset;
use blktamper_core::scrub::{Fill, ScrubPlan};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};
use ratatui::Frame;

/// Inner width of the dialog, less the border and the 12-column label gutter.
const BOX_W: u16 = 78;
const TEXT_W: usize = BOX_W as usize - 2 - 12;
const GUTTER: usize = 12;

fn kv<'a>(k: &'a str, v: String) -> Line<'a> {
    Line::from(vec![Span::styled(format!(" {k:<11}"), theme::HEADER), Span::raw(v)])
}

fn cont(v: String) -> Line<'static> {
    Line::from(vec![Span::raw(" ".repeat(GUTTER)), Span::raw(v)])
}

/// A labelled value, wrapped to the gutter. Everything is pre-wrapped here rather
/// than by `Paragraph`, whose re-flow would ignore the aligned columns and break
/// lines at column zero.
fn kv_wrapped(k: &str, v: &str) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for (i, chunk) in wrap(v, TEXT_W).into_iter().enumerate() {
        if i == 0 {
            out.push(Line::from(vec![
                Span::styled(format!(" {k:<11}"), theme::HEADER),
                Span::raw(chunk),
            ]));
        } else {
            out.push(cont(chunk));
        }
    }
    out
}

/// A bulleted list under one label, each item wrapped and hanging-indented.
fn kv_list(k: &str, items: &[String]) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut first_label = true;
    for item in items {
        for (j, chunk) in wrap(item, TEXT_W - 2).into_iter().enumerate() {
            match (first_label, j) {
                (true, 0) => out.push(Line::from(vec![
                    Span::styled(format!(" {k:<11}"), theme::HEADER),
                    Span::raw(chunk),
                ])),
                (false, 0) => out.push(cont(chunk)),
                _ => out.push(cont(format!("  {chunk}"))),
            }
            first_label = false;
        }
    }
    out
}

pub fn draw(f: &mut Frame, area: Rect, app: &App, plan: &ScrubPlan) {
    let ss = app.session.sector_size as u64;
    let mut lines: Vec<Line> = Vec::new();

    lines.extend(kv_wrapped("Record", &plan.label));
    lines.push(cont(format!(
        "{} record(s), {} bytes at {}",
        plan.records(),
        plan.records() * 32,
        plan.edits.first().map(|e| fmt_offset(e.offset)).unwrap_or_default()
    )));
    lines.push(Line::from(""));

    // The two fills, with the refusal spelled out rather than the option just absent.
    let mark = |on: bool| if on { "(o)" } else { "( )" };
    lines.push(Line::from(vec![
        Span::styled(" Fill       ", theme::HEADER),
        Span::styled(
            format!("{} neutral", mark(plan.fill == Fill::Neutral)),
            if plan.fill == Fill::Neutral { theme::HIGHLIGHT } else { Default::default() },
        ),
        Span::styled(format!("   {}", Fill::Neutral.describe()), theme::DIM),
    ]));
    let zero_style = if !plan.zero_available() {
        theme::status_style(blktamper_core::Status::Warn)
    } else if plan.fill == Fill::Zero {
        theme::HIGHLIGHT
    } else {
        Default::default()
    };
    lines.push(Line::from(vec![
        Span::raw(" ".repeat(GUTTER)),
        Span::styled(format!("{} zero", mark(plan.fill == Fill::Zero)), zero_style),
        Span::styled(
            if plan.zero_available() {
                format!("      {}", Fill::Zero.describe())
            } else {
                "      REFUSED HERE:".to_string()
            },
            if plan.zero_available() {
                theme::DIM
            } else {
                theme::status_style(blktamper_core::Status::Warn)
            },
        ),
    ]));
    if let Some(r) = &plan.zero_refusal {
        for chunk in wrap(&r.message(), TEXT_W - 6) {
            lines.push(Line::from(Span::styled(
                format!("{}{chunk}", " ".repeat(GUTTER + 6)),
                theme::status_style(blktamper_core::Status::Warn),
            )));
        }
    }
    lines.push(Line::from(""));

    lines.extend(kv_list("Removes", &plan.removes));
    lines.extend(kv_list("Keeps", &plan.keeps));

    for w in &plan.warnings {
        lines.push(Line::from(""));
        for (i, chunk) in wrap(&w.message, TEXT_W).into_iter().enumerate() {
            let text = if i == 0 {
                format!(" !          {chunk}")
            } else {
                format!("{}{chunk}", " ".repeat(GUTTER))
            };
            lines.push(Line::from(Span::styled(text, theme::status_style(w.status))));
        }
    }

    lines.push(Line::from(""));
    let sectors = plan.sectors_touched(ss);
    let total: usize = sectors.iter().map(|(_, c)| c).sum();
    lines.extend(kv_wrapped(
        "Rewrites",
        &format!(
            "{} sector(s) of {ss} B, in full; {total} of {} bytes actually change, and \
             every other record in them is preserved",
            sectors.len(),
            sectors.len() as u64 * ss
        ),
    ));

    lines.push(Line::from(""));
    let armed = app.session.write.armed();
    for chunk in wrap(
        if armed {
            "[Enter] stage   [n] neutral   [z] zero   [Esc] cancel"
        } else {
            "[Enter] stage   [n] neutral   [z] zero   [Esc] cancel   -- staging writes \
             nothing; :arm and :commit are still needed to reach the device"
        },
        BOX_W as usize - 4,
    ) {
        lines.push(Line::from(Span::styled(format!(" {chunk}"), theme::DIM)));
    }

    let h = (lines.len() as u16 + 2).min(area.height);
    let rect = super::centered(area, BOX_W, h);
    f.render_widget(Clear, rect);
    f.render_widget(Paragraph::new(lines).block(super::popup_block("scrub deleted record")), rect);
}

pub fn draw_commit(f: &mut Frame, area: Rect, app: &App, typed: &str) {
    let ss = app.session.sector_size as u64;
    let staged = app.session.overlay.staged();
    let sectors = app.session.overlay.sectors_touched(ss);
    let want = app
        .session
        .info
        .path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut lines = vec![
        kv("Device", app.session.info.path.display().to_string()),
        kv(
            "",
            format!("{} — {}", blktamper_core::value::human_size(app.session.info.len), app.session.info.kind.label()),
        ),
    ];
    if app.session.info.is_mounted() {
        lines.push(Line::from(""));
        for m in &app.session.info.mounts {
            lines.push(Line::from(Span::styled(
                format!(" WARNING    /dev/{} is mounted at {}", m.device, m.mount_point),
                theme::WARN_BANNER,
            )));
        }
        lines.push(cont("writing a mounted volume's metadata corrupts it or panics the kernel".into()));
    }
    if app.session.info.rotational == Some(false) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " NOTE       solid-state device: an overwrite changes the mapping, not".to_string(),
            theme::DIM,
        )));
        lines.push(cont("necessarily the cell. Physical erasure is out of scope.".into()));
    }

    lines.push(Line::from(""));
    lines.push(kv("Edits", format!("{} staged, {} bytes", staged.len(), app.session.overlay.bytes_changed())));
    for s in staged.iter().take(8) {
        lines.push(cont(format!(
            "{}  {} B  {}",
            fmt_offset(s.edit.offset),
            s.edit.new.len(),
            s.path
        )));
    }
    if staged.len() > 8 {
        lines.push(cont(format!("... and {} more", staged.len() - 8)));
    }

    lines.push(Line::from(""));
    lines.push(kv(
        "Rewrites",
        format!("{} sector(s) of {ss} B, in full", sectors.len()),
    ));
    lines.push(kv("Journal", format!("originals go to {}", blktamper_io::Journal::default_dir().display())));

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Confirm    ", theme::HEADER),
        Span::raw(format!("type \"{want}\": ")),
        Span::styled(format!("{typed}_"), theme::HIGHLIGHT),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" [Enter] write   [Esc] cancel", theme::DIM)));

    let h = (lines.len() as u16 + 2).min(area.height);
    let rect = super::centered(area, 76, h);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).block(super::popup_block("COMMIT — this writes to the device")),
        rect,
    );
}

/// Wrap on word boundaries. `Paragraph`'s own wrap would re-flow the aligned
/// key/value columns, so the columns are built here and the text is pre-wrapped.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}
