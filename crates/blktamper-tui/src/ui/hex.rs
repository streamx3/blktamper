//! The hex pane.
//!
//! Whatever row is selected, its bytes are highlighted here. This is the feature
//! that makes the labels trustworthy: you can always see that the tool is not
//! lying to you about where a value came from (doc/05-tui-design.md).

use crate::app::App;
use crate::theme;
use blktamper_core::render::fmt_offset;
use blktamper_core::value::ascii_lossy;
use blktamper_core::{BlockSource, Extent, ReadOutcome};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

const BYTES_PER_LINE: u64 = 16;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let rows = area.height.saturating_sub(2) as u64;
    let extent = app.selected_node().map(|n| n.extent.clone()).unwrap_or(Extent::None);
    let focus_byte = extent.min_byte().unwrap_or(0);

    // Centre the selection, but never scroll before the start of the device.
    let first_line = focus_byte / BYTES_PER_LINE;
    let start_line = first_line.saturating_sub(rows / 3);
    let start = start_line * BYTES_PER_LINE;
    let want = (rows * BYTES_PER_LINE) as usize;

    let (buf, outcome) = app.session.src.read_vec(start, want);
    let title = match extent.first() {
        Some(s) => format!(
            "Hex  {}..{}",
            fmt_offset(s.start_byte()),
            fmt_offset(s.end_byte())
        ),
        None => "Hex".to_string(),
    };

    let mut lines: Vec<Line> = Vec::with_capacity(rows as usize);
    if outcome == ReadOutcome::Unreadable {
        lines.push(Line::from(Span::styled(
            format!(
                "  the device returned an I/O error for {} - these bytes are NOT zeros",
                fmt_offset(start)
            ),
            theme::status_style(blktamper_core::Status::Unreadable),
        )));
    }

    for row in 0..rows {
        let line_start = start + row * BYTES_PER_LINE;
        let lo = (row * BYTES_PER_LINE) as usize;
        if lo >= buf.len() {
            break;
        }
        let hi = (lo + BYTES_PER_LINE as usize).min(buf.len());
        let chunk = &buf[lo..hi];

        let mut spans = vec![Span::styled(format!("{line_start:08X}  "), theme::DIM)];
        for (i, b) in chunk.iter().enumerate() {
            if i == 8 {
                spans.push(Span::raw(" "));
            }
            let addr = line_start + i as u64;
            let sel = extent.contains_byte(addr);
            spans.push(Span::styled(
                format!("{b:02X} "),
                if sel { theme::HEX_SELECTED } else { ratatui::style::Style::default() },
            ));
        }
        for i in chunk.len()..BYTES_PER_LINE as usize {
            if i == 8 {
                spans.push(Span::raw(" "));
            }
            spans.push(Span::raw("   "));
        }
        spans.push(Span::raw(" |"));
        for (i, b) in chunk.iter().enumerate() {
            let addr = line_start + i as u64;
            let sel = extent.contains_byte(addr);
            let ch = ascii_lossy(&[*b], false);
            spans.push(Span::styled(
                ch,
                if sel { theme::HEX_SELECTED } else { ratatui::style::Style::default() },
            ));
        }
        spans.push(Span::raw("|"));
        lines.push(Line::from(spans));
    }

    f.render_widget(Paragraph::new(lines).block(super::pane_block(&title, false)), area);
}
