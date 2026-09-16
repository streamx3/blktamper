//! The field detail popup: everything known about one field, in one place.

use crate::app::App;
use crate::theme;
use blktamper_core::render::{fmt_offset, render_value};
use blktamper_core::value::{ascii_lossy, hex_bytes};
use blktamper_core::FormatId;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};
use ratatui::Frame;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let ctx = app.render_ctx();
    let path = app.selected_path();
    let sector_size = app.session.sector_size as u64;
    let Some(node) = app.selected_node() else { return };

    let mut lines: Vec<Line> = Vec::new();
    let kv = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!(" {k:<11}"), theme::HEADER),
            Span::raw(v),
        ])
    };

    if let Some(s) = node.extent.first() {
        let lba = s.start_byte() / sector_size.max(1);
        let within = s.start_byte() % sector_size.max(1);
        lines.push(kv(
            "Offset",
            format!("{}  (LBA {lba} + {within})", fmt_offset(s.start_byte())),
        ));
        lines.push(kv(
            "Size",
            if s.is_byte_aligned() {
                format!("{} bytes ({} bits)", s.byte_len(), s.len_bits)
            } else {
                format!("{} bit(s) at bit {}", s.len_bits, s.start_bit % 8)
            },
        ));
    }
    if let blktamper_core::Extent::Many(spans) = &node.extent {
        lines.push(kv(
            "Extents",
            format!(
                "{} pieces: {}",
                spans.len(),
                spans
                    .iter()
                    .take(4)
                    .map(|s| fmt_offset(s.start_byte()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    if !node.raw.is_empty() {
        lines.push(kv("Raw", hex_bytes(&node.raw[..node.raw.len().min(24)])));
    }
    lines.push(Line::from(""));

    if let Some(n) = node.value.as_u64() {
        lines.push(Line::from(vec![
            Span::styled(" hex        ", theme::HEADER),
            Span::raw(format!("{n:#X}")),
            Span::styled("      dec        ", theme::HEADER),
            Span::raw(blktamper_core::value::group_digits(n)),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" oct        ", theme::HEADER),
            Span::raw(format!("{n:#o}")),
            Span::styled("      bin        ", theme::HEADER),
            Span::raw(format!("{n:#b}")),
        ]));
    }
    if !node.raw.is_empty() {
        lines.push(kv("ascii", format!("\"{}\"", ascii_lossy(&node.raw, false))));
    }
    lines.push(Line::from(""));
    lines.push(kv("Decoded", render_value(node, &ctx)));

    if let Some(d) = &node.derived {
        lines.push(kv(
            "Computed",
            format!(
                "{} - {} ({})",
                d.value,
                if d.matches { "matches" } else { "DOES NOT MATCH" },
                d.how
            ),
        ));
        if !d.matches {
            lines.push(Line::from(Span::styled(
                "             this build is read-only; :recompute lands with the write path",
                theme::DIM,
            )));
        }
    }

    if let Some(doc) = node.doc {
        if !doc.is_empty() {
            lines.push(Line::from(""));
            lines.push(kv("Doc", doc.to_string()));
        }
    }
    if !node.links.is_empty() {
        lines.push(Line::from(""));
        for l in &node.links {
            let target = l
                .resolved
                .map(|b| format!("{} (raw {})", fmt_offset(b), l.raw))
                .unwrap_or_else(|| format!("raw {}", l.raw));
            lines.push(kv("Link", format!("-> {} at {target}   [g]", l.label)));
        }
    }
    for d in &node.diags {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", d.status.glyph()), theme::status_style(d.status)),
            Span::styled(d.message.clone(), theme::status_style(d.status)),
        ]));
        if let Some(h) = &d.hint {
            lines.push(Line::from(Span::styled(format!("   {h}"), theme::DIM)));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " [y] value  [Y] labelled  [y h] hex  [y p] path  [g] follow  [any] close",
        theme::DIM,
    )));

    let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let rect = super::centered(area, 78, h);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).block(super::popup_block(&path)).wrap(Wrap { trim: false }),
        rect,
    );
}

/// The "interpret as" chooser, shown when probing finds more than one plausible
/// format and none is confident. Ranked candidates beat a confident wrong guess.
pub fn draw_interpret(
    f: &mut Frame,
    area: Rect,
    at: u64,
    options: &[(FormatId, String, u8)],
    sel: usize,
) {
    let mut lines = vec![
        Line::from(Span::styled(
            format!(" Nothing is certain at {}. Candidates:", fmt_offset(at)),
            theme::DIM,
        )),
        Line::from(""),
    ];
    for (i, (id, name, score)) in options.iter().enumerate() {
        let marker = if i == sel { ">" } else { " " };
        let style = if i == sel { theme::HIGHLIGHT } else { ratatui::style::Style::default() };
        lines.push(Line::from(Span::styled(
            format!(" {marker} {name:<28} {id:<8} confidence {score:>3}"),
            style,
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " [j/k] choose  [Enter] open  [any] cancel",
        theme::DIM,
    )));

    let rect = super::centered(area, 64, lines.len() as u16 + 2);
    f.render_widget(Clear, rect);
    f.render_widget(Paragraph::new(lines).block(super::popup_block("interpret as")), rect);
}
