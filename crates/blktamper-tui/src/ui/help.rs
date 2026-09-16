//! The key map, on one screen.

use crate::theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};
use ratatui::Frame;

const KEYS: &[(&str, &str)] = &[
    ("MOVE", ""),
    ("j k / arrows", "row down / up"),
    ("PgDn PgUp", "full page"),
    ("Ctrl-d Ctrl-u", "half page"),
    ("Home / G", "first / last row"),
    ("l h / arrows", "expand / collapse"),
    ("Tab", "switch pane"),
    ("[ ]", "previous / next region"),
    ("", ""),
    ("NAVIGATE", ""),
    ("g", "follow the selected field's link"),
    ("Ctrl-o Ctrl-r", "jump stack back / forward"),
    (":0x1BE", "go to byte offset"),
    (":lba 2048", "go to LBA"),
    (":probe", "what formats match here?"),
    (":as gpt", "force an interpretation here"),
    (":sector 4096", "change sector size and re-probe"),
    ("", ""),
    ("DISPLAY", ""),
    ("z", "cycle filter: all / hide-empty / anomalies"),
    ("Z", "show or hide unclaimed gaps"),
    ("H", "toggle the hex pane"),
    ("w", "wide mode (hide the region tree)"),
    ("Enter / i", "field detail"),
    ("", ""),
    ("COPY", ""),
    ("y", "decoded value"),
    ("Y", "label + raw + decoded + offset"),
    ("y h", "hex dump of this node"),
    ("y r", "raw bytes as hex, unspaced"),
    ("y p", "node path"),
    ("y t", "whole visible table as TSV"),
    ("", ""),
    ("q / Ctrl-c", "quit"),
];

pub fn draw(f: &mut Frame, area: Rect) {
    let lines: Vec<Line> = KEYS
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                Line::from(Span::styled(format!(" {k}"), theme::HEADER))
            } else {
                Line::from(vec![
                    Span::styled(format!("  {k:<16}"), theme::HEADER),
                    Span::raw(*v),
                ])
            }
        })
        .collect();
    let h = (lines.len() as u16 + 2).min(area.height);
    let rect = super::centered(area, 60, h);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).block(super::popup_block("keys - read-only build")),
        rect,
    );
}
