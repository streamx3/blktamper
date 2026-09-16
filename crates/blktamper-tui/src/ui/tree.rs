//! The region tree: everything discovered on the device, with offsets (R-5.1).

use crate::app::{App, Focus};
use crate::theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState};
use ratatui::Frame;

/// Compact offsets for the tree, where a full 10-digit address would crowd out the
/// name. Full precision is always one keypress away in the status bar.
fn short_offset(b: u64) -> String {
    if b == 0 {
        "0".into()
    } else {
        format!("{b:X}")
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let focused = super::is_focused(app, Focus::Tree);
    let items: Vec<ListItem> = app
        .session
        .regions
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let indent = "  ".repeat(r.depth);
            let marker = if i == app.region { ">" } else { " " };
            let conf = if r.score >= 80 {
                theme::status_style(blktamper_core::Status::Ok)
            } else {
                theme::status_style(blktamper_core::Status::Warn)
            };
            // The offset matters more than a long format name, so the name is what
            // gives way when the pane is narrow.
            let room = (area.width as usize).saturating_sub(indent.len() + 14);
            let mut label = r.label.clone();
            if label.chars().count() > room {
                label = label.chars().take(room.saturating_sub(1)).collect::<String>() + "~";
            }
            ListItem::new(Line::from(vec![
                Span::raw(format!("{marker}{indent}")),
                Span::styled(label, conf),
                Span::raw(" "),
                Span::styled(short_offset(r.base), theme::DIM),
            ]))
        })
        .collect();

    let items = if items.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(" (none found)", theme::DIM)))]
    } else {
        items
    };
    let mut state = ListState::default();
    state.select(app.has_regions().then_some(app.region));
    let list = List::new(items)
        .block(super::pane_block("Regions", focused))
        .highlight_style(theme::HIGHLIGHT);
    f.render_stateful_widget(list, area, &mut state);
}
