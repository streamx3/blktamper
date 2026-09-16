//! The one place that turns semantics into colour.
//!
//! Nothing below the TUI knows what red means (R-8.2), and everything here degrades:
//! status is carried by a single-width ASCII glyph as well as by colour, so the app
//! stays usable on a monochrome 80x24 terminal (R-4.8).

use blktamper_core::{FieldFlags, Node, NodeKind, Status};
use ratatui::style::{Color, Modifier, Style};

pub fn status_style(s: Status) -> Style {
    match s {
        Status::Ok => Style::default(),
        Status::Info => Style::default().fg(Color::Cyan),
        Status::Warn => Style::default().fg(Color::Yellow),
        Status::Bad => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Status::Unreadable => Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
    }
}

/// The gutter glyph: single-width ASCII so column alignment survives every terminal.
pub fn gutter(node: &Node) -> char {
    if node.status != Status::Ok {
        return node.status.glyph();
    }
    if node.derived.as_ref().is_some_and(|d| !d.matches) {
        return 'X';
    }
    if !node.links.is_empty() {
        return '*';
    }
    if node.flags.has(FieldFlags::RESERVED) || node.flags.has(FieldFlags::MUST_ZERO) {
        return 'r';
    }
    if node.children.len_hint().is_none_or(|n| n > 0) && !node.children.is_none() {
        return '+';
    }
    ' '
}

pub fn label_style(node: &Node) -> Style {
    let base = status_style(node.deep_status());
    match node.kind {
        NodeKind::Region => base.add_modifier(Modifier::BOLD),
        NodeKind::Gap => base.fg(Color::DarkGray),
        NodeKind::Bit => base.fg(Color::DarkGray),
        _ if node.flags.has(FieldFlags::LEGACY) => base.add_modifier(Modifier::DIM),
        _ if node.flags.has(FieldFlags::OPAQUE) => base.fg(Color::DarkGray),
        _ => base,
    }
}

pub fn value_style(node: &Node) -> Style {
    if node.derived.as_ref().is_some_and(|d| !d.matches) {
        return Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    }
    if node.derived.as_ref().is_some_and(|d| d.matches) {
        return Style::default().fg(Color::Green);
    }
    status_style(node.status)
}

pub const HIGHLIGHT: Style = Style::new().bg(Color::Indexed(238)).add_modifier(Modifier::BOLD);
pub const HEX_SELECTED: Style = Style::new().fg(Color::Black).bg(Color::Yellow);
pub const DIM: Style = Style::new().fg(Color::DarkGray);
pub const HEADER: Style = Style::new().fg(Color::Indexed(245)).add_modifier(Modifier::BOLD);
pub const WARN_BANNER: Style = Style::new().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD);
