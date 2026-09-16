//! Application state and the key handling that drives it.

use crate::clip::Clipboard;
use crate::rows::{self, Expansion, Filter, RowSet};
use crate::session::Session;
use blktamper_core::render::{copy_hexdump, copy_labelled, copy_tsv, copy_value, fmt_offset};
use blktamper_core::{FormatId, Node, RenderCtx};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Tree,
    Table,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Popup {
    None,
    Help,
    Detail,
    /// Offer the formats that scored above zero at an offset.
    Interpret { at: u64, options: Vec<(FormatId, String, u8)>, sel: usize },
    Command { buffer: String },
}

/// Where we came from, so a 40 GB jump is reversible (R-5.3).
#[derive(Clone, Debug)]
pub struct Jump {
    pub region: usize,
    pub row: usize,
}

pub struct App {
    pub session: Session,
    pub region: usize,
    pub exp: Expansion,
    pub filter: Filter,
    pub show_gaps: bool,
    pub focus: Focus,
    pub row: usize,
    pub rowset: RowSet,
    pub back: Vec<Jump>,
    pub forward: Vec<Jump>,
    pub message: String,
    pub popup: Popup,
    pub clip: Clipboard,
    pub should_quit: bool,
    pub hex_visible: bool,
    pub wide: bool,
    /// Pending multi-key sequence, e.g. `y` waiting for its second key.
    pub pending: Option<char>,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("region", &self.region)
            .field("row", &self.row)
            .field("filter", &self.filter)
            .finish()
    }
}

impl App {
    pub fn new(session: Session) -> App {
        let mut app = App {
            session,
            region: 0,
            exp: Expansion::default(),
            filter: Filter::All,
            show_gaps: true,
            focus: Focus::Table,
            row: 0,
            rowset: RowSet::default(),
            back: Vec::new(),
            forward: Vec::new(),
            message: String::new(),
            popup: Popup::None,
            clip: Clipboard::new(),
            should_quit: false,
            hex_visible: true,
            wide: false,
            pending: None,
        };
        app.enter_region(0);
        app
    }

    pub fn render_ctx(&self) -> RenderCtx {
        RenderCtx {
            sector_size: self.session.sector_size,
            cluster_base: None,
            device_len: self.session.src.len(),
        }
    }

    pub fn has_regions(&self) -> bool {
        !self.session.regions.is_empty()
    }

    pub fn enter_region(&mut self, index: usize) {
        if index >= self.session.regions.len() {
            return;
        }
        self.region = index;
        self.row = 0;
        let root = self.session.regions[index].root_mut().clone();
        self.exp = Expansion::default();
        self.exp.open_top(&root);
        self.rebuild();
    }

    pub fn rebuild(&mut self) {
        if !self.has_regions() {
            self.rowset = RowSet::default();
            self.row = 0;
            return;
        }
        // Lift the tree out so `exp` and the root are not borrowed from `self` at
        // once, then put it straight back. Cheaper than it looks: rebuild only
        // happens on a keypress.
        let taken = self.session.regions[self.region].root_mut().clone();
        self.rowset = rows::flatten(&taken, &self.exp, self.filter, self.show_gaps);
        self.session.regions[self.region].root = Some(taken);
        if self.row >= self.rowset.rows.len() {
            self.row = self.rowset.rows.len().saturating_sub(1);
        }
    }

    pub fn selected_node(&mut self) -> Option<&Node> {
        if !self.has_regions() {
            return None;
        }
        let idx = self.rowset.rows.get(self.row)?.index_path.clone();
        let root = self.session.regions[self.region].root_mut();
        rows::node_at(root, &idx)
    }

    /// The stable identifier for the selected node: `mbr.entries[0].part_type`.
    /// Copied by `y p`, shown in the status bar, and the address a future
    /// `blktamper get <path>` would take.
    pub fn selected_path(&self) -> String {
        match self.rowset.rows.get(self.row) {
            Some(r) => r.path.to_string(),
            None => self
                .session
                .regions
                .get(self.region)
                .map(|r| r.format.0.to_string())
                .unwrap_or_default(),
        }
    }

    fn move_by(&mut self, delta: isize) {
        let len = self.rowset.rows.len();
        if len == 0 {
            return;
        }
        let cur = self.row as isize;
        self.row = (cur + delta).clamp(0, len as isize - 1) as usize;
    }

    fn toggle_expand(&mut self) {
        if !self.has_regions() {
            return;
        }
        let Some(row) = self.rowset.rows.get(self.row).cloned() else { return };
        if !row.expandable {
            return;
        }
        let opening = !self.exp.is_open(&row.path);
        if opening {
            let src = self.session.src.clone();
            let root = self.session.regions[self.region].root_mut();
            rows::resolve_at(root, &row.index_path, &*src);
        }
        self.exp.toggle(&row.path);
        self.rebuild();
    }

    fn collapse_or_up(&mut self) {
        let Some(row) = self.rowset.rows.get(self.row).cloned() else { return };
        if row.expanded {
            self.exp.close(&row.path);
            self.rebuild();
            return;
        }
        // Jump to the parent row.
        if row.depth > 0 {
            for i in (0..self.row).rev() {
                if self.rowset.rows[i].depth < row.depth {
                    self.row = i;
                    break;
                }
            }
        }
    }

    fn follow_link(&mut self) {
        let Some(node) = self.selected_node() else { return };
        let Some(link) = node.links.first().cloned() else {
            self.message = "no link on this field".into();
            return;
        };
        let Some(target) = link.resolved else {
            self.message = format!("{} has no resolvable target", link.label);
            return;
        };
        self.goto_byte(target);
    }

    pub fn goto_byte(&mut self, target: u64) {
        if target >= self.session.src.len() {
            self.message = format!("{} is past the end of the device", fmt_offset(target));
            return;
        }
        self.push_jump();
        // An existing region wins; otherwise offer interpretations.
        if let Some(i) = self.session.regions.iter().position(|r| r.base == target) {
            self.enter_region(i);
            self.message = format!("-> {} @{}", self.session.regions[i].label, fmt_offset(target));
            return;
        }
        let cands = self.session.registry.candidates(&*self.session.src, target);
        if cands.is_empty() {
            self.message =
                format!("nothing recognised at {} - use :as <format> to force", fmt_offset(target));
            return;
        }
        let options: Vec<(FormatId, String, u8)> = cands
            .iter()
            .map(|(id, s)| {
                let name = self
                    .session
                    .registry
                    .get(*id)
                    .map(|p| p.name().to_string())
                    .unwrap_or_else(|| id.0.to_string());
                (*id, name, *s)
            })
            .collect();
        if options.len() == 1 || options[0].2 >= 80 {
            let id = options[0].0;
            if let Some(i) = self.session.interpret_as(id, target) {
                self.enter_region(i);
                self.message = format!("-> {} @{}", options[0].1, fmt_offset(target));
            }
        } else {
            self.popup = Popup::Interpret { at: target, options, sel: 0 };
        }
    }

    fn push_jump(&mut self) {
        self.back.push(Jump { region: self.region, row: self.row });
        self.forward.clear();
    }

    fn jump_back(&mut self) {
        let Some(j) = self.back.pop() else {
            self.message = "no further back".into();
            return;
        };
        self.forward.push(Jump { region: self.region, row: self.row });
        self.enter_region(j.region);
        self.row = j.row.min(self.rowset.rows.len().saturating_sub(1));
    }

    fn jump_forward(&mut self) {
        let Some(j) = self.forward.pop() else {
            self.message = "no further forward".into();
            return;
        };
        self.back.push(Jump { region: self.region, row: self.row });
        self.enter_region(j.region);
        self.row = j.row.min(self.rowset.rows.len().saturating_sub(1));
    }

    fn yank(&mut self, kind: char) {
        if !self.has_regions() || self.rowset.rows.is_empty() {
            self.message = "nothing selected to copy".into();
            return;
        }
        let ctx = self.render_ctx();
        let path = self.selected_path();
        let rows_snapshot: Vec<(String, Vec<usize>)> = self
            .rowset
            .rows
            .iter()
            .map(|r| (r.path.to_string(), r.index_path.clone()))
            .collect();
        let root = self.session.regions[self.region].root_mut().clone();

        let text = match kind {
            'y' => match rows::node_at(&root, &self.rowset.rows[self.row].index_path) {
                Some(n) => copy_value(n, &ctx),
                None => return,
            },
            'Y' => match rows::node_at(&root, &self.rowset.rows[self.row].index_path) {
                Some(n) => copy_labelled(n, &path, &ctx),
                None => return,
            },
            'h' => match rows::node_at(&root, &self.rowset.rows[self.row].index_path) {
                Some(n) => copy_hexdump(n),
                None => return,
            },
            'r' => match rows::node_at(&root, &self.rowset.rows[self.row].index_path) {
                Some(n) => n.raw.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                None => return,
            },
            'p' => path.clone(),
            't' => {
                let mut pairs = Vec::new();
                for (p, ip) in &rows_snapshot {
                    if let Some(n) = rows::node_at(&root, ip) {
                        pairs.push((p.clone(), n));
                    }
                }
                let refs: Vec<(&str, &Node)> =
                    pairs.iter().map(|(p, n)| (p.as_str(), *n)).collect();
                copy_tsv(&refs, &ctx)
            }
            _ => return,
        };

        let n = text.len();
        let (mech, err) = self.clip.copy(&text);
        self.message = match err {
            None => format!("copied {n} bytes to {}", mech.label()),
            Some(e) => format!(
                "clipboard unavailable ({e}); {n} bytes written to {}",
                self.clip.spill_path().display()
            ),
        };
    }

    fn run_command(&mut self, cmd: &str) {
        let cmd = cmd.trim();
        let (head, rest) = cmd.split_once(' ').unwrap_or((cmd, ""));
        match head {
            "q" | "quit" => self.should_quit = true,
            "lba" => match parse_num(rest) {
                Some(lba) => match lba.checked_mul(self.session.sector_size as u64) {
                    Some(b) => self.goto_byte(b),
                    None => self.message = "LBA overflows a byte offset".into(),
                },
                None => self.message = format!("not a number: {rest}"),
            },
            "as" => {
                let at = self
                    .selected_node()
                    .and_then(|n| n.extent.first())
                    .map(|s| s.start_byte())
                    .unwrap_or(0);
                match self.session.registry.probes().iter().find(|p| p.id().0 == rest) {
                    Some(p) => {
                        let id = p.id();
                        if let Some(i) = self.session.interpret_as(id, at) {
                            self.enter_region(i);
                            self.message = format!("forced {rest} at {}", fmt_offset(at));
                        }
                    }
                    None => {
                        let known: Vec<&str> =
                            self.session.registry.probes().iter().map(|p| p.id().0).collect();
                        self.message = format!("unknown format {rest}; known: {}", known.join(", "));
                    }
                }
            }
            "probe" => {
                let at = self
                    .selected_node()
                    .and_then(|n| n.extent.first())
                    .map(|s| s.start_byte())
                    .unwrap_or(0);
                let c = self.session.registry.candidates(&*self.session.src, at);
                self.message = if c.is_empty() {
                    format!("nothing recognised at {}", fmt_offset(at))
                } else {
                    format!(
                        "at {}: {}",
                        fmt_offset(at),
                        c.iter().map(|(i, s)| format!("{i}={s}")).collect::<Vec<_>>().join(" ")
                    )
                };
            }
            "sector" => match parse_num(rest) {
                Some(s) if s.is_power_of_two() && (512..=65536).contains(&s) => {
                    self.session.sector_size = s as u32;
                    self.session.discover();
                    self.enter_region(0);
                    self.message = format!("sector size set to {s}; regions re-probed");
                }
                _ => self.message = "sector size must be a power of two, 512..65536".into(),
            },
            "" => {}
            _ => match parse_num(cmd) {
                Some(off) => self.goto_byte(off),
                None => self.message = format!("unknown command: {cmd}"),
            },
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        self.message.clear();

        // Popups swallow input.
        match &mut self.popup {
            Popup::Help => {
                self.popup = Popup::None;
                return;
            }
            Popup::Detail => {
                if !matches!(key.code, KeyCode::Down | KeyCode::Up) {
                    self.popup = Popup::None;
                }
                return;
            }
            Popup::Interpret { at, options, sel } => {
                let (at, options, sel) = (*at, options.clone(), *sel);
                match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Popup::Interpret { sel, .. } = &mut self.popup {
                            *sel = (sel.saturating_add(1)).min(options.len() - 1);
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if let Popup::Interpret { sel, .. } = &mut self.popup {
                            *sel = sel.saturating_sub(1);
                        }
                    }
                    KeyCode::Enter => {
                        self.popup = Popup::None;
                        if let Some((id, name, _)) = options.get(sel) {
                            if let Some(i) = self.session.interpret_as(*id, at) {
                                self.enter_region(i);
                                self.message = format!("-> {name} @{}", fmt_offset(at));
                            }
                        }
                    }
                    _ => self.popup = Popup::None,
                }
                return;
            }
            Popup::Command { buffer } => {
                match key.code {
                    KeyCode::Char(c) => buffer.push(c),
                    KeyCode::Backspace => {
                        buffer.pop();
                        if buffer.is_empty() {
                            self.popup = Popup::None;
                        }
                    }
                    KeyCode::Enter => {
                        let cmd = buffer.clone();
                        self.popup = Popup::None;
                        self.run_command(&cmd);
                    }
                    KeyCode::Esc => self.popup = Popup::None,
                    _ => {}
                }
                return;
            }
            Popup::None => {}
        }

        // Two-key sequences: only `y` has one.
        if let Some(lead) = self.pending.take() {
            if lead == 'y' {
                if let KeyCode::Char(c) = key.code {
                    self.yank(c);
                }
                return;
            }
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('c') if ctrl => self.should_quit = true,
            KeyCode::Char('?') => self.popup = Popup::Help,
            KeyCode::Char(':') => self.popup = Popup::Command { buffer: String::new() },

            KeyCode::Char('j') | KeyCode::Down => self.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_by(-1),
            KeyCode::PageDown => self.move_by(20),
            KeyCode::PageUp => self.move_by(-20),
            KeyCode::Char('d') if ctrl => self.move_by(10),
            KeyCode::Char('u') if ctrl => self.move_by(-10),
            KeyCode::Char('G') | KeyCode::End => {
                self.row = self.rowset.rows.len().saturating_sub(1)
            }
            KeyCode::Home => self.row = 0,

            KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => {
                if key.code == KeyCode::Enter && self.focus == Focus::Table {
                    self.popup = Popup::Detail;
                } else {
                    self.toggle_expand();
                }
            }
            KeyCode::Char('h') | KeyCode::Left => self.collapse_or_up(),
            KeyCode::Char('i') if !ctrl => self.popup = Popup::Detail,

            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Tree => Focus::Table,
                    Focus::Table => Focus::Tree,
                }
            }

            KeyCode::Char('z') => {
                self.filter = self.filter.next();
                self.rebuild();
                self.message = format!("filter: {}", self.filter.label());
            }
            KeyCode::Char('Z') => {
                self.show_gaps = !self.show_gaps;
                self.rebuild();
                self.message =
                    format!("gaps {}", if self.show_gaps { "shown" } else { "hidden" });
            }
            KeyCode::Char('H') => self.hex_visible = !self.hex_visible,
            KeyCode::Char('w') => self.wide = !self.wide,

            KeyCode::Char('g') => self.follow_link(),
            // Ctrl-i is indistinguishable from Tab at the terminal level, so the
            // vim pairing cannot be used here; Ctrl-r reads as "redo the jump".
            KeyCode::Char('o') if ctrl => self.jump_back(),
            KeyCode::Char('r') if ctrl => self.jump_forward(),

            KeyCode::Char('y') => self.pending = Some('y'),
            KeyCode::Char('Y') => self.yank('Y'),

            KeyCode::Char('[') => {
                if self.region > 0 {
                    let r = self.region - 1;
                    self.enter_region(r);
                }
            }
            KeyCode::Char(']')
                if self.region + 1 < self.session.regions.len() => {
                    let r = self.region + 1;
                    self.enter_region(r);
                }
            _ => {}
        }
    }
}

/// Accept `0x1be`, `1be` when prefixed, plain decimal, and `1_048_576`.
pub fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim().replace('_', "");
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(b) = s.strip_prefix("0b") {
        return u64::from_str_radix(b, 2).ok();
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_parse_in_the_forms_people_type() {
        assert_eq!(parse_num("0x1BE"), Some(446));
        assert_eq!(parse_num("446"), Some(446));
        assert_eq!(parse_num("1_048_576"), Some(1_048_576));
        assert_eq!(parse_num("0b1010"), Some(10));
        assert_eq!(parse_num("zzz"), None);
        assert_eq!(parse_num(""), None);
    }
}
