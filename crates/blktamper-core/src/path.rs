//! Stable identifiers for nodes: `gpt.primary.header.header_crc32`.
//!
//! One string that names any node. Used by the status bar, `y p` copy, the undo
//! journal, bug reports, and a future non-interactive `blktamper get <path>` — which
//! is most of why it is worth having a real type rather than formatting on the fly.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct NodePath(Vec<Seg>);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Seg {
    Name(String),
    Index(usize),
}

impl NodePath {
    pub fn new() -> NodePath {
        NodePath(Vec::new())
    }

    pub fn segments(&self) -> &[Seg] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push_name(&self, name: impl Into<String>) -> NodePath {
        let mut v = self.0.clone();
        v.push(Seg::Name(name.into()));
        NodePath(v)
    }

    pub fn push_index(&self, i: usize) -> NodePath {
        let mut v = self.0.clone();
        v.push(Seg::Index(i));
        NodePath(v)
    }

    pub fn parent(&self) -> Option<NodePath> {
        if self.0.is_empty() {
            None
        } else {
            Some(NodePath(self.0[..self.0.len() - 1].to_vec()))
        }
    }

    pub fn last_name(&self) -> Option<&str> {
        self.0.iter().rev().find_map(|s| match s {
            Seg::Name(n) => Some(n.as_str()),
            Seg::Index(_) => None,
        })
    }

    /// Parse the display form back. Accepts `a.b[3].c`. Never fails on odd input —
    /// worst case it produces a path that matches nothing.
    pub fn parse(s: &str) -> NodePath {
        let mut segs = Vec::new();
        let mut cur = String::new();
        let mut in_idx = false;
        let mut idx = String::new();
        for ch in s.chars() {
            match ch {
                '.' if !in_idx => {
                    if !cur.is_empty() {
                        segs.push(Seg::Name(std::mem::take(&mut cur)));
                    }
                }
                '[' => {
                    if !cur.is_empty() {
                        segs.push(Seg::Name(std::mem::take(&mut cur)));
                    }
                    in_idx = true;
                }
                ']' if in_idx => {
                    if let Ok(n) = idx.parse::<usize>() {
                        segs.push(Seg::Index(n));
                    }
                    idx.clear();
                    in_idx = false;
                }
                c if in_idx => idx.push(c),
                c => cur.push(c),
            }
        }
        if !cur.is_empty() {
            segs.push(Seg::Name(cur));
        }
        NodePath(segs)
    }
}

impl fmt::Display for NodePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for s in &self.0 {
            match s {
                Seg::Name(n) => {
                    if !first {
                        f.write_str(".")?;
                    }
                    f.write_str(n)?;
                }
                Seg::Index(i) => write!(f, "[{i}]")?,
            }
            first = false;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_display() {
        let p = NodePath::new().push_name("gpt").push_name("entries").push_index(3).push_name("first_lba");
        assert_eq!(p.to_string(), "gpt.entries[3].first_lba");
        assert_eq!(NodePath::parse("gpt.entries[3].first_lba"), p);
    }

    #[test]
    fn parsing_junk_does_not_panic() {
        for s in ["", "[", "]", "a[", "a[]", "a[x]", "...", "[[3]]"] {
            let _ = NodePath::parse(s);
        }
    }

    #[test]
    fn parent_and_last_name() {
        let p = NodePath::parse("mbr.entries[0].part_type");
        assert_eq!(p.last_name(), Some("part_type"));
        assert_eq!(p.parent().unwrap().to_string(), "mbr.entries[0]");
    }
}
