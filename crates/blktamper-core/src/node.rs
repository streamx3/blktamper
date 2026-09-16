//! The node tree — the parsed form of everything.
//!
//! There is no `Result` here. `RegionReader::root()` always returns a `Node`.
//! Invalid data is expressed as `Status` plus diagnostics attached to the node it
//! belongs to (R-3.1). A viewer whose parser can refuse is a viewer that goes blank
//! exactly when you need it.

use crate::checksum::Derived;
use crate::desc::{FieldFlags, LinkKind};
use crate::span::{Extent, Span};
use crate::value::{Repr, Value};
use std::borrow::Cow;
use std::sync::Arc;

/// Severity of whatever the parser noticed. Semantic only — `Status` does not know
/// it is red (R-8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Status {
    #[default]
    Ok,
    /// Worth pointing out; not wrong. A legacy field, a deleted entry.
    Info,
    /// Suspicious: out of range, inconsistent with a sibling, non-zero reserved.
    Warn,
    /// Definitely wrong: failed signature, failed checksum, impossible geometry.
    Bad,
    /// The bytes could not be read at all. Never confused with zero (R-2.7).
    Unreadable,
}

impl Status {
    pub fn is_anomaly(self) -> bool {
        matches!(self, Status::Warn | Status::Bad | Status::Unreadable)
    }
    pub fn merge(self, other: Status) -> Status {
        self.max(other)
    }
    pub fn glyph(self) -> char {
        match self {
            Status::Ok => ' ',
            Status::Info => 'i',
            Status::Warn => '!',
            Status::Bad => 'X',
            Status::Unreadable => '?',
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub status: Status,
    pub message: String,
    /// Optional suggested next action, shown in the diagnostic strip.
    pub hint: Option<String>,
}

impl Diagnostic {
    pub fn warn(message: impl Into<String>) -> Diagnostic {
        Diagnostic { status: Status::Warn, message: message.into(), hint: None }
    }
    pub fn bad(message: impl Into<String>) -> Diagnostic {
        Diagnostic { status: Status::Bad, message: message.into(), hint: None }
    }
    pub fn info(message: impl Into<String>) -> Diagnostic {
        Diagnostic { status: Status::Info, message: message.into(), hint: None }
    }
    pub fn with_hint(mut self, hint: impl Into<String>) -> Diagnostic {
        self.hint = Some(hint.into());
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// A discovered area of the device: "GPT primary header", "Partition 1".
    Region,
    /// An instance of a `StructDesc`.
    Struct,
    /// Repeated records.
    Array,
    /// A leaf with a value.
    Field,
    /// One bit of a bitfield.
    Bit,
    /// A logical grouping over non-contiguous parts: an LFN run, an exFAT entry set.
    Group,
    /// Bytes inside a parent's range that no field claimed.
    Gap,
    /// Uninterpreted bytes.
    Raw,
}

/// A followable reference, resolved enough to act on.
#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    pub label: String,
    pub kind: LinkKind,
    /// Raw target value as stored (LBA, cluster, byte offset).
    pub raw: u64,
    /// Absolute byte offset, when the reader could resolve it.
    pub resolved: Option<u64>,
}

/// Lazily-expanded children.
///
/// This is not an optimisation. A FAT on a 58 GiB stick is ~7 MB of entries and a
/// directory can hold tens of thousands of records; the UI expands only what is on
/// screen (R-3.5).
#[derive(Clone)]
pub enum Children {
    None,
    Resolved(Vec<Node>),
    Lazy(Arc<dyn Expander>),
}

impl std::fmt::Debug for Children {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Children::None => write!(f, "None"),
            Children::Resolved(v) => write!(f, "Resolved({} nodes)", v.len()),
            Children::Lazy(e) => write!(f, "Lazy(hint={:?})", e.hint_len()),
        }
    }
}

impl Children {
    pub fn is_none(&self) -> bool {
        matches!(self, Children::None)
    }
    pub fn resolved(&self) -> Option<&[Node]> {
        match self {
            Children::Resolved(v) => Some(v),
            _ => None,
        }
    }
    /// Number of children if known without expanding.
    pub fn len_hint(&self) -> Option<usize> {
        match self {
            Children::None => Some(0),
            Children::Resolved(v) => Some(v.len()),
            Children::Lazy(e) => e.hint_len(),
        }
    }
}

/// Produces children on demand. Implemented by format modules.
pub trait Expander: Send + Sync {
    fn expand(&self, src: &dyn crate::source::BlockSource) -> Vec<Node>;
    /// Child count without expanding, for scrollbar sizing. `None` when unknown.
    fn hint_len(&self) -> Option<usize> {
        None
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub label: Cow<'static, str>,
    pub extent: Extent,
    pub kind: NodeKind,
    pub value: Value,
    pub repr: Repr,
    pub status: Status,
    pub flags: FieldFlags,
    pub diags: Vec<Diagnostic>,
    pub links: Vec<Link>,
    /// A value the parser derived that should match the stored one.
    pub derived: Option<Derived>,
    pub doc: Option<&'static str>,
    /// Raw bytes as stored. Always kept: the raw column, the hex pane, the editor
    /// and `y r` all read from here rather than re-reading the device.
    pub raw: Vec<u8>,
    pub children: Children,
}

impl Default for Node {
    fn default() -> Self {
        Node {
            label: Cow::Borrowed(""),
            extent: Extent::None,
            kind: NodeKind::Field,
            value: Value::Unset,
            repr: Repr::Raw,
            status: Status::Ok,
            flags: FieldFlags::NONE,
            diags: Vec::new(),
            links: Vec::new(),
            derived: None,
            doc: None,
            raw: Vec::new(),
            children: Children::None,
        }
    }
}

impl Node {
    pub fn new(label: impl Into<Cow<'static, str>>, kind: NodeKind) -> Node {
        Node { label: label.into(), kind, ..Default::default() }
    }

    pub fn region(label: impl Into<Cow<'static, str>>, span: Span) -> Node {
        Node {
            label: label.into(),
            kind: NodeKind::Region,
            extent: Extent::One(span),
            value: Value::Composite,
            ..Default::default()
        }
    }

    pub fn with_children(mut self, children: Vec<Node>) -> Node {
        self.children = Children::Resolved(children);
        self
    }

    pub fn with_lazy(mut self, e: Arc<dyn Expander>) -> Node {
        self.children = Children::Lazy(e);
        self
    }

    pub fn with_diag(mut self, d: Diagnostic) -> Node {
        self.status = self.status.merge(d.status);
        self.diags.push(d);
        self
    }

    pub fn with_status(mut self, s: Status) -> Node {
        self.status = self.status.merge(s);
        self
    }

    pub fn with_link(mut self, l: Link) -> Node {
        self.links.push(l);
        self
    }

    pub fn with_doc(mut self, d: &'static str) -> Node {
        self.doc = Some(d);
        self
    }

    /// Status of this node combined with every resolved descendant. Lazy children
    /// are not expanded to compute it — an unexpanded subtree reports what it knows.
    pub fn deep_status(&self) -> Status {
        let mut s = self.status;
        if let Children::Resolved(kids) = &self.children {
            for k in kids {
                s = s.merge(k.deep_status());
            }
        }
        s
    }

    /// True when this node carries no information and "hide empty" should fold it
    /// away (R-4.3). Reserved fields count as empty only when they are actually
    /// zero — a non-zero reserved field is the opposite of uninteresting.
    pub fn is_empty_for_filter(&self) -> bool {
        if self.status.is_anomaly() {
            return false;
        }
        if !self.raw.is_empty() {
            let blank = self.raw.iter().all(|&b| b == 0) || self.raw.iter().all(|&b| b == 0xFF);
            if !blank {
                return false;
            }
        }
        match &self.children {
            Children::Resolved(kids) => kids.iter().all(|k| k.is_empty_for_filter()),
            Children::Lazy(_) => false,
            Children::None => self.value.is_blank() || !self.raw.is_empty(),
        }
    }

    /// True when this node should survive the "anomalies only" filter: a real
    /// finding, or a reserved/must-be-zero field that is not zero.
    pub fn is_anomaly(&self) -> bool {
        if self.status.is_anomaly() {
            return true;
        }
        if self.kind == NodeKind::Gap && !self.raw.iter().all(|&b| b == 0) {
            return true;
        }
        if (self.flags.has(FieldFlags::RESERVED) || self.flags.has(FieldFlags::MUST_ZERO))
            && !self.raw.is_empty()
            && !self.raw.iter().all(|&b| b == 0)
        {
            return true;
        }
        if let Some(d) = &self.derived {
            if !d.matches {
                return true;
            }
        }
        false
    }

    /// Depth-first iteration over resolved nodes only.
    pub fn walk(&self, f: &mut impl FnMut(&Node)) {
        f(self);
        if let Children::Resolved(kids) = &self.children {
            for k in kids {
                k.walk(f);
            }
        }
    }

    pub fn find_child(&self, label: &str) -> Option<&Node> {
        self.children.resolved()?.iter().find(|n| n.label == label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(label: &'static str, raw: Vec<u8>) -> Node {
        Node { label: label.into(), raw, ..Default::default() }
    }

    #[test]
    fn status_merges_upward() {
        assert_eq!(Status::Ok.merge(Status::Bad), Status::Bad);
        assert_eq!(Status::Warn.merge(Status::Info), Status::Warn);
        assert_eq!(Status::Bad.merge(Status::Unreadable), Status::Unreadable);
    }

    #[test]
    fn zero_and_ff_both_count_as_empty() {
        assert!(field("a", vec![0, 0, 0]).is_empty_for_filter());
        assert!(field("b", vec![0xFF; 4]).is_empty_for_filter());
        assert!(!field("c", vec![0, 1]).is_empty_for_filter());
    }

    #[test]
    fn an_anomalous_field_is_never_hidden_as_empty() {
        let n = field("a", vec![0, 0]).with_diag(Diagnostic::bad("signature missing"));
        assert!(!n.is_empty_for_filter());
        assert!(n.is_anomaly());
    }

    #[test]
    fn nonzero_reserved_is_an_anomaly() {
        let mut n = field("reserved", vec![0, 0, 1, 0]);
        n.flags = FieldFlags::RESERVED;
        assert!(n.is_anomaly());
        n.raw = vec![0, 0, 0, 0];
        assert!(!n.is_anomaly());
    }

    #[test]
    fn deep_status_bubbles_from_resolved_children() {
        let parent = Node::new("p", NodeKind::Struct)
            .with_children(vec![field("a", vec![0]), field("b", vec![0]).with_status(Status::Bad)]);
        assert_eq!(parent.status, Status::Ok);
        assert_eq!(parent.deep_status(), Status::Bad);
    }

    #[test]
    fn empty_parent_with_all_empty_children_is_empty() {
        let p = Node::new("p", NodeKind::Struct)
            .with_children(vec![field("a", vec![0]), field("b", vec![0xFF])]);
        assert!(p.is_empty_for_filter());
    }
}
