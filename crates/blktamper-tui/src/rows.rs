//! Flattening a node tree into the visible rows of the field table.
//!
//! Expansion state lives here rather than in the nodes, so the model stays a pure
//! description of the disk and the same tree can be shown two ways.

use blktamper_core::{BlockSource, Children, Node, NodePath};
use std::collections::HashSet;

/// The `z` filter, cycled with one key (R-4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Filter {
    /// Everything.
    #[default]
    All,
    /// Hide all-zero / all-0xFF fields and unused slots, but keep a count so you
    /// never forget they are there.
    HideEmpty,
    /// Only findings: failed checks, non-zero reserved fields, checksum mismatches,
    /// unclaimed non-zero gaps. The view that finds corruption.
    Anomalies,
}

impl Filter {
    pub fn next(self) -> Filter {
        match self {
            Filter::All => Filter::HideEmpty,
            Filter::HideEmpty => Filter::Anomalies,
            Filter::Anomalies => Filter::All,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "all",
            Filter::HideEmpty => "hide-empty",
            Filter::Anomalies => "anomalies",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Row {
    pub path: NodePath,
    /// Index path into the tree, for mutation (lazy expansion).
    pub index_path: Vec<usize>,
    pub depth: usize,
    pub expandable: bool,
    pub expanded: bool,
}

/// A row that stands in for content the filter removed.
#[derive(Clone, Debug)]
pub struct Elision {
    pub after_row: usize,
    pub hidden: usize,
}

#[derive(Debug, Default)]
pub struct RowSet {
    pub rows: Vec<Row>,
    pub elisions: Vec<Elision>,
}

#[derive(Debug, Default)]
pub struct Expansion {
    open: HashSet<String>,
}

impl Expansion {
    pub fn is_open(&self, p: &NodePath) -> bool {
        self.open.contains(&p.to_string())
    }
    pub fn toggle(&mut self, p: &NodePath) -> bool {
        let k = p.to_string();
        if self.open.contains(&k) {
            self.open.remove(&k);
            false
        } else {
            self.open.insert(k);
            true
        }
    }
    pub fn open_path(&mut self, p: &NodePath) {
        self.open.insert(p.to_string());
    }
    pub fn close(&mut self, p: &NodePath) {
        self.open.remove(&p.to_string());
    }
    /// Open the root's immediate children, which is what you want on arrival.
    pub fn open_top(&mut self, root: &Node) {
        let base = NodePath::new().push_name(root.label.as_ref());
        self.open_path(&base);
        if let Some(kids) = root.children.resolved() {
            for (i, k) in kids.iter().enumerate() {
                if matches!(k.kind, blktamper_core::NodeKind::Array) {
                    self.open_path(&child_path(&base, k, i));
                }
            }
        }
    }
}

fn child_path(parent: &NodePath, node: &Node, index: usize) -> NodePath {
    // Array members are addressed by index; everything else by name, which keeps
    // paths stable when a filter hides a sibling.
    if node.label.starts_with('[') {
        parent.push_index(index)
    } else {
        parent.push_name(node.label.as_ref())
    }
}

/// Resolve any lazy children along `index_path`, so expanding a node reads only
/// what it needs (R-3.5).
pub fn resolve_at(root: &mut Node, index_path: &[usize], src: &dyn BlockSource) {
    let mut cur = root;
    for &i in index_path {
        if let Children::Lazy(e) = &cur.children {
            let kids = e.expand(src);
            cur.children = Children::Resolved(kids);
        }
        let Children::Resolved(kids) = &mut cur.children else { return };
        if i >= kids.len() {
            return;
        }
        cur = &mut kids[i];
    }
    if let Children::Lazy(e) = &cur.children {
        let kids = e.expand(src);
        cur.children = Children::Resolved(kids);
    }
}

/// Build the visible row list.
pub fn flatten(root: &Node, exp: &Expansion, filter: Filter, show_gaps: bool) -> RowSet {
    let mut out = RowSet::default();
    let base = NodePath::new().push_name(root.label.as_ref());
    out.rows.push(Row {
        path: base.clone(),
        index_path: Vec::new(),
        depth: 0,
        expandable: !root.children.is_none(),
        expanded: exp.is_open(&base),
    });
    if exp.is_open(&base) {
        walk(root, &base, &mut Vec::new(), 1, exp, filter, show_gaps, &mut out);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn walk(
    node: &Node,
    path: &NodePath,
    index_path: &mut Vec<usize>,
    depth: usize,
    exp: &Expansion,
    filter: Filter,
    show_gaps: bool,
    out: &mut RowSet,
) {
    let Some(kids) = node.children.resolved() else { return };
    let mut hidden = 0usize;
    for (i, k) in kids.iter().enumerate() {
        if !keep(k, filter, show_gaps) {
            hidden += 1;
            continue;
        }
        if hidden > 0 {
            out.elisions.push(Elision { after_row: out.rows.len(), hidden });
            hidden = 0;
        }
        let kp = child_path(path, k, i);
        index_path.push(i);
        let open = exp.is_open(&kp);
        out.rows.push(Row {
            path: kp.clone(),
            index_path: index_path.clone(),
            depth,
            expandable: !k.children.is_none(),
            expanded: open,
        });
        if open {
            walk(k, &kp, index_path, depth + 1, exp, filter, show_gaps, out);
        }
        index_path.pop();
    }
    if hidden > 0 {
        out.elisions.push(Elision { after_row: out.rows.len(), hidden });
    }
}

fn keep(node: &Node, filter: Filter, show_gaps: bool) -> bool {
    if node.kind == blktamper_core::NodeKind::Gap && !show_gaps {
        // A gap holding data is never hidden: it is either our bug or the disk's
        // secret, and both are worth seeing.
        if node.raw.iter().all(|&b| b == 0) {
            return false;
        }
    }
    match filter {
        Filter::All => true,
        Filter::HideEmpty => !node.is_empty_for_filter(),
        Filter::Anomalies => subtree_has_anomaly(node),
    }
}

fn subtree_has_anomaly(node: &Node) -> bool {
    if node.is_anomaly() {
        return true;
    }
    node.children
        .resolved()
        .is_some_and(|kids| kids.iter().any(subtree_has_anomaly))
}

/// Look up the node a row refers to.
pub fn node_at<'a>(root: &'a Node, index_path: &[usize]) -> Option<&'a Node> {
    let mut cur = root;
    for &i in index_path {
        cur = cur.children.resolved()?.get(i)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::{Diagnostic, FieldFlags, NodeKind, Status};

    fn leaf(label: &'static str, raw: Vec<u8>) -> Node {
        Node { label: label.into(), raw, ..Default::default() }
    }

    fn tree() -> Node {
        Node::new("root", NodeKind::Struct).with_children(vec![
            leaf("live", vec![1, 2, 3]),
            leaf("zeros", vec![0, 0, 0]),
            leaf("ff", vec![0xFF, 0xFF]),
            leaf("broken", vec![9]).with_diag(Diagnostic::bad("nope")),
        ])
    }

    fn open_root() -> Expansion {
        let mut e = Expansion::default();
        e.open_path(&NodePath::new().push_name("root"));
        e
    }

    #[test]
    fn all_shows_everything() {
        let r = flatten(&tree(), &open_root(), Filter::All, true);
        assert_eq!(r.rows.len(), 5); // root + 4
    }

    #[test]
    fn hide_empty_drops_zero_and_ff_and_counts_them() {
        let r = flatten(&tree(), &open_root(), Filter::HideEmpty, true);
        let labels: Vec<String> = r.rows.iter().map(|x| x.path.to_string()).collect();
        assert!(labels.iter().any(|l| l.ends_with("live")));
        assert!(labels.iter().any(|l| l.ends_with("broken")));
        assert!(!labels.iter().any(|l| l.ends_with("zeros")));
        assert_eq!(r.elisions.iter().map(|e| e.hidden).sum::<usize>(), 2);
    }

    #[test]
    fn anomalies_shows_only_findings() {
        let r = flatten(&tree(), &open_root(), Filter::Anomalies, true);
        let labels: Vec<String> = r.rows.iter().map(|x| x.path.to_string()).collect();
        assert_eq!(labels.len(), 2, "{labels:?}");
        assert!(labels[1].ends_with("broken"));
    }

    #[test]
    fn a_nonzero_reserved_field_survives_the_anomaly_filter() {
        let mut n = leaf("reserved", vec![0, 1]);
        n.flags = FieldFlags::RESERVED;
        let t = Node::new("root", NodeKind::Struct).with_children(vec![n]);
        let r = flatten(&t, &open_root(), Filter::Anomalies, true);
        assert_eq!(r.rows.len(), 2);
    }

    #[test]
    fn a_parent_is_kept_when_a_descendant_is_anomalous() {
        let inner = Node::new("inner", NodeKind::Struct)
            .with_children(vec![leaf("bad", vec![1]).with_status(Status::Bad)]);
        let t = Node::new("root", NodeKind::Struct).with_children(vec![inner]);
        let mut e = open_root();
        e.open_path(&NodePath::parse("root.inner"));
        let r = flatten(&t, &e, Filter::Anomalies, true);
        assert_eq!(r.rows.len(), 3);
    }

    #[test]
    fn collapsed_children_are_not_listed() {
        let inner = Node::new("inner", NodeKind::Struct).with_children(vec![leaf("x", vec![1])]);
        let t = Node::new("root", NodeKind::Struct).with_children(vec![inner]);
        let r = flatten(&t, &open_root(), Filter::All, true);
        assert_eq!(r.rows.len(), 2);
        assert!(r.rows[1].expandable && !r.rows[1].expanded);
    }

    #[test]
    fn filter_cycles_in_three_states() {
        assert_eq!(Filter::All.next(), Filter::HideEmpty);
        assert_eq!(Filter::HideEmpty.next(), Filter::Anomalies);
        assert_eq!(Filter::Anomalies.next(), Filter::All);
    }

    #[test]
    fn array_members_get_index_paths_so_they_survive_filtering() {
        let t = Node::new("root", NodeKind::Array)
            .with_children(vec![leaf("[0] a", vec![1]), leaf("[1] b", vec![2])]);
        let r = flatten(&t, &open_root(), Filter::All, true);
        assert_eq!(r.rows[1].path.to_string(), "root[0]");
        assert_eq!(r.rows[2].path.to_string(), "root[1]");
    }
}
