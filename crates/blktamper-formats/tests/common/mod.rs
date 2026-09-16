//! Shared fixture plumbing for the integration tests.
//!
//! Images are produced by `tests/fixtures/make-fixtures.sh` with `sfdisk`,
//! `sgdisk`, `mkfs.vfat`, `mkfs.exfat` and `mtools` — real tools on real images,
//! never hand-crafted bytes, so a passing test means we agree with the ecosystem
//! rather than with ourselves (R-9.1). Tests skip when the images are absent.

#![allow(dead_code)]

use blktamper_core::{BlockSource, Node, NodeKind, Status};
use blktamper_io::{open_path, Access};
use std::path::PathBuf;
use std::sync::Arc;

pub fn fixture_dir() -> PathBuf {
    let local = PathBuf::from("tests/fixtures/gen");
    if local.exists() {
        return local;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/gen")
}

/// Open a fixture, or `None` when the images have not been generated.
pub fn fixture(name: &str) -> Option<Arc<dyn BlockSource>> {
    let p = fixture_dir().join(name);
    if !p.exists() {
        eprintln!("skipping: {} not found; run tests/fixtures/make-fixtures.sh", p.display());
        return None;
    }
    let (src, _) = open_path(&p, Access::ReadOnly).ok()?;
    Some(src)
}

/// Run `body` with the fixture, or skip cleanly.
pub fn with_fixture(name: &str, body: impl FnOnce(Arc<dyn BlockSource>)) {
    if let Some(src) = fixture(name) {
        body(src);
    }
}

/// Depth-first search for the first node whose label contains `needle`.
pub fn find_deep<'a>(node: &'a Node, needle: &str) -> Option<&'a Node> {
    if node.label.contains(needle) {
        return Some(node);
    }
    for k in node.children.resolved()? {
        if let Some(f) = find_deep(k, needle) {
            return Some(f);
        }
    }
    None
}

/// Every resolved node in the tree, flattened.
pub fn flatten(node: &Node) -> Vec<&Node> {
    let mut out = Vec::new();
    fn go<'a>(n: &'a Node, out: &mut Vec<&'a Node>) {
        out.push(n);
        if let Some(kids) = n.children.resolved() {
            for k in kids {
                go(k, out);
            }
        }
    }
    go(node, &mut out);
    out
}

/// Scalar value of a named descendant path.
pub fn u64_at(node: &Node, path: &[&str]) -> Option<u64> {
    let mut cur = node;
    for seg in path {
        cur = cur.children.resolved()?.iter().find(|n| n.label == *seg)?;
    }
    cur.value.as_u64()
}

/// Text value of a named descendant path.
pub fn text_at(node: &Node, path: &[&str]) -> Option<String> {
    let mut cur = node;
    for seg in path {
        cur = cur.children.resolved()?.iter().find(|n| n.label == *seg)?;
    }
    cur.value.as_str().map(str::to_string)
}

/// Structural sanity, whatever was parsed.
pub fn assert_tree_invariants(root: &Node) {
    for n in flatten(root) {
        assert!(!n.label.is_empty(), "every node must have a label");
        if n.kind == NodeKind::Field && n.status == Status::Ok && !n.raw.is_empty() {
            assert!(
                n.extent.len_bytes() > 0,
                "field {} holds bytes but claims no extent",
                n.label
            );
        }
    }
}
