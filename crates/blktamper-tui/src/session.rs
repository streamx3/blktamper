//! A device session: the source, what we know about it, and the regions found on it.
//!
//! Region discovery is deliberately shallow and explicit. The app probes sector 0,
//! then probes the start of anything the resulting table points at. It does not go
//! hunting across the whole device — an inspector should show you what the metadata
//! claims, and let you go looking yourself when the metadata is lying.

use blktamper_core::{BlockSource, FormatId, LinkKind, Node, NodeKind, RegionReader, Registry, Score};
use blktamper_io::{open_path, Access, CachedSource, DeviceInfo, OpenError};
use std::path::Path;
use std::sync::Arc;

/// Below this, a match is too weak to put in the region tree on its own; the user
/// can still force it with `:as`.
const MIN_AUTO_SCORE: Score = 30;

/// Signature plus self-consistent geometry. Only a second match this strong earns
/// its own region alongside the winner.
const CONFIDENT: Score = 80;

/// One discovered structure on the device.
pub struct Region {
    pub label: String,
    pub base: u64,
    pub format: FormatId,
    pub score: Score,
    pub reader: Box<dyn RegionReader>,
    /// Parsed tree, resolved on first use and mutated in place as the user expands.
    pub root: Option<Node>,
    /// Nesting depth in the region tree.
    pub depth: usize,
}

impl std::fmt::Debug for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Region")
            .field("label", &self.label)
            .field("base", &self.base)
            .field("format", &self.format)
            .field("score", &self.score)
            .finish()
    }
}

impl Region {
    pub fn root_mut(&mut self) -> &mut Node {
        if self.root.is_none() {
            self.root = Some(self.reader.root());
        }
        self.root.as_mut().unwrap()
    }
}

#[derive(Debug)]
pub struct Session {
    pub src: Arc<dyn BlockSource>,
    pub info: DeviceInfo,
    pub registry: Registry,
    pub regions: Vec<Region>,
    /// Sector size actually in use; may differ from the device's own report when
    /// the user overrides it (R-2.3).
    pub sector_size: u32,
}

impl Session {
    pub fn open(path: &Path, sector_override: Option<u32>) -> Result<Session, OpenError> {
        let (raw, mut info) = open_path(path, Access::ReadOnly)?;
        if let Some(s) = sector_override {
            info.logical_sector_size = s;
        }
        let sector_size = info.logical_sector_size;
        let src: Arc<dyn BlockSource> = Arc::new(CachedSource::new(raw));
        let registry = blktamper_formats::registry();
        let mut s = Session { src, info, registry, regions: Vec::new(), sector_size };
        s.discover();
        Ok(s)
    }

    /// Probe sector 0, then follow whatever it points at one level down.
    pub fn discover(&mut self) {
        self.regions.clear();
        self.probe_and_add(0, 0, None);

        // Anything the top-level table points at.
        let targets = self.partition_targets();
        for (label, off) in targets {
            self.probe_and_add(off, 1, Some(label));
        }
    }

    fn probe_and_add(&mut self, at: u64, depth: usize, label: Option<String>) {
        if at >= self.src.len() {
            return;
        }
        let candidates = self.registry.candidates(&*self.src, at);
        let Some(&(best_id, best_score)) = candidates.first() else { return };
        if best_score < MIN_AUTO_SCORE {
            return;
        }

        // Normally only the best candidate becomes a region and the rest stay
        // available through "interpret as", so a wrong guess is never sticky.
        //
        // The exception is real rather than defensive: a GPT disk carries a
        // protective MBR in sector 0, and both structures are genuinely present.
        // Showing only the winner would hide the decoy that a reader coming from
        // a legacy BIOS actually sees — and hiding it is how hybrid MBR/GPT setups
        // surprise people.
        let mut to_add = vec![(best_id, best_score)];
        for &(id, score) in candidates.iter().skip(1) {
            if score >= CONFIDENT && !to_add.iter().any(|(i, _)| *i == id) {
                to_add.push((id, score));
            }
        }

        for (id, score) in to_add {
            let Some(probe) = self.registry.get(id) else { continue };
            let reader = probe.open(self.src.clone(), at);
            let name = probe.name().to_string();
            let label = match &label {
                Some(l) if id == best_id => l.clone(),
                Some(l) => format!("{l} ({name})"),
                None => name,
            };
            self.regions.push(Region { label, base: at, format: id, score, reader, root: None, depth });
        }
    }

    /// Byte offsets worth probing, taken from the tables already discovered.
    ///
    /// Only `ProbeAt*` links count. A partition entry says "there may be a
    /// filesystem here"; a cluster pointer or a backup-header pointer does not, and
    /// following every resolvable link would fill the region tree with noise the
    /// moment a filesystem module lands.
    fn partition_targets(&mut self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = Vec::new();
        for i in 0..self.regions.len() {
            let root = self.regions[i].root_mut().clone();
            collect_probe_targets(&root, &mut |owner, byte| {
                if byte > 0 && byte < self.src.len() {
                    out.push((partition_label(owner), byte));
                }
            });
        }
        out.sort_by_key(|(_, b)| *b);
        out.dedup_by_key(|(_, b)| *b);
        // A table claiming hundreds of partitions is either corrupt or hostile;
        // either way the region tree is not the place to find out.
        out.truncate(32);
        out
    }

    /// Force a reinterpretation at an offset, inserting it as a new region.
    pub fn interpret_as(&mut self, id: FormatId, at: u64) -> Option<usize> {
        let probe = self.registry.get(id)?;
        let score = probe.probe(&*self.src, at);
        let reader = probe.open(self.src.clone(), at);
        let label = format!("{} @{:#x} (forced)", probe.name(), at);
        self.regions.push(Region {
            label,
            base: at,
            format: id,
            score,
            reader,
            root: None,
            depth: 1,
        });
        Some(self.regions.len() - 1)
    }

}

/// Walk a resolved tree, reporting `ProbeAt*` link targets along with the label of
/// the record that owns them — the partition entry, not the field.
fn collect_probe_targets(node: &Node, f: &mut impl FnMut(&str, u64)) {
    fn go(node: &Node, owner: &str, f: &mut impl FnMut(&str, u64)) {
        // A struct with its own children names the records beneath it.
        let owner = if matches!(node.kind, NodeKind::Struct | NodeKind::Group) && !node.label.is_empty()
        {
            node.label.as_ref()
        } else {
            owner
        };
        for l in &node.links {
            if matches!(l.kind, LinkKind::ProbeAtLba | LinkKind::ProbeAtByte) {
                if let Some(byte) = l.resolved {
                    f(owner, byte);
                }
            }
        }
        if let Some(kids) = node.children.resolved() {
            for k in kids {
                go(k, owner, f);
            }
        }
    }
    go(node, node.label.as_ref(), f);
}

/// Turn a partition entry's label into something that reads well in the tree:
/// `[0] 0C FAT32 LBA` becomes `Partition 1 (FAT32 LBA)`.
fn partition_label(owner: &str) -> String {
    if let Some(rest) = owner.strip_prefix('[') {
        if let Some((idx, tail)) = rest.split_once(']') {
            if let Ok(n) = idx.parse::<usize>() {
                let kind = tail.trim().split_once(' ').map(|(_, k)| k).unwrap_or(tail.trim());
                if kind.is_empty() || kind == "--" {
                    return format!("Partition {}", n + 1);
                }
                return format!("Partition {} ({kind})", n + 1);
            }
        }
    }
    owner.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_entry_labels_become_readable_region_names() {
        assert_eq!(partition_label("[0] 0C FAT32 LBA"), "Partition 1 (FAT32 LBA)");
        assert_eq!(partition_label("[3] 83 Linux"), "Partition 4 (Linux)");
        assert_eq!(partition_label("[1] --"), "Partition 2");
        // anything that is not an entry label passes through untouched
        assert_eq!(partition_label("GPT primary header"), "GPT primary header");
        assert_eq!(partition_label(""), "");
    }

    #[test]
    fn malformed_entry_labels_do_not_panic() {
        for s in ["[", "]", "[]", "[x] y", "[999999999999999999999] z", "[0]"] {
            let _ = partition_label(s);
        }
    }
}
