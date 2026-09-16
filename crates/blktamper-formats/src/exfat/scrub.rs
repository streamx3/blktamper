//! Overwriting a recoverable exFAT record set.
//!
//! An exFAT delete clears one bit — `InUse`, bit 7 of the type byte — in each record
//! of the set: `0x85` becomes `0x05`, `0xC0` becomes `0x40`, `0xC1` becomes `0x41`.
//! Nothing else changes, so a deleted file keeps its complete UTF-16 filename, both
//! lengths, the first cluster, all three timestamps and every attribute. It leaks
//! more than a FAT delete does, which is what makes scrubbing worth having.
//!
//! Nothing here writes: this describes an edit, and the caller stages and commits it
//! (ADR-007, ADR-011).

use super::{cluster_chain, types, ExfatReader, Geometry};
use blktamper_core::node::Diagnostic;
use blktamper_core::scrub::{
    layout_directory, scrub_edit, Fill, RecordClass, RecordShape, ScrubMode, ScrubPlan, ZeroRefusal,
};
use blktamper_core::ByteEdit;
use blktamper_core::{Node, Span};

const ENTRY_SIZE: u64 = 32;

/// A directory this long is corrupt or hostile; the scan behind the zero guard has
/// to terminate either way.
const MAX_SCAN_CLUSTERS: usize = 4096;

/// A directory holding more records than this is not one we will rewrite in a single
/// commit; the blast radius stops being previewable.
const MAX_DIR_RECORDS: usize = 16_384;

/// How a record reads right now. `InUse` is one bit of the type byte, and it is the
/// only thing distinguishing a live record from a deleted one — so the conservative
/// reading is the safe one.
fn classify(b: &[u8]) -> RecordClass {
    match b.first().copied() {
        Some(types::END_OF_DIRECTORY) => RecordClass::Free,
        Some(t) if types::is_in_use(t) => RecordClass::Live,
        Some(_) => RecordClass::Deleted,
        None => RecordClass::Free,
    }
}

/// Do these bytes read as a directory rather than as file data?
///
/// exFAT's type byte is structured: bit 7 InUse, bit 6 category, bit 5 importance,
/// bits 0..4 a type code, and code 0 is reserved for the end-of-directory marker. So
/// any allocated record must have a non-zero type code, which arbitrary data fails
/// often enough to be a useful filter.
fn looks_like_directory(records: &[Vec<u8>]) -> bool {
    let mut used = 0usize;
    for b in records {
        if b.len() < 32 {
            return false;
        }
        let t = b[0];
        if t == types::END_OF_DIRECTORY {
            continue;
        }
        used += 1;
        if t & 0x1F == 0 {
            return false;
        }
    }
    used > 0
}

/// A record's filename, for the confirmation list. Only name records carry one.
fn record_name(b: &[u8]) -> String {
    if types::undeleted(b[0]) == types::FILE_NAME {
        let s = blktamper_core::value::utf16le_lossy(&b[2..32], true);
        if !s.is_empty() {
            return s;
        }
    }
    format!("{:#04X} record", b[0])
}

impl ExfatReader {
    pub(super) fn plan_scrub(&self, node: &Node, mode: ScrubMode) -> Option<ScrubPlan> {
        match mode {
            ScrubMode::Record(fill) => self.plan_record(node, fill),
            ScrubMode::Sweep | ScrubMode::Compact => self.plan_directory(node, mode),
        }
    }

    /// Rewrite a whole directory. See the FAT module for the reasoning; the only
    /// differences here are the marker and that an entry set is several contiguous
    /// records, which packing in order preserves.
    fn plan_directory(&self, node: &Node, mode: ScrubMode) -> Option<ScrubPlan> {
        let src = &*self.src;
        let (boot, _) = src.read_vec(self.base, 512);
        let (geo, _) = Geometry::from_boot(&boot, self.base, src.logical_sector_size());
        if !geo.trusted {
            return None;
        }
        let span = match node.extent.spans() {
            [s] => *s,
            _ => return None,
        };
        let start = span.start_byte();
        let heap = geo.heap_byte()?;
        if start < heap || span.byte_len() != geo.cluster_size {
            return None;
        }
        if (start - heap) % geo.cluster_size != 0 {
            return None;
        }

        // The whole allocated extent, terminator or not.
        let runs = self.dir_runs_from(&geo, start).ok()?;
        let mut offsets: Vec<u64> = Vec::new();
        let mut records: Vec<Vec<u8>> = Vec::new();
        for (at, len) in &runs {
            let mut off = *at;
            let end = at.saturating_add(*len);
            while off + ENTRY_SIZE <= end {
                let (b, outcome) = src.read_vec(off, ENTRY_SIZE as usize);
                if b.len() != ENTRY_SIZE as usize
                    || outcome == blktamper_core::ReadOutcome::Unreadable
                {
                    return None;
                }
                offsets.push(off);
                records.push(b);
                off += ENTRY_SIZE;
                if records.len() >= MAX_DIR_RECORDS {
                    break;
                }
            }
        }
        if records.is_empty() {
            return None;
        }

        // As in the FAT module: a cluster-sized, cluster-aligned span is also the
        // shape of a file's first cluster, and rewriting file data as directory
        // records is the worst outcome available here.
        if !looks_like_directory(&records) {
            return None;
        }

        let class: Vec<RecordClass> = records.iter().map(|b| classify(b)).collect();
        let new = layout_directory(&records, &class, mode, RecordShape::DIR_ENTRY_32);

        let mut edits = Vec::new();
        for ((off, old), fresh) in offsets.iter().zip(&records).zip(&new) {
            if old == fresh {
                continue;
            }
            edits.push(ByteEdit {
                offset: *off,
                old: old.clone(),
                new: fresh.clone(),
                reason: format!("{} directory", mode.label()),
            });
        }
        if edits.is_empty() {
            return None;
        }

        let deleted: Vec<String> = records
            .iter()
            .zip(&class)
            .filter(|(_, c)| **c == RecordClass::Deleted)
            .map(|(b, _)| record_name(b))
            .collect();
        let live = class.iter().filter(|c| **c == RecordClass::Live).count();
        let relocated = if mode == ScrubMode::Compact {
            records
                .iter()
                .zip(&new)
                .zip(&class)
                .filter(|((old, fresh), c)| **c == RecordClass::Live && old != fresh)
                .count()
        } else {
            0
        };

        let mut removes = vec![format!(
            "{} deleted record(s), with their filenames, timestamps, lengths and \
             cluster pointers",
            deleted.len()
        )];
        let residue = records
            .iter()
            .zip(&class)
            .filter(|(b, c)| **c == RecordClass::Free && !b.iter().all(|&x| x == 0))
            .count();
        if residue > 0 {
            removes.push(format!(
                "{residue} record(s) typed 0x00 whose bytes are not zero — entries \
                 overwritten rather than erased"
            ));
        }

        let mut keeps = vec![format!("all {live} record(s) still in use")];
        let mut warnings = Vec::new();
        match mode {
            ScrubMode::Compact => {
                keeps.push(
                    "nothing else: no cleared-InUse record remains, and every byte the \
                     survivors vacate is zeroed"
                        .into(),
                );
                if relocated > 0 {
                    warnings.push(
                        Diagnostic::warn(format!(
                            "{relocated} live record(s) move to close the gap, so the whole \
                             directory is rewritten rather than one sector"
                        ))
                        .with_hint(
                            "entry sets stay contiguous because packing preserves order",
                        ),
                    );
                }
            }
            _ => keeps.push(format!(
                "{} cleared-InUse record(s) sitting between live ones",
                deleted.len()
            )),
        }
        keeps.push("the files' data clusters, which this command does not reach".into());
        keeps.push("the allocation bitmap, which the delete already updated".into());
        warnings.push(
            Diagnostic::warn(
                "this does not touch any file's data. Names and metadata go; contents \
                 stay where they are."
                    .to_string(),
            )
            .with_hint("overwriting contents is sanitize's job"),
        );

        Some(ScrubPlan {
            label: node.label.to_string(),
            mode,
            affected: deleted,
            relocated,
            edits,
            removes,
            keeps,
            zero_refusal: None,
            warnings,
        })
    }

    fn plan_record(&self, node: &Node, fill: Fill) -> Option<ScrubPlan> {
        let spans = node.extent.spans();
        if spans.is_empty() {
            return None;
        }
        // Whole records only: scrubbing one field would leave the rest of the set,
        // and therefore the filename, perfectly readable.
        if spans.iter().any(|s| s.byte_len() != ENTRY_SIZE || !s.is_byte_aligned()) {
            return None;
        }

        let src = &*self.src;
        let (boot, _) = src.read_vec(self.base, 512);
        let (geo, _) = Geometry::from_boot(&boot, self.base, src.logical_sector_size());

        let mut records: Vec<(Span, Vec<u8>)> = Vec::with_capacity(spans.len());
        for s in spans {
            let (bytes, _) = src.read_vec(s.start_byte(), ENTRY_SIZE as usize);
            if bytes.len() != ENTRY_SIZE as usize {
                return None;
            }
            records.push((*s, bytes));
        }

        // Every record must be a deleted one. A set that still has InUse set belongs
        // to a live file, and scrubbing it would lose something nobody asked to lose.
        if !records
            .iter()
            .all(|(_, b)| b[0] != types::END_OF_DIRECTORY && !types::is_in_use(b[0]))
        {
            return None;
        }

        let mut ordered = records.clone();
        ordered.sort_by_key(|(s, _)| s.start_byte());

        let edits: Vec<_> = ordered
            .iter()
            .filter_map(|(s, b)| {
                scrub_edit(*s, b, RecordShape::DIR_ENTRY_32, fill, "scrub deleted exFAT record")
            })
            .collect();
        if edits.is_empty() {
            return None;
        }

        let last_end = ordered.last().map(|(s, _)| s.end_byte()).unwrap_or(0);
        let zero_refusal = match self.in_use_after(&geo, last_end) {
            Ok(None) => None,
            Ok(Some((count, first_at))) => Some(ZeroRefusal::InUseRecordsFollow { count, first_at }),
            Err(why) => Some(ZeroRefusal::CouldNotVerify(why)),
        };

        let (removes, keeps, warnings) = describe(&geo, &ordered, fill);

        Some(ScrubPlan {
            label: node.label.to_string(),
            mode: ScrubMode::Record(fill),
            affected: ordered.iter().map(|(_, b)| record_name(b)).collect(),
            relocated: 0,
            edits,
            removes,
            keeps,
            zero_refusal,
            warnings,
        })
    }

    /// Records still in use after `after`, in the same directory.
    ///
    /// `entry_type == 0x00` ends the directory for a driver, so zeroing a record
    /// ahead of live ones hides them. Records whose `InUse` bit is merely clear do
    /// *not* end it — a driver skips those and keeps going — so they are no obstacle.
    fn in_use_after(&self, geo: &Geometry, after: u64) -> Result<Option<(usize, u64)>, String> {
        if !geo.trusted {
            return Err("the volume geometry is not usable".into());
        }
        let runs = self.dir_runs_from(geo, after)?;
        let src = &*self.src;
        let mut count = 0usize;
        let mut first_at: Option<u64> = None;
        let mut past_terminator = false;

        for (start, len) in runs {
            let mut off = start;
            let end = start.saturating_add(len);
            while off + ENTRY_SIZE <= end {
                let (b, outcome) = src.read_vec(off, ENTRY_SIZE as usize);
                if b.len() != ENTRY_SIZE as usize
                    || outcome == blktamper_core::ReadOutcome::Unreadable
                {
                    return Err(format!("the directory could not be read at {off:#012X}"));
                }
                // Does not stop at the end-of-directory marker: a driver does, so a
                // live record past it is already invisible, but the safety check must
                // not believe a marker the viewer pointedly does not.
                if b[0] == types::END_OF_DIRECTORY {
                    past_terminator = true;
                } else if types::is_in_use(b[0]) && !past_terminator {
                    count += 1;
                    first_at.get_or_insert(off);
                }
                off += ENTRY_SIZE;
            }
        }
        Ok(pack(count, first_at))
    }

    /// Byte runs of the directory containing `from`, starting at `from`.
    fn dir_runs_from(&self, geo: &Geometry, from: u64) -> Result<Vec<(u64, u64)>, String> {
        let heap = geo.heap_byte().ok_or("the cluster heap is not locatable")?;
        if from < heap {
            return Err("the record is not inside the cluster heap".into());
        }
        let cluster = (from - heap) / geo.cluster_size.max(1) + 2;
        if !geo.cluster_in_heap(cluster) {
            return Err(format!("cluster {cluster} is outside the heap"));
        }

        // A directory is always FAT-chained: the NoFatChain shortcut is a property
        // of a file's stream extension, not of the directory holding it.
        let (clusters, _) = cluster_chain(&*self.src, geo, cluster, false, None);
        let clusters: Vec<u64> = clusters.into_iter().take(MAX_SCAN_CLUSTERS).collect();
        if clusters.is_empty() {
            return Err(format!("the chain from cluster {cluster} is empty"));
        }

        let mut runs: Vec<(u64, u64)> = Vec::with_capacity(clusters.len());
        for (i, c) in clusters.iter().enumerate() {
            let Some(at) = geo.cluster_byte(*c) else { continue };
            let (start, len) = if i == 0 {
                let within = from.saturating_sub(at);
                (from, geo.cluster_size.saturating_sub(within))
            } else {
                (at, geo.cluster_size)
            };
            match runs.last_mut() {
                Some((o, l)) if *o + *l == start => *l += len,
                _ => runs.push((start, len)),
            }
        }
        Ok(runs)
    }
}

fn pack(count: usize, first_at: Option<u64>) -> Option<(usize, u64)> {
    match (count, first_at) {
        (0, _) | (_, None) => None,
        (n, Some(at)) => Some((n, at)),
    }
}

fn describe(
    geo: &Geometry,
    records: &[(Span, Vec<u8>)],
    fill: Fill,
) -> (Vec<String>, Vec<String>, Vec<Diagnostic>) {
    let mut removes = Vec::new();
    let mut keeps = Vec::new();
    let mut warnings = Vec::new();

    let names = records.iter().filter(|(_, b)| types::undeleted(b[0]) == types::FILE_NAME).count();
    if names > 0 {
        removes.push(format!(
            "the filename, held in {names} name record(s) that survived the delete in full"
        ));
    }

    if records.iter().any(|(_, b)| types::undeleted(b[0]) == types::FILE) {
        removes.push("the file attributes".into());
        removes.push("the creation, last-modified and last-accessed timestamps, \
                      including their 10ms and UTC-offset fields".into());
    }

    if let Some((_, b)) = records
        .iter()
        .find(|(_, b)| types::undeleted(b[0]) == types::STREAM_EXTENSION)
    {
        let data_len = u64::from_le_bytes([
            b[0x18], b[0x19], b[0x1A], b[0x1B], b[0x1C], b[0x1D], b[0x1E], b[0x1F],
        ]);
        let valid_len = u64::from_le_bytes([
            b[0x08], b[0x09], b[0x0A], b[0x0B], b[0x0C], b[0x0D], b[0x0E], b[0x0F],
        ]);
        let first = u32::from_le_bytes([b[0x14], b[0x15], b[0x16], b[0x17]]) as u64;
        let no_fat_chain = b[0x01] & 0x02 != 0;

        removes.push(format!("the recorded size, {data_len} bytes ({valid_len} valid)"));
        removes.push("the name hash and name length".into());
        if first >= 2 {
            removes.push(format!("the first cluster, {first}"));
            let at = geo.cluster_byte(first);
            let where_ = at.map(|a| format!(" at {a:#012X}")).unwrap_or_default();
            if no_fat_chain {
                warnings.push(
                    Diagnostic::warn(format!(
                        "this does not touch the file's data. The record says NoFatChain, \
                         so the file was contiguous: {data_len} bytes from cluster \
                         {first}{where_} are still there, and losing this record makes \
                         them harder to find rather than gone."
                    ))
                    .with_hint("overwriting contents is sanitize's job"),
                );
            } else {
                warnings.push(
                    Diagnostic::warn(format!(
                        "this does not touch the file's data. Cluster {first}{where_} and \
                         whatever followed it are unchanged."
                    ))
                    .with_hint(
                        "the chain was released by the delete, so only this first cluster \
                         is knowable from the metadata",
                    ),
                );
            }
        }
    }

    match fill {
        Fill::Neutral => keeps.push(
            "the cleared-InUse type byte on each record: that something was deleted \
             here stays visible, what it was does not"
                .into(),
        ),
        Fill::Zero => keeps.push(
            "nothing in these records; they will read as space that was never used".into(),
        ),
    }
    keeps.push("the file's data clusters, which this command does not reach".into());
    keeps.push(
        "the allocation bitmap, which the delete already updated and which this does \
         not change"
            .into(),
    );

    (removes, keeps, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::{Extent, MemSource, NodeKind, RegionReader};
    use std::sync::Arc;

    /// A volume whose root directory holds `entries`, and the byte offset they
    /// actually land at.
    ///
    /// `synth_volume` writes the volume label, the allocation bitmap and the up-case
    /// table first — three records every real volume has — so the caller's entries
    /// start 96 bytes in. Those three are in use, but they come *before* the set
    /// under test, so they are no obstacle to zeroing it.
    fn volume(entries: &[u8]) -> (Vec<u8>, u64) {
        let img = super::super::synth_volume(entries);
        let (geo, _) = Geometry::from_boot(&img[..512], 0, 512);
        let root = geo.cluster_byte(geo.first_cluster_of_root).expect("root cluster");
        (img, root + 96)
    }

    fn reader(img: Vec<u8>) -> ExfatReader {
        ExfatReader::new(Arc::new(MemSource::new(img)), 0)
    }

    /// A minimal deleted entry set: 0x05 primary, 0x40 stream, 0x41 name.
    fn deleted_set(first_cluster: u32, len: u64) -> Vec<u8> {
        let mut v = vec![0u8; 96];
        v[0] = 0x05;
        v[1] = 2; // secondary_count
        v[32] = 0x40;
        v[32 + 0x03] = 6; // name_length
        v[32 + 0x14..32 + 0x18].copy_from_slice(&first_cluster.to_le_bytes());
        v[32 + 0x18..32 + 0x20].copy_from_slice(&len.to_le_bytes());
        v[64] = 0x41;
        for (i, u) in "SECRET".encode_utf16().enumerate() {
            v[64 + 2 + i * 2..64 + 4 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn live_entry() -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0] = 0x85;
        v
    }

    fn set_node(root: u64, count: u64) -> Node {
        Node {
            label: "SECRET (deleted)".into(),
            extent: Extent::Many((0..count).map(|i| Span::bytes(root + i * 32, 32)).collect()),
            kind: NodeKind::Group,
            ..Default::default()
        }
    }

    #[test]
    fn neutral_keeps_each_records_own_marker() {
        let (img, root) = volume(&deleted_set(7, 1234));
        let r = reader(img);
        let p = r.scrub_plan(&set_node(root, 3), ScrubMode::Record(Fill::Neutral)).expect("a plan");
        assert_eq!(p.records(), 3);
        // exFAT uses a different marker per record kind; neutral must not normalise.
        assert_eq!(p.edits[0].new[0], 0x05);
        assert_eq!(p.edits[1].new[0], 0x40);
        assert_eq!(p.edits[2].new[0], 0x41);
        for e in &p.edits {
            assert!(e.new[1..].iter().all(|&b| b == 0));
        }
        assert!(p.removes.iter().any(|s| s.contains("1234 bytes")), "{:?}", p.removes);
        assert!(p.removes.iter().any(|s| s.contains("first cluster, 7")), "{:?}", p.removes);
        assert!(p.removes.iter().any(|s| s.contains("1 name record")), "{:?}", p.removes);
    }

    #[test]
    fn zeroing_is_warned_about_not_refused_when_a_live_record_follows() {
        let mut entries = deleted_set(7, 10);
        entries.extend_from_slice(&live_entry());
        let (img, root) = volume(&entries);
        let r = reader(img);
        let p = r.scrub_plan(&set_node(root, 3), ScrubMode::Record(Fill::Zero)).unwrap();
        assert!(!p.edits.is_empty(), "the plan is still offered: warned, not refused");
        match p.zero_refusal.as_ref().expect("the cost must be stated") {
            ZeroRefusal::InUseRecordsFollow { count, first_at } => {
                assert_eq!(*count, 1);
                assert_eq!(*first_at, root + 96);
            }
            other => panic!("wrong refusal: {other:?}"),
        }
    }

    #[test]
    fn zero_is_allowed_when_only_free_space_follows() {
        let (img, root) = volume(&deleted_set(7, 10));
        let r = reader(img);
        let p = r.scrub_plan(&set_node(root, 3), ScrubMode::Record(Fill::Zero)).unwrap();
        assert!(p.zero_is_free(), "{:?}", p.zero_refusal);
        for e in &p.edits {
            assert!(e.new.iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn a_live_set_has_no_plan() {
        let mut entries = live_entry();
        entries.extend_from_slice(&[0u8; 64]);
        let (img, root) = volume(&entries);
        let r = reader(img);
        assert!(r.scrub_plan(&set_node(root, 1), ScrubMode::Record(Fill::Neutral)).is_none());
    }

    #[test]
    fn a_mixed_selection_has_no_plan() {
        // A deleted set followed by a live entry, selected together: refusing is
        // right, because scrubbing the live one loses a file.
        let mut entries = deleted_set(7, 10);
        entries.extend_from_slice(&live_entry());
        let (img, root) = volume(&entries);
        let r = reader(img);
        assert!(r.scrub_plan(&set_node(root, 4), ScrubMode::Record(Fill::Neutral)).is_none());
    }

    #[test]
    fn a_partial_record_selection_has_no_plan() {
        let (img, root) = volume(&deleted_set(7, 10));
        let r = reader(img);
        let field = Node {
            label: "file_name".into(),
            extent: Extent::One(Span::bytes(root + 64 + 2, 30)),
            ..Default::default()
        };
        assert!(r.scrub_plan(&field, ScrubMode::Record(Fill::Neutral)).is_none());
    }

    #[test]
    fn a_contiguous_file_says_so_in_the_warning() {
        let mut entries = deleted_set(7, 4096);
        entries[32 + 0x01] |= 0x02; // NoFatChain
        let (img, root) = volume(&entries);
        let r = reader(img);
        let p = r.scrub_plan(&set_node(root, 3), ScrubMode::Record(Fill::Neutral)).unwrap();
        assert!(
            p.warnings.iter().any(|w| w.message.contains("NoFatChain")),
            "a contiguous file's data is fully locatable and the warning must say so"
        );
    }
}
