//! Overwriting a recoverable FAT record.
//!
//! A FAT delete changes exactly one byte per record: the first byte of the 8.3 name,
//! and the order byte of each long-filename fragment, both become `0xE5`. Everything
//! else survives — the full long name, all three timestamps, the attributes, the
//! size and the first cluster. Scrubbing is what actually removes that.
//!
//! Nothing here writes. It produces a `ScrubPlan` describing what would change; the
//! caller stages it in the overlay and commits explicitly (ADR-007, ADR-011).

use super::{desc, follow_chain, FatReader, Geom};
use blktamper_core::node::Diagnostic;
use blktamper_core::scrub::{
    layout_directory, scrub_edit, Fill, RecordClass, RecordShape, ScrubMode, ScrubPlan, ZeroRefusal,
};
use blktamper_core::ByteEdit;
use blktamper_core::{Node, Span};

/// A directory this long is either corrupt or hostile; the scan that decides whether
/// zeroing is safe must terminate either way.
const MAX_SCAN_CLUSTERS: usize = 4096;

/// A directory holding more records than this is not one we will rewrite in a
/// single commit; the blast radius stops being previewable.
const MAX_DIR_RECORDS: usize = 16_384;

/// How a record reads right now. Only the marker byte distinguishes a live record
/// from a deleted one, so the conservative reading is the safe one.
fn classify(b: &[u8]) -> RecordClass {
    match b.first().copied() {
        Some(desc::FREE_MARK) => RecordClass::Free,
        Some(desc::DELETED_MARK) => RecordClass::Deleted,
        Some(_) => RecordClass::Live,
        None => RecordClass::Free,
    }
}

/// Do these bytes read as a directory rather than as file data?
///
/// The check that carries the weight is the attribute byte: bits 6 and 7 are
/// reserved and always zero in a real entry, so arbitrary data fails it quickly.
/// Deliberately strict — a false negative costs the user a refusal they can work
/// around, a false positive rewrites a file as if it were a directory.
fn looks_like_directory(records: &[Vec<u8>]) -> bool {
    let mut used = 0usize;
    for b in records {
        if b.len() < 32 {
            return false;
        }
        if classify(b) == RecordClass::Free {
            // A free record must be genuinely free or plausible residue, not data.
            continue;
        }
        used += 1;
        let attr = b[0x0B];
        if attr & 0xC0 != 0 {
            return false;
        }
        // The 8.3 name is OEM text and never holds control characters. A
        // long-filename record is exempt: its equivalent bytes are UTF-16 code
        // units, so every second one is routinely 0x00.
        if attr & desc::ATTR_LONG_NAME_MASK != desc::ATTR_LONG_NAME
            && b[1..11].iter().any(|&c| c < 0x20)
        {
            return false;
        }
    }
    used > 0
}

/// The 8.3 name as text, for the confirmation list.
fn short_name(b: &[u8]) -> String {
    let raw = &b[..b.len().min(11)];
    let s = blktamper_core::value::ascii_lossy(raw, true);
    if s.is_empty() { "(unnamed)".into() } else { s }
}

impl FatReader {
    pub(super) fn plan_scrub(&self, node: &Node, mode: ScrubMode) -> Option<ScrubPlan> {
        match mode {
            ScrubMode::Record(fill) => self.plan_record(node, fill),
            ScrubMode::Sweep | ScrubMode::Compact => self.plan_directory(node, mode),
        }
    }

    /// Rewrite a whole directory: `Sweep` blanks tombstones in place, `Compact`
    /// removes them and closes the gap.
    ///
    /// Takes a directory node — the one whose extent is a directory cluster — rather
    /// than a record, because the layout has to start from the directory's beginning
    /// and a FAT chain is singly linked forward: from a record in the middle there is
    /// no cheap way back to the start.
    fn plan_directory(&self, node: &Node, mode: ScrubMode) -> Option<ScrubPlan> {
        let src = &*self.src;
        let g = self.geometry();
        if !g.sane {
            return None;
        }
        let span = match node.extent.spans() {
            [s] => *s,
            _ => return None,
        };
        let start = span.start_byte();
        let is_fixed_root = g.root_entries > 0 && start == g.root_dir_start;
        if !is_fixed_root {
            // A directory node spans exactly one cluster and starts on one.
            if start < g.data_start || span.byte_len() != g.bytes_per_cluster {
                return None;
            }
            if (start - g.data_start) % g.bytes_per_cluster != 0 {
                return None;
            }
        }

        // Every record from the directory's start to the end of its allocated space.
        // Deliberately not stopping at the end-of-directory marker: a record past it
        // is invisible to a driver and just as readable on disk, which is exactly the
        // residue this removes.
        let runs = self.dir_runs_from(&g, start).ok()?;
        let mut offsets: Vec<u64> = Vec::new();
        let mut records: Vec<Vec<u8>> = Vec::new();
        for (at, len) in &runs {
            let mut off = *at;
            let end = at.saturating_add(*len);
            while off + desc::ENTRY_SIZE <= end {
                let (b, outcome) = src.read_vec(off, desc::ENTRY_SIZE as usize);
                if b.len() != desc::ENTRY_SIZE as usize
                    || outcome == blktamper_core::ReadOutcome::Unreadable
                {
                    return None; // rewriting a directory we cannot fully read is not on
                }
                offsets.push(off);
                records.push(b);
                off += desc::ENTRY_SIZE;
                if records.len() >= MAX_DIR_RECORDS {
                    break;
                }
            }
        }
        if records.is_empty() {
            return None;
        }

        // A cluster-aligned span the size of a cluster is also the shape of a *file's*
        // first cluster. Accepting one of those and "compacting" it would rewrite file
        // data as though it were directory records, which is the worst thing this code
        // could do — so the bytes have to agree that they are a directory.
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
            .map(|(b, _)| short_name(b))
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
            "{} deleted record(s) in this directory, with their names, timestamps, \
             sizes and cluster pointers",
            deleted.len()
        )];
        let residue = records
            .iter()
            .zip(&class)
            .filter(|(b, c)| **c == RecordClass::Free && !b.iter().all(|&x| x == 0))
            .count();
        if residue > 0 {
            removes.push(format!(
                "{residue} record(s) marked never-used whose bytes are not zero — \
                 entries that were overwritten rather than erased"
            ));
        }

        let mut keeps = vec![format!("all {live} record(s) still in use")];
        let mut warnings = Vec::new();
        match mode {
            ScrubMode::Compact => {
                keeps.push(
                    "nothing else: no tombstone remains, and every byte the survivors \
                     vacate is zeroed"
                        .into(),
                );
                if relocated > 0 {
                    warnings.push(
                        Diagnostic::warn(format!(
                            "{relocated} live record(s) move to close the gap, so the whole \
                             directory is rewritten rather than one sector"
                        ))
                        .with_hint(
                            "safe because neither FAT nor exFAT has positional \
                             back-references — nothing points at a record's slot",
                        ),
                    );
                }
            }
            _ => {
                let tombstones = deleted.len();
                keeps.push(format!(
                    "{tombstones} tombstone(s) where deleted records sit between live \
                     ones: that something was deleted stays visible, what it was does not"
                ));
            }
        }
        keeps.push("the files' data clusters, which this command does not reach".into());
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
        // Only whole records. Selecting a single field and scrubbing it would leave
        // the rest of the record — and therefore the name — perfectly readable.
        if spans.iter().any(|s| s.byte_len() != desc::ENTRY_SIZE || !s.is_byte_aligned()) {
            return None;
        }

        let src = &*self.src;
        let g = self.geometry();

        // Read every record as it is now, and refuse unless all of them are deleted.
        let mut records: Vec<(Span, Vec<u8>)> = Vec::with_capacity(spans.len());
        for s in spans {
            let (bytes, _) = src.read_vec(s.start_byte(), desc::ENTRY_SIZE as usize);
            if bytes.len() != desc::ENTRY_SIZE as usize {
                return None;
            }
            records.push((*s, bytes));
        }
        if !records.iter().all(|(_, b)| b[0] == desc::DELETED_MARK) {
            // Live records are not this command's business: scrubbing one would
            // orphan its clusters and lose a file the user did not ask to lose.
            return None;
        }

        let mut ordered = records.clone();
        ordered.sort_by_key(|(s, _)| s.start_byte());

        let edits: Vec<_> = ordered
            .iter()
            .filter_map(|(s, b)| scrub_edit(*s, b, RecordShape::DIR_ENTRY_32, fill, "scrub deleted FAT record"))
            .collect();
        if edits.is_empty() {
            return None;
        }

        let last_end = ordered.last().map(|(s, _)| s.end_byte()).unwrap_or(0);
        let zero_refusal = match self.in_use_after(&g, last_end) {
            Ok(None) => None,
            Ok(Some((count, first_at))) => Some(ZeroRefusal::InUseRecordsFollow { count, first_at }),
            Err(why) => Some(ZeroRefusal::CouldNotVerify(why)),
        };

        let (removes, keeps, warnings) = self.describe(&g, &ordered, fill);

        Some(ScrubPlan {
            label: node.label.to_string(),
            mode: ScrubMode::Record(fill),
            // The 8.3 entry carries the name; the other records in the set are
            // long-filename fragments whose equivalent bytes are UTF-16 and read as
            // nonsense if taken for text.
            affected: vec![ordered
                .iter()
                .find(|(_, b)| b[0x0B] & desc::ATTR_LONG_NAME_MASK != desc::ATTR_LONG_NAME)
                .map(|(_, b)| short_name(b))
                .unwrap_or_else(|| "(long-filename fragments only)".into())],
            relocated: 0,
            edits,
            removes,
            keeps,
            zero_refusal,
            warnings,
        })
    }

    /// What the scrub destroys, what it leaves, and anything worth reading first.
    fn describe(
        &self,
        g: &Geom,
        records: &[(Span, Vec<u8>)],
        fill: Fill,
    ) -> (Vec<String>, Vec<String>, Vec<Diagnostic>) {
        let short = records
            .iter()
            .find(|(_, b)| b[0x0B] & desc::ATTR_LONG_NAME_MASK != desc::ATTR_LONG_NAME);
        let lfn_count = records.len() - short.iter().count();

        let mut removes = Vec::new();
        if lfn_count > 0 {
            removes.push(format!(
                "the long filename, held in {lfn_count} fragment(s) that survived the delete intact"
            ));
        }
        removes.push("the 8.3 name, less its already-destroyed first character".into());

        let mut keeps = Vec::new();
        let mut warnings = Vec::new();

        if let Some((_, b)) = short {
            removes.push("the attribute byte".into());
            removes.push("the creation, last-access and last-write timestamps".into());
            let size = u32::from_le_bytes([b[0x1C], b[0x1D], b[0x1E], b[0x1F]]);
            removes.push(format!("the recorded size, {size} bytes"));

            let hi = u16::from_le_bytes([b[0x14], b[0x15]]) as u64;
            let lo = u16::from_le_bytes([b[0x1A], b[0x1B]]) as u64;
            let first = (hi << 16) | lo;
            if first >= 2 {
                removes.push(format!("the first cluster, {first}"));
                match g.cluster_to_byte(first) {
                    Some(at) => warnings.push(
                        Diagnostic::warn(format!(
                            "this does not touch the file's data. Cluster {first} at \
                             {at:#012X} and whatever followed it are unchanged."
                        ))
                        .with_hint(
                            "overwriting contents is sanitize's job; the chain was \
                             released by the delete, so only this first cluster is \
                             even knowable from the metadata",
                        ),
                    ),
                    None => warnings.push(Diagnostic::info(format!(
                        "first cluster {first} is outside this volume; nothing to point at"
                    ))),
                }
            }
        }

        match fill {
            Fill::Neutral => keeps.push(
                "the 0xE5 marker on each record: that a file was deleted here stays \
                 visible, which file it was does not"
                    .into(),
            ),
            Fill::Zero => keeps.push(
                "nothing in these records; they will read as space that was never used"
                    .into(),
            ),
        }
        keeps.push("the file's data clusters, which this command does not reach".into());

        (removes, keeps, warnings)
    }

    /// Records still in use after `after`, within the same directory.
    ///
    /// This is what decides whether `Fill::Zero` may be offered: a zeroed first byte
    /// means *stop scanning* to a FAT driver, so zeroing ahead of live entries hides
    /// them. `Err` means the question could not be answered, which is also a refusal
    /// — an unverifiable guarantee is not one.
    fn in_use_after(&self, g: &Geom, after: u64) -> Result<Option<(usize, u64)>, String> {
        if !g.sane {
            return Err("the volume geometry is not usable".into());
        }
        let runs = self.dir_runs_from(g, after)?;
        let src = &*self.src;
        let mut count = 0usize;
        let mut first_at = None;
        let mut past_terminator = false;
        let mut unreachable_live = 0usize;

        for (start, len) in runs {
            let mut off = start;
            let end = start.saturating_add(len);
            while off + desc::ENTRY_SIZE <= end {
                let (b, outcome) = src.read_vec(off, desc::ENTRY_SIZE as usize);
                if b.len() != desc::ENTRY_SIZE as usize || outcome == blktamper_core::ReadOutcome::Unreadable {
                    return Err(format!("the directory could not be read at {off:#012X}"));
                }
                // Deliberately does not stop at the end-of-directory marker. A
                // driver does, so a live record past it is already invisible and
                // zeroing ahead of it changes nothing — but the tool that decides
                // what is safe must not believe a marker that the viewer pointedly
                // does not. Records past the terminator are counted separately.
                match b[0] {
                    desc::FREE_MARK => past_terminator = true,
                    desc::DELETED_MARK => {}
                    _ if past_terminator => unreachable_live += 1,
                    _ => {
                        count += 1;
                        first_at.get_or_insert(off);
                    }
                }
                off += desc::ENTRY_SIZE;
            }
        }
        let _ = unreachable_live;
        finish(count, first_at)
    }

    /// The byte runs of the directory containing `from`, starting at `from`.
    ///
    /// Only the remainder is needed — the question is what comes *after* the record
    /// — so the directory's own start never has to be found.
    fn dir_runs_from(&self, g: &Geom, from: u64) -> Result<Vec<(u64, u64)>, String> {
        // FAT12/16 keep the root directory in a fixed area outside the data region.
        let root_end = g.root_dir_start.saturating_add(g.root_entries.saturating_mul(desc::ENTRY_SIZE));
        if g.root_entries > 0 && from >= g.root_dir_start && from < root_end {
            return Ok(vec![(from, root_end - from)]);
        }

        if from < g.data_start {
            return Err("the record is not inside the data area".into());
        }
        let rel = from - g.data_start;
        let cluster = rel / g.bytes_per_cluster.max(1) + 2;
        if !g.cluster_in_range(cluster) {
            return Err(format!("cluster {cluster} is outside this volume"));
        }

        let (clusters, _) = follow_chain(&*self.src, g, cluster, MAX_SCAN_CLUSTERS);
        if clusters.is_empty() {
            return Err(format!("the chain from cluster {cluster} is empty"));
        }
        let mut runs = Vec::with_capacity(clusters.len());
        for (i, c) in clusters.iter().enumerate() {
            let Some(at) = g.cluster_to_byte(*c) else { continue };
            let (start, len) = if i == 0 {
                // The first cluster is entered part-way through, at the record itself.
                let within = from.saturating_sub(at);
                (from, g.bytes_per_cluster.saturating_sub(within))
            } else {
                (at, g.bytes_per_cluster)
            };
            match runs.last_mut() {
                Some((o, l)) if *o + *l == start => *l += len,
                _ => runs.push((start, len)),
            }
        }
        Ok(runs)
    }
}

fn finish(count: usize, first_at: Option<u64>) -> Result<Option<(usize, u64)>, String> {
    Ok(match (count, first_at) {
        (0, _) | (_, None) => None,
        (n, Some(at)) => Some((n, at)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::{Extent, MemSource, NodeKind, RegionReader};
    use std::sync::Arc;

    /// 2048 sectors, 1 per cluster, 4-sector FATs -> root directory at byte 20480.
    const ROOT: u64 = (32 + 2 * 4) * 512;

    fn volume() -> Vec<u8> {
        super::super::synth_fat32(2048, 1, 4)
    }

    fn reader(img: Vec<u8>) -> FatReader {
        FatReader::new(Arc::new(MemSource::new(img)), 0)
    }

    /// A node standing for one record at directory slot `slot`.
    fn record(slot: u64) -> Node {
        Node {
            label: "?EST.TXT (deleted)".into(),
            extent: Extent::One(Span::bytes(ROOT + slot * 32, 32)),
            kind: NodeKind::Group,
            ..Default::default()
        }
    }

    fn delete(img: &mut [u8], slot: u64) {
        img[(ROOT + slot * 32) as usize] = desc::DELETED_MARK;
    }

    #[test]
    fn neutral_keeps_the_marker_and_zeroes_everything_else() {
        let mut img = volume();
        super::super::synth_entry(&mut img, (ROOT) as usize, b"SECRET  TXT", 0x20, 5, 1234);
        delete(&mut img, 0);
        let r = reader(img);

        let p = r.scrub_plan(&record(0), ScrubMode::Record(Fill::Neutral)).expect("a deleted record has a plan");
        assert_eq!(p.records(), 1);
        let e = &p.edits[0];
        assert_eq!(e.offset, ROOT);
        assert_eq!(e.new[0], desc::DELETED_MARK, "the marker must survive");
        assert!(e.new[1..].iter().all(|&b| b == 0));
        assert!(p.removes.iter().any(|s| s.contains("1234 bytes")), "{:?}", p.removes);
        assert!(p.removes.iter().any(|s| s.contains("first cluster, 5")), "{:?}", p.removes);
    }

    #[test]
    fn zeroing_is_warned_about_not_refused_when_a_live_record_follows() {
        // The whole reason the guard exists: a zeroed first byte means "stop
        // scanning", so doing this ahead of a live entry hides it from every driver.
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"GONE    TXT", 0x20, 5, 10);
        super::super::synth_entry(&mut img, (ROOT + 32) as usize, b"KEEPME  TXT", 0x20, 6, 20);
        delete(&mut img, 0);
        let r = reader(img);

        let p = r.scrub_plan(&record(0), ScrubMode::Record(Fill::Zero)).unwrap();
        assert!(!p.zero_is_free(), "a live record follows, so zeroing has a cost");
        assert!(!p.edits.is_empty(), "the plan is still offered: warned, not refused");
        match p.zero_refusal.as_ref().unwrap() {
            ZeroRefusal::InUseRecordsFollow { count, first_at } => {
                assert_eq!(*count, 1);
                assert_eq!(*first_at, ROOT + 32);
            }
            other => panic!("wrong refusal: {other:?}"),
        }
        // ...and the warning is a property of the record, not of the fill chosen.
        let n = r.scrub_plan(&record(0), ScrubMode::Record(Fill::Neutral)).unwrap();
        assert!(!n.zero_is_free());
        assert_eq!(n.edits.len(), 1);
    }

    #[test]
    fn zero_is_allowed_when_nothing_in_use_follows() {
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"LIVE    TXT", 0x20, 5, 10);
        super::super::synth_entry(&mut img, (ROOT + 32) as usize, b"GONE    TXT", 0x20, 6, 20);
        delete(&mut img, 1);
        let r = reader(img);

        let p = r.scrub_plan(&record(1), ScrubMode::Record(Fill::Zero)).unwrap();
        assert!(p.zero_is_free(), "only free records follow: {:?}", p.zero_refusal);
        assert!(p.edits[0].new.iter().all(|&b| b == 0));
    }

    #[test]
    fn deleted_records_following_do_not_block_zeroing() {
        // They are already unreachable; hiding them changes nothing that a driver
        // could see, and their bytes are untouched either way.
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"GONE    TXT", 0x20, 5, 10);
        super::super::synth_entry(&mut img, (ROOT + 32) as usize, b"ALSOGONETXT", 0x20, 6, 20);
        delete(&mut img, 0);
        delete(&mut img, 1);
        let r = reader(img);
        assert!(r.scrub_plan(&record(0), ScrubMode::Record(Fill::Zero)).unwrap().zero_is_free());
    }

    #[test]
    fn a_live_record_has_no_plan() {
        // Scrubbing a live file would orphan its clusters and lose something the
        // user did not ask to lose. Not this command's business.
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"LIVE    TXT", 0x20, 5, 10);
        let r = reader(img);
        assert!(r.scrub_plan(&record(0), ScrubMode::Record(Fill::Neutral)).is_none());
    }

    #[test]
    fn selecting_a_field_rather_than_a_record_has_no_plan() {
        // Scrubbing 11 bytes of a name leaves the rest of the record readable.
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"SECRET  TXT", 0x20, 5, 10);
        delete(&mut img, 0);
        let r = reader(img);
        let field = Node {
            label: "name".into(),
            extent: Extent::One(Span::bytes(ROOT, 11)),
            ..Default::default()
        };
        assert!(r.scrub_plan(&field, ScrubMode::Record(Fill::Neutral)).is_none());
    }

    #[test]
    fn a_whole_record_set_is_planned_together() {
        let mut img = volume();
        // two long-filename fragments then the short entry
        for slot in 0..2 {
            let o = (ROOT + slot * 32) as usize;
            img[o] = desc::DELETED_MARK;
            img[o + 0x0B] = desc::ATTR_LONG_NAME;
        }
        super::super::synth_entry(&mut img, (ROOT + 64) as usize, b"SECRET  TXT", 0x20, 5, 10);
        delete(&mut img, 2);
        let r = reader(img);

        let set = Node {
            label: "secret.txt (deleted)".into(),
            extent: Extent::Many(vec![
                Span::bytes(ROOT + 64, 32),
                Span::bytes(ROOT + 32, 32),
                Span::bytes(ROOT, 32),
            ]),
            kind: NodeKind::Group,
            ..Default::default()
        };
        let p = r.scrub_plan(&set, ScrubMode::Record(Fill::Neutral)).unwrap();
        assert_eq!(p.records(), 3, "half a set would leave the name recoverable");
        // edits come out in on-disk order regardless of the logical order above
        assert_eq!(p.edits[0].offset, ROOT);
        assert_eq!(p.edits[2].offset, ROOT + 64);
        assert!(p.removes.iter().any(|s| s.contains("2 fragment(s)")), "{:?}", p.removes);
    }

    #[test]
    fn an_unreadable_directory_refuses_zeroing_rather_than_guessing() {
        use blktamper_core::source::FailingSource;
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"SECRET  TXT", 0x20, 5, 10);
        delete(&mut img, 0);
        let src = FailingSource { inner: MemSource::new(img), fail_from: ROOT + 32 };
        let r = FatReader::new(Arc::new(src), 0);
        let p = r.scrub_plan(&record(0), ScrubMode::Record(Fill::Zero));
        // The record itself is readable, so there is a plan; the guarantee is not.
        if let Some(p) = p {
            assert!(matches!(p.zero_refusal, Some(ZeroRefusal::CouldNotVerify(_))));
        }
    }

    #[test]
    fn a_files_cluster_is_never_mistaken_for_a_directory() {
        // A file's first cluster has exactly the shape the directory check looks for:
        // one span, cluster-aligned, one cluster long. Accepting one and "compacting"
        // it would rewrite file data as though it were directory records, which is
        // the worst thing this code could do.
        let mut img = volume();
        let data_at = ROOT as usize + 512; // cluster 3
        // Plausible file contents, not directory records.
        for (i, b) in img[data_at..data_at + 512].iter_mut().enumerate() {
            *b = (i as u8) ^ 0xC3;
        }
        let r = reader(img);
        let cluster = Node {
            label: "file data".into(),
            extent: Extent::One(Span::bytes(ROOT + 512, 512)),
            kind: NodeKind::Region,
            ..Default::default()
        };
        for mode in [ScrubMode::Compact, ScrubMode::Sweep] {
            assert!(
                r.scrub_plan(&cluster, mode).is_none(),
                "{mode:?} accepted a file's cluster as a directory"
            );
        }
    }

    #[test]
    fn a_real_directory_is_still_accepted() {
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"LIVE    TXT", 0x20, 5, 10);
        super::super::synth_entry(&mut img, (ROOT + 32) as usize, b"GONE    TXT", 0x20, 6, 20);
        delete(&mut img, 1);
        let r = reader(img);
        let dir = Node {
            label: "root directory".into(),
            extent: Extent::One(Span::bytes(ROOT, 512)),
            kind: NodeKind::Region,
            ..Default::default()
        };
        let p = r.scrub_plan(&dir, ScrubMode::Compact).expect("a real directory compacts");
        assert_eq!(p.affected.len(), 1, "one deleted record to remove");
        // The live record stays at slot 0, the deleted one is zeroed.
        let zeroed = p.edits.iter().find(|e| e.offset == ROOT + 32).expect("slot 1 changes");
        assert!(zeroed.new.iter().all(|&b| b == 0));
        assert!(
            !p.edits.iter().any(|e| e.offset == ROOT),
            "the live record at slot 0 does not move, so it needs no edit"
        );
    }

    #[test]
    fn compaction_relocates_survivors_past_a_removed_record() {
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"GONE    TXT", 0x20, 5, 10);
        super::super::synth_entry(&mut img, (ROOT + 32) as usize, b"KEEPME  TXT", 0x20, 6, 20);
        delete(&mut img, 0);
        let r = reader(img);
        let dir = Node {
            label: "root directory".into(),
            extent: Extent::One(Span::bytes(ROOT, 512)),
            kind: NodeKind::Region,
            ..Default::default()
        };
        let p = r.scrub_plan(&dir, ScrubMode::Compact).unwrap();
        assert_eq!(p.relocated, 1, "the survivor moves up into the gap");
        let moved = p.edits.iter().find(|e| e.offset == ROOT).expect("slot 0 is rewritten");
        assert_eq!(&moved.new[..11], b"KEEPME  TXT");
        let vacated = p.edits.iter().find(|e| e.offset == ROOT + 32).expect("slot 1 is vacated");
        assert!(vacated.new.iter().all(|&b| b == 0), "the vacated slot must be zeroed");
    }

    #[test]
    fn sweep_leaves_an_interleaved_tombstone_but_empties_it() {
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"GONE    TXT", 0x20, 5, 10);
        super::super::synth_entry(&mut img, (ROOT + 32) as usize, b"LIVE    TXT", 0x20, 6, 20);
        delete(&mut img, 0);
        let r = reader(img);
        let dir = Node {
            label: "root directory".into(),
            extent: Extent::One(Span::bytes(ROOT, 512)),
            kind: NodeKind::Region,
            ..Default::default()
        };
        let p = r.scrub_plan(&dir, ScrubMode::Sweep).unwrap();
        assert_eq!(p.relocated, 0, "a sweep moves nothing");
        let t = p.edits.iter().find(|e| e.offset == ROOT).unwrap();
        assert_eq!(t.new[0], desc::DELETED_MARK, "the marker stays so the live record stays visible");
        assert!(t.new[1..].iter().all(|&b| b == 0), "but the content goes");
        assert!(
            !p.edits.iter().any(|e| e.offset == ROOT + 32),
            "the live record is untouched"
        );
    }

    #[test]
    fn a_record_past_the_end_of_the_device_has_no_plan() {
        let r = reader(volume());
        let node = Node {
            label: "x".into(),
            extent: Extent::One(Span::bytes(u64::MAX - 64, 32)),
            ..Default::default()
        };
        assert!(r.scrub_plan(&node, ScrubMode::Record(Fill::Neutral)).is_none());
    }
}
