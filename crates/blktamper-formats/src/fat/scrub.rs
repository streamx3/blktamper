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
use blktamper_core::scrub::{scrub_edit, Fill, RecordShape, ScrubPlan, ZeroRefusal};
use blktamper_core::{Node, Span};

/// A directory this long is either corrupt or hostile; the scan that decides whether
/// zeroing is safe must terminate either way.
const MAX_SCAN_CLUSTERS: usize = 4096;

impl FatReader {
    pub(super) fn plan_scrub(&self, node: &Node, fill: Fill) -> Option<ScrubPlan> {
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
            fill,
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

        for (start, len) in runs {
            let mut off = start;
            let end = start.saturating_add(len);
            while off + desc::ENTRY_SIZE <= end {
                let (b, outcome) = src.read_vec(off, desc::ENTRY_SIZE as usize);
                if b.len() != desc::ENTRY_SIZE as usize || outcome == blktamper_core::ReadOutcome::Unreadable {
                    return Err(format!("the directory could not be read at {off:#012X}"));
                }
                match b[0] {
                    desc::FREE_MARK => return finish(count, first_at), // end of directory
                    desc::DELETED_MARK => {}
                    _ => {
                        count += 1;
                        first_at.get_or_insert(off);
                    }
                }
                off += desc::ENTRY_SIZE;
            }
        }
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

        let p = r.scrub_plan(&record(0), Fill::Neutral).expect("a deleted record has a plan");
        assert_eq!(p.records(), 1);
        let e = &p.edits[0];
        assert_eq!(e.offset, ROOT);
        assert_eq!(e.new[0], desc::DELETED_MARK, "the marker must survive");
        assert!(e.new[1..].iter().all(|&b| b == 0));
        assert!(p.removes.iter().any(|s| s.contains("1234 bytes")), "{:?}", p.removes);
        assert!(p.removes.iter().any(|s| s.contains("first cluster, 5")), "{:?}", p.removes);
    }

    #[test]
    fn zero_is_refused_when_a_live_record_follows() {
        // The whole reason the guard exists: a zeroed first byte means "stop
        // scanning", so doing this ahead of a live entry hides it from every driver.
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"GONE    TXT", 0x20, 5, 10);
        super::super::synth_entry(&mut img, (ROOT + 32) as usize, b"KEEPME  TXT", 0x20, 6, 20);
        delete(&mut img, 0);
        let r = reader(img);

        let p = r.scrub_plan(&record(0), Fill::Zero).unwrap();
        assert!(!p.zero_available(), "a live record follows; zeroing must be refused");
        match p.zero_refusal.as_ref().unwrap() {
            ZeroRefusal::InUseRecordsFollow { count, first_at } => {
                assert_eq!(*count, 1);
                assert_eq!(*first_at, ROOT + 32);
            }
            other => panic!("wrong refusal: {other:?}"),
        }
        // ...while neutral is always available.
        let n = r.scrub_plan(&record(0), Fill::Neutral).unwrap();
        assert!(!n.zero_available(), "the refusal is a property of the record, not the fill");
        assert_eq!(n.edits.len(), 1);
    }

    #[test]
    fn zero_is_allowed_when_nothing_in_use_follows() {
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"LIVE    TXT", 0x20, 5, 10);
        super::super::synth_entry(&mut img, (ROOT + 32) as usize, b"GONE    TXT", 0x20, 6, 20);
        delete(&mut img, 1);
        let r = reader(img);

        let p = r.scrub_plan(&record(1), Fill::Zero).unwrap();
        assert!(p.zero_available(), "only free records follow: {:?}", p.zero_refusal);
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
        assert!(r.scrub_plan(&record(0), Fill::Zero).unwrap().zero_available());
    }

    #[test]
    fn a_live_record_has_no_plan() {
        // Scrubbing a live file would orphan its clusters and lose something the
        // user did not ask to lose. Not this command's business.
        let mut img = volume();
        super::super::synth_entry(&mut img, ROOT as usize, b"LIVE    TXT", 0x20, 5, 10);
        let r = reader(img);
        assert!(r.scrub_plan(&record(0), Fill::Neutral).is_none());
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
        assert!(r.scrub_plan(&field, Fill::Neutral).is_none());
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
        let p = r.scrub_plan(&set, Fill::Neutral).unwrap();
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
        let p = r.scrub_plan(&record(0), Fill::Zero);
        // The record itself is readable, so there is a plan; the guarantee is not.
        if let Some(p) = p {
            assert!(matches!(p.zero_refusal, Some(ZeroRefusal::CouldNotVerify(_))));
        }
    }

    #[test]
    fn a_record_past_the_end_of_the_device_has_no_plan() {
        let r = reader(volume());
        let node = Node {
            label: "x".into(),
            extent: Extent::One(Span::bytes(u64::MAX - 64, 32)),
            ..Default::default()
        };
        assert!(r.scrub_plan(&node, Fill::Neutral).is_none());
    }
}
