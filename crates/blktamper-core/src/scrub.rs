//! Overwriting a recoverable record.
//!
//! A deleted file is not gone: on FAT the delete changes exactly one byte per
//! record, leaving the long filename, every timestamp, the size and the first
//! cluster intact; on exFAT it clears one bit of three type bytes and leaves
//! everything else. Scrubbing is the operation that actually removes that residue.
//!
//! Two fills, and random is not one of them ([ADR-011](../../../doc/03-decisions.md)):
//! a directory cluster a formatter never used is zeros, so noise written into one
//! announces that somebody scrubbed there, while zeros are indistinguishable from
//! space that was never allocated.
//!
//! Nothing here writes. A `ScrubPlan` is a description; applying it is the caller's
//! decision and goes through the overlay, the journal and an explicit commit.

use crate::checksum::ByteEdit;
use crate::node::Diagnostic;
use crate::span::Span;

/// What to write over the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Fill {
    /// Keep the byte that marks the record deleted; zero everything else.
    ///
    /// Always safe: the record stays a deleted record, so directory scanning is
    /// unchanged. Leaves a tombstone — that *a* file was deleted here stays
    /// visible, which file it was does not.
    #[default]
    Neutral,
    /// Zero the whole record, so it reads as space that was never used.
    ///
    /// Only valid when nothing in use follows in the same directory: a zeroed first
    /// byte means *stop scanning* to both FAT and exFAT, so doing this ahead of live
    /// entries hides them from every driver.
    Zero,
}

impl Fill {
    pub fn label(self) -> &'static str {
        match self {
            Fill::Neutral => "neutral",
            Fill::Zero => "zero",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Fill::Neutral => "keep the deleted marker, zero the rest",
            Fill::Zero => "zero every byte; reads as never used",
        }
    }
}

/// What a directory-wide scrub should leave behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ScrubMode {
    /// One record set only, keeping its deleted marker.
    Record(Fill),
    /// Every deleted record in the directory gets its payload zeroed but keeps its
    /// marker; everything past the last live record is zeroed outright.
    ///
    /// Lower blast radius than `Compact` — no live record moves — at the cost of
    /// leaving tombstones wherever they are interleaved with live files.
    Sweep,
    /// Deleted records are removed, the survivors close the gap, and everything they
    /// vacate is zeroed along with the rest of the directory's allocated space.
    ///
    /// The default: it is the only mode that leaves no tombstone at all. Feasible
    /// because neither FAT nor exFAT has positional back-references — nothing points
    /// at "record 6 of this directory", so survivors can move. (NTFS would be a
    /// different story; MFT references are positional.)
    #[default]
    Compact,
}

impl ScrubMode {
    pub fn label(self) -> &'static str {
        match self {
            ScrubMode::Record(Fill::Neutral) => "neutral",
            ScrubMode::Record(Fill::Zero) => "zero",
            ScrubMode::Sweep => "sweep",
            ScrubMode::Compact => "compact",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            ScrubMode::Record(f) => f.describe(),
            ScrubMode::Sweep => "blank every deleted record, zero the tail",
            ScrubMode::Compact => "remove them, close the gap, zero the tail",
        }
    }

    /// True when survivors are relocated, so the whole directory is rewritten.
    pub fn relocates(self) -> bool {
        self == ScrubMode::Compact
    }

    /// True when the mode operates on a directory rather than one record set.
    pub fn is_directory_wide(self) -> bool {
        matches!(self, ScrubMode::Sweep | ScrubMode::Compact)
    }
}

/// How a directory record reads right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordClass {
    /// In use by a file or directory. Never touched: only the marker distinguishes a
    /// live record from a deleted one, so the conservative reading is the safe one.
    Live,
    /// Marked deleted but still holding its content. The residue this removes.
    Deleted,
    /// Never used, or already blanked.
    Free,
}

/// The shape of one record, as far as scrubbing is concerned.
#[derive(Clone, Copy, Debug)]
pub struct RecordShape {
    /// Offset within the record of the byte that marks it deleted.
    ///
    /// Both formats in scope put it at 0: FAT's first name byte, exFAT's entry type.
    pub marker_off: u32,
    pub len: u32,
}

impl RecordShape {
    pub const DIR_ENTRY_32: RecordShape = RecordShape { marker_off: 0, len: 32 };
}

/// What zeroing a record would cost here.
///
/// Not a refusal. R-7.8 says the tool warns and the user decides, and zeroing is
/// recoverable in every case below: the records that become unreachable keep their
/// bytes, blktamper still shows them, and restoring the one record from the journal
/// makes them reachable again. Hiding and destroying are different claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZeroRefusal {
    /// In-use records follow in this directory; zeroing would hide them.
    InUseRecordsFollow { count: usize, first_at: u64 },
    /// The scan could not reach the end of the directory, so it cannot promise.
    CouldNotVerify(String),
}

impl ZeroRefusal {
    pub fn message(&self) -> String {
        match self {
            ZeroRefusal::InUseRecordsFollow { count, first_at } => format!(
                "{count} file(s) still in use follow in this directory, the first at \
                 {first_at:#012X}. Zeroing this record writes a stop-scanning marker \
                 ahead of them, so the OS stops seeing them. Their records and data are \
                 untouched and undo restores them — but compact does the same job \
                 without hiding anything."
            ),
            ZeroRefusal::CouldNotVerify(why) => format!(
                "cannot confirm what follows in this directory ({why}), so zeroing is \
                 not offered"
            ),
        }
    }
}

/// A described, unapplied scrub.
#[derive(Clone, Debug)]
pub struct ScrubPlan {
    /// The target as the user sees it, e.g. `?ECRET.TXT (deleted)`.
    pub label: String,
    pub mode: ScrubMode,
    /// Records this removes or blanks, named for the confirmation.
    pub affected: Vec<String>,
    /// Live records this moves. Non-empty only for `Compact`, and the reason its
    /// blast radius is the whole directory rather than one sector.
    pub relocated: usize,
    /// One edit per record in the set, in on-disk order.
    pub edits: Vec<ByteEdit>,
    /// Information this destroys, in the user's terms.
    pub removes: Vec<String>,
    /// Information that survives it.
    pub keeps: Vec<String>,
    /// What zeroing costs here, when it costs anything. Advisory, not a veto.
    pub zero_refusal: Option<ZeroRefusal>,
    /// Anything else the user should read before committing.
    pub warnings: Vec<Diagnostic>,
}

impl ScrubPlan {
    pub fn bytes_changed(&self) -> usize {
        self.edits
            .iter()
            .map(|e| e.old.iter().zip(&e.new).filter(|(a, b)| a != b).count())
            .sum()
    }

    pub fn records(&self) -> usize {
        self.edits.len()
    }

    /// Sectors this rewrites in full, with how many bytes of each are actually
    /// changing. A 32-byte scrub rewrites a whole sector, and that sector holds
    /// other directory records — the confirmation has to say so.
    pub fn sectors_touched(&self, sector_size: u64) -> Vec<(u64, usize)> {
        let mut map: std::collections::BTreeMap<u64, usize> = Default::default();
        for e in &self.edits {
            let (first, count) = e.sectors_touched(sector_size.max(1));
            let changed = e.old.iter().zip(&e.new).filter(|(a, b)| a != b).count();
            for s in first..first + count {
                *map.entry(s).or_default() += changed;
            }
        }
        map.into_iter().collect()
    }

    /// True when zeroing has no consequence beyond the record itself.
    pub fn zero_is_free(&self) -> bool {
        self.zero_refusal.is_none()
    }

    /// The fill, for record-scoped plans.
    pub fn fill(&self) -> Option<Fill> {
        match self.mode {
            ScrubMode::Record(f) => Some(f),
            _ => None,
        }
    }
}

/// Lay out a directory after a `Sweep` or a `Compact`.
///
/// `records` is every record from the directory's start to the end of its allocated
/// space, in on-disk order, and the scan that produced it must not have stopped at an
/// end-of-directory marker: a record past that marker is invisible to a driver but
/// its bytes are just as readable, and leaving it is exactly the residue this exists
/// to remove.
///
/// Returns the new bytes for each record, same length and order as the input.
pub fn layout_directory(
    records: &[Vec<u8>],
    class: &[RecordClass],
    mode: ScrubMode,
    shape: RecordShape,
) -> Vec<Vec<u8>> {
    let len = records.len().min(class.len());
    let blank = |n: usize| vec![0u8; n];

    match mode {
        ScrubMode::Record(_) => records.to_vec(),

        ScrubMode::Sweep => {
            // Everything from the last live record onward can be zeroed outright:
            // nothing reachable follows it, so no driver's scan is affected.
            let last_live = (0..len).rev().find(|&i| class[i] == RecordClass::Live);
            (0..len)
                .map(|i| match (last_live, class[i]) {
                    (Some(l), _) if i > l => blank(records[i].len()),
                    (None, _) => blank(records[i].len()),
                    (_, RecordClass::Live) => records[i].clone(),
                    (_, RecordClass::Deleted) => scrub_bytes(&records[i], shape, Fill::Neutral),
                    (_, RecordClass::Free) => blank(records[i].len()),
                })
                .collect()
        }

        ScrubMode::Compact => {
            // Survivors keep their relative order, which is what preserves a FAT
            // long-filename run (the fragments sit immediately before their 8.3
            // entry) and an exFAT entry set (primary then secondaries). Both are
            // contiguous, so packing in order never splits one.
            //
            // `.` and `..` stay first in a FAT subdirectory for free: they are live,
            // and they are already first.
            let mut out: Vec<Vec<u8>> = (0..len)
                .filter(|&i| class[i] == RecordClass::Live)
                .map(|i| records[i].clone())
                .collect();
            let width = records.first().map(|r| r.len()).unwrap_or(shape.len as usize);
            while out.len() < len {
                out.push(blank(width));
            }
            out.truncate(len);
            out
        }
    }
}

/// Compute the replacement bytes for one record.
///
/// `Neutral` preserves whatever byte currently marks the record deleted, rather than
/// writing a particular constant: FAT uses `0xE5` while exFAT uses whichever type
/// byte had its in-use bit cleared (`0x05`, `0x40`, `0x41`). Preserving what is there
/// is correct for both and needs no per-format table.
pub fn scrub_bytes(old: &[u8], shape: RecordShape, fill: Fill) -> Vec<u8> {
    let mut new = vec![0u8; old.len()];
    if fill == Fill::Neutral {
        if let Some(&marker) = old.get(shape.marker_off as usize) {
            if let Some(slot) = new.get_mut(shape.marker_off as usize) {
                *slot = marker;
            }
        }
    }
    new
}

/// Build the edit for one record, or `None` when it would change nothing.
pub fn scrub_edit(span: Span, old: &[u8], shape: RecordShape, fill: Fill, reason: &str) -> Option<ByteEdit> {
    let new = scrub_bytes(old, shape, fill);
    if new == old {
        return None;
    }
    Some(ByteEdit {
        offset: span.start_byte(),
        old: old.to_vec(),
        new,
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(marker: u8) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0] = marker;
        for (i, b) in v.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        v
    }

    #[test]
    fn neutral_keeps_whatever_marker_is_there() {
        // FAT deleted entry
        let out = scrub_bytes(&rec(0xE5), RecordShape::DIR_ENTRY_32, Fill::Neutral);
        assert_eq!(out[0], 0xE5);
        assert!(out[1..].iter().all(|&b| b == 0));

        // exFAT deleted file / stream / name entries each keep their own byte
        for m in [0x05u8, 0x40, 0x41] {
            let out = scrub_bytes(&rec(m), RecordShape::DIR_ENTRY_32, Fill::Neutral);
            assert_eq!(out[0], m, "neutral must not normalise the marker");
            assert!(out[1..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn zero_writes_nothing_but_zeros() {
        let out = scrub_bytes(&rec(0xE5), RecordShape::DIR_ENTRY_32, Fill::Zero);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn an_already_clean_record_produces_no_edit() {
        let clean = vec![0u8; 32];
        assert!(scrub_edit(Span::bytes(0, 32), &clean, RecordShape::DIR_ENTRY_32, Fill::Zero, "x").is_none());
        // ...but neutral over an already-zeroed record is also a no-op
        assert!(scrub_edit(Span::bytes(0, 32), &clean, RecordShape::DIR_ENTRY_32, Fill::Neutral, "x").is_none());
    }

    #[test]
    fn a_neutral_scrub_of_a_live_looking_record_still_only_touches_31_bytes() {
        let span = Span::bytes(0x1FC4C0, 32);
        let e = scrub_edit(span, &rec(0xE5), RecordShape::DIR_ENTRY_32, Fill::Neutral, "scrub").unwrap();
        assert_eq!(e.offset, 0x1FC4C0);
        assert_eq!(e.new[0], 0xE5);
        assert_eq!(e.old.len(), 32);
        assert_eq!(e.old.iter().zip(&e.new).filter(|(a, b)| a != b).count(), 31);
    }

    #[test]
    fn a_short_record_does_not_panic() {
        let short = vec![0xE5u8, 1, 2];
        let out = scrub_bytes(&short, RecordShape::DIR_ENTRY_32, Fill::Neutral);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], 0xE5);
        // marker beyond the data is simply not preserved
        let shape = RecordShape { marker_off: 99, len: 32 };
        let out = scrub_bytes(&short, shape, Fill::Neutral);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn a_two_byte_change_still_rewrites_whole_sectors() {
        let plan = ScrubPlan {
            label: "x".into(),
            mode: ScrubMode::Record(Fill::Neutral),
            affected: vec![],
            relocated: 0,
            edits: vec![ByteEdit {
                offset: 0x1FC4C0,
                old: vec![0xE5; 32],
                new: vec![0; 32],
                reason: String::new(),
            }],
            removes: vec![],
            keeps: vec![],
            zero_refusal: None,
            warnings: vec![],
        };
        let sectors = plan.sectors_touched(512);
        assert_eq!(sectors.len(), 1);
        assert_eq!(sectors[0].0, 0x1FC4C0 / 512);
        assert_eq!(plan.records(), 1);
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    const N: usize = 32;

    fn rec(marker: u8, payload: u8) -> Vec<u8> {
        let mut v = vec![payload; N];
        v[0] = marker;
        v
    }

    fn live() -> Vec<u8> {
        rec(b'L', 0x11)
    }
    fn del() -> Vec<u8> {
        rec(0xE5, 0x22)
    }
    fn free() -> Vec<u8> {
        vec![0u8; N]
    }

    fn classes(v: &[Vec<u8>]) -> Vec<RecordClass> {
        v.iter()
            .map(|r| match r[0] {
                0 => RecordClass::Free,
                0xE5 => RecordClass::Deleted,
                _ => RecordClass::Live,
            })
            .collect()
    }

    fn run(records: Vec<Vec<u8>>, mode: ScrubMode) -> Vec<Vec<u8>> {
        let c = classes(&records);
        layout_directory(&records, &c, mode, RecordShape::DIR_ENTRY_32)
    }

    #[test]
    fn compact_closes_the_gap_and_leaves_no_tombstone() {
        // [live][deleted][live][deleted][free]
        let out = run(vec![live(), del(), live(), del(), free()], ScrubMode::Compact);
        assert_eq!(out.len(), 5);
        assert_eq!(out[0], live());
        assert_eq!(out[1], live(), "the survivor moved up into the gap");
        for r in &out[2..] {
            assert!(r.iter().all(|&b| b == 0), "everything vacated must be zeroed");
        }
        assert!(
            !out.iter().any(|r| r[0] == 0xE5),
            "compaction's whole point is that no tombstone remains"
        );
    }

    #[test]
    fn compact_preserves_the_order_that_binds_a_name_to_its_record() {
        // A FAT long-filename run sits immediately before its 8.3 entry; an exFAT
        // entry set is primary-then-secondaries. Packing in order keeps both intact.
        let lfn_a = rec(b'1', 0xAA);
        let short_a = rec(b'A', 0xAB);
        let lfn_b = rec(b'2', 0xBB);
        let short_b = rec(b'B', 0xBC);
        let out = run(
            vec![lfn_a.clone(), short_a.clone(), del(), lfn_b.clone(), short_b.clone()],
            ScrubMode::Compact,
        );
        assert_eq!(out[0], lfn_a);
        assert_eq!(out[1], short_a);
        assert_eq!(out[2], lfn_b, "the pair must not be split by the compaction");
        assert_eq!(out[3], short_b);
        assert!(out[4].iter().all(|&b| b == 0));
    }

    #[test]
    fn sweep_blanks_tombstones_in_place_and_zeroes_past_the_last_live_record() {
        // [live][deleted][live][deleted][deleted][free]
        let out = run(
            vec![live(), del(), live(), del(), del(), free()],
            ScrubMode::Sweep,
        );
        assert_eq!(out[0], live(), "live records never move or change");
        assert_eq!(out[1][0], 0xE5, "an interleaved tombstone keeps its marker");
        assert!(out[1][1..].iter().all(|&b| b == 0), "but loses its content");
        assert_eq!(out[2], live());
        for r in &out[3..] {
            assert!(
                r.iter().all(|&b| b == 0),
                "past the last live record there is nothing to protect, so zero it"
            );
        }
    }

    #[test]
    fn sweep_zeroes_everything_when_no_record_is_live() {
        let out = run(vec![del(), del(), free()], ScrubMode::Sweep);
        for r in &out {
            assert!(r.iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn residue_in_a_never_used_record_is_removed_too() {
        // A record marked free whose remaining bytes are not zero: a directory entry
        // that was overwritten rather than erased. Both modes must clear it.
        let mut residue = vec![0u8; N];
        residue[5] = b'X';
        for mode in [ScrubMode::Sweep, ScrubMode::Compact] {
            let out = run(vec![live(), residue.clone()], mode);
            assert!(
                out[1].iter().all(|&b| b == 0),
                "{mode:?} must not leave overwritten-but-not-erased bytes behind"
            );
        }
    }

    #[test]
    fn a_directory_of_only_live_records_is_untouched_by_either_mode() {
        let input = vec![live(), live(), live()];
        for mode in [ScrubMode::Sweep, ScrubMode::Compact] {
            assert_eq!(run(input.clone(), mode), input, "{mode:?} changed a clean directory");
        }
    }

    #[test]
    fn compact_never_drops_a_live_record() {
        // The invariant that matters most: whatever the mix, every live record
        // survives and none is duplicated.
        let input = vec![del(), live(), del(), del(), live(), free(), live(), del()];
        let out = run(input.clone(), ScrubMode::Compact);
        let live_in = input.iter().filter(|r| r[0] == b'L').count();
        let live_out = out.iter().filter(|r| r[0] == b'L').count();
        assert_eq!(live_in, live_out, "compaction lost or duplicated a live record");
        assert_eq!(out.len(), input.len(), "the directory must not change size");
    }

    #[test]
    fn an_empty_directory_does_not_panic() {
        for mode in [ScrubMode::Sweep, ScrubMode::Compact, ScrubMode::Record(Fill::Zero)] {
            assert!(layout_directory(&[], &[], mode, RecordShape::DIR_ENTRY_32).is_empty());
        }
    }

    #[test]
    fn modes_describe_their_blast_radius() {
        assert!(ScrubMode::Compact.relocates());
        assert!(!ScrubMode::Sweep.relocates());
        assert!(ScrubMode::Sweep.is_directory_wide());
        assert!(!ScrubMode::Record(Fill::Neutral).is_directory_wide());
        assert_eq!(ScrubMode::default(), ScrubMode::Compact);
    }
}
