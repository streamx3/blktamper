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

/// Why `Fill::Zero` is unavailable for a particular record.
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
                "{count} record(s) still in use follow in this directory, the first at \
                 {first_at:#012X}. Zeroing this one writes a stop-scanning marker ahead \
                 of them, which hides them from every driver."
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
    /// The record as the user sees it, e.g. `?ECRET.TXT (deleted)`.
    pub label: String,
    pub fill: Fill,
    /// One edit per record in the set, in on-disk order.
    pub edits: Vec<ByteEdit>,
    /// Information this destroys, in the user's terms.
    pub removes: Vec<String>,
    /// Information that survives it.
    pub keeps: Vec<String>,
    /// Whether `Fill::Zero` is available, and why not when it is not.
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

    pub fn zero_available(&self) -> bool {
        self.zero_refusal.is_none()
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
            fill: Fill::Neutral,
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
