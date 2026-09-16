//! Staged edits sitting on top of a `BlockSource`.
//!
//! The overlay implements `BlockSource` itself, so the entire parse and render path
//! is unaware that editing exists: change a byte and the next render re-reads through
//! the overlay, so a checksum field recomputes and turns green before anything has
//! touched the device. That is the trick that makes the editor cheap, and it is a
//! better editing experience than writing first and looking afterwards.
//!
//! It is also the safety mechanism. A 32-byte scrub is physically a read-modify-write
//! of whichever sector holds it, and that sector holds other directory records; the
//! overlay preserves them by construction rather than by care.

use blktamper_core::{BlockSink, BlockSource, ByteEdit, ReadOutcome, WriteError};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// One staged change, with where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    pub edit: ByteEdit,
    /// Node path the edit came from, for the journal and the diff view.
    pub path: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StageError {
    #[error("{path}: the device no longer holds the bytes this edit was based on at {offset:#x} (expected {expected}, found {found}) — something else has written here")]
    Stale { path: String, offset: u64, expected: String, found: String },
    #[error("{path}: edit at {offset:#x} runs past the end of the device")]
    PastEnd { path: String, offset: u64 },
    #[error("{path}: edit at {offset:#x} overlaps an already-staged edit")]
    Overlaps { path: String, offset: u64 },
    #[error("the device could not be read at {offset:#x} to verify the edit")]
    Unreadable { offset: u64 },
}

pub struct Overlay {
    inner: Arc<dyn BlockSource>,
    /// Byte-granular edits. Fine for the sizes in scope — a record scrub is tens of
    /// bytes, a header restore is hundreds — and it makes overlap detection trivial.
    bytes: Mutex<BTreeMap<u64, u8>>,
    staged: Mutex<Vec<Staged>>,
}

impl std::fmt::Debug for Overlay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Overlay")
            .field("source", &self.inner.name())
            .field("staged_edits", &self.staged.lock().map(|s| s.len()).unwrap_or(0))
            .field("bytes_changed", &self.bytes.lock().map(|b| b.len()).unwrap_or(0))
            .finish()
    }
}

impl Overlay {
    pub fn new(inner: Arc<dyn BlockSource>) -> Overlay {
        Overlay { inner, bytes: Mutex::new(BTreeMap::new()), staged: Mutex::new(Vec::new()) }
    }

    pub fn is_dirty(&self) -> bool {
        !self.bytes.lock().unwrap().is_empty()
    }

    pub fn staged(&self) -> Vec<Staged> {
        self.staged.lock().unwrap().clone()
    }

    pub fn bytes_changed(&self) -> usize {
        self.bytes.lock().unwrap().len()
    }

    /// Discard everything staged. The device was never touched, so this is total.
    pub fn revert(&self) {
        self.bytes.lock().unwrap().clear();
        self.staged.lock().unwrap().clear();
    }

    /// Stage one edit.
    ///
    /// The `old` bytes are checked against what the device currently holds. That is
    /// not paranoia: the plan may have been built minutes ago, and on a live device
    /// something else may have written there since. Committing an edit whose basis
    /// has moved is how you corrupt a neighbour.
    pub fn stage(&self, edit: ByteEdit, path: impl Into<String>) -> Result<(), StageError> {
        let path = path.into();
        if edit.new.len() != edit.old.len() {
            return Err(StageError::Stale {
                path,
                offset: edit.offset,
                expected: format!("{} bytes", edit.old.len()),
                found: format!("{} bytes", edit.new.len()),
            });
        }
        let end = edit.offset.saturating_add(edit.new.len() as u64);
        if end > self.inner.len() {
            return Err(StageError::PastEnd { path, offset: edit.offset });
        }

        let (current, outcome) = self.inner.read_vec(edit.offset, edit.old.len());
        if outcome == ReadOutcome::Unreadable {
            return Err(StageError::Unreadable { offset: edit.offset });
        }
        if current != edit.old {
            return Err(StageError::Stale {
                path,
                offset: edit.offset,
                expected: blktamper_core::value::hex_bytes(&edit.old),
                found: blktamper_core::value::hex_bytes(&current),
            });
        }

        let mut bytes = self.bytes.lock().unwrap();
        for i in 0..edit.new.len() as u64 {
            if bytes.contains_key(&(edit.offset + i)) {
                return Err(StageError::Overlaps { path, offset: edit.offset });
            }
        }
        for (i, b) in edit.new.iter().enumerate() {
            bytes.insert(edit.offset + i as u64, *b);
        }
        drop(bytes);
        self.staged.lock().unwrap().push(Staged { edit, path });
        Ok(())
    }

    /// Stage several edits as one unit: if any is refused, none is staged.
    ///
    /// A half-scrubbed record set would leave the filename recoverable from the
    /// records that were not reached, which is the exact failure the feature exists
    /// to prevent.
    pub fn stage_all(&self, edits: Vec<ByteEdit>, path: &str) -> Result<(), StageError> {
        let before_bytes = self.bytes.lock().unwrap().clone();
        let before_staged = self.staged.lock().unwrap().clone();
        for e in edits {
            if let Err(err) = self.stage(e, path) {
                *self.bytes.lock().unwrap() = before_bytes;
                *self.staged.lock().unwrap() = before_staged;
                return Err(err);
            }
        }
        Ok(())
    }

    /// The sectors a commit would rewrite, and how many bytes of each actually change.
    pub fn sectors_touched(&self, sector_size: u64) -> Vec<(u64, usize)> {
        let ss = sector_size.max(1);
        let mut map: BTreeMap<u64, usize> = BTreeMap::new();
        for off in self.bytes.lock().unwrap().keys() {
            *map.entry(off / ss).or_default() += 1;
        }
        map.into_iter().collect()
    }

    /// Write every staged edit through `sink`, sector by sector.
    ///
    /// Callers are expected to have journalled first; this does not do it for them,
    /// because the journal has to be flushed *before* the device is touched and only
    /// the caller knows whether that happened.
    pub fn commit(&self, sink: &dyn BlockSink, sector_size: u64) -> Result<usize, WriteError> {
        let ss = sector_size.max(1);
        let bytes = self.bytes.lock().unwrap().clone();
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut sectors: Vec<u64> = bytes.keys().map(|o| o / ss).collect();
        sectors.sort_unstable();
        sectors.dedup();

        for sector in &sectors {
            let base = sector * ss;
            // Read-modify-write, explicitly: the sector holds bytes we are not
            // changing and they have to survive.
            let mut buf = vec![0u8; ss as usize];
            match self.inner.read_at(base, &mut buf) {
                ReadOutcome::Ok => {}
                ReadOutcome::Short { filled } => buf.truncate(filled.max(1)),
                ReadOutcome::Unreadable => {
                    return Err(WriteError::Io {
                        offset: base,
                        len: ss as usize,
                        source: std::io::Error::other(
                            "the sector could not be read back before rewriting it; \
                             refusing to write a sector whose other contents are unknown",
                        ),
                    })
                }
            }
            for (off, b) in bytes.range(base..base + buf.len() as u64) {
                buf[(off - base) as usize] = *b;
            }
            sink.write_at(base, &buf)?;
        }
        sink.flush()?;
        Ok(sectors.len())
    }
}

impl BlockSource for Overlay {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn logical_sector_size(&self) -> u32 {
        self.inner.logical_sector_size()
    }
    fn physical_sector_size(&self) -> u32 {
        self.inner.physical_sector_size()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ReadOutcome {
        let outcome = self.inner.read_at(offset, buf);
        if outcome == ReadOutcome::Unreadable {
            return outcome;
        }
        let end = offset.saturating_add(buf.len() as u64);
        for (off, b) in self.bytes.lock().unwrap().range(offset..end) {
            buf[(off - offset) as usize] = *b;
        }
        outcome
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::MemSource;

    fn src(n: usize) -> Arc<dyn BlockSource> {
        Arc::new(MemSource::new((0..n).map(|i| (i % 251) as u8).collect()))
    }

    fn edit(offset: u64, old: Vec<u8>, new: Vec<u8>) -> ByteEdit {
        ByteEdit { offset, old, new, reason: "test".into() }
    }

    #[test]
    fn reads_see_staged_edits_before_anything_is_written() {
        let inner = src(1024);
        let o = Overlay::new(inner.clone());
        let old = inner.read_vec(100, 4).0;
        o.stage(edit(100, old, vec![0xAA; 4]), "x").unwrap();

        let (seen, _) = o.read_vec(98, 8);
        assert_eq!(&seen[2..6], &[0xAA; 4]);
        // and the device underneath is untouched
        assert_ne!(inner.read_vec(100, 4).0, vec![0xAA; 4]);
    }

    #[test]
    fn a_stale_basis_is_refused() {
        let o = Overlay::new(src(1024));
        let err = o.stage(edit(100, vec![0xFF; 4], vec![0; 4]), "x").unwrap_err();
        assert!(matches!(err, StageError::Stale { .. }));
        assert!(!o.is_dirty(), "a refused edit must stage nothing");
    }

    #[test]
    fn overlapping_edits_are_refused() {
        let inner = src(1024);
        let o = Overlay::new(inner.clone());
        o.stage(edit(100, inner.read_vec(100, 4).0, vec![1; 4]), "a").unwrap();
        let err = o.stage(edit(102, inner.read_vec(102, 4).0, vec![2; 4]), "b").unwrap_err();
        assert!(matches!(err, StageError::Overlaps { .. }));
    }

    #[test]
    fn stage_all_is_all_or_nothing() {
        let inner = src(1024);
        let o = Overlay::new(inner.clone());
        let good = edit(100, inner.read_vec(100, 4).0, vec![1; 4]);
        let bad = edit(200, vec![0xFF; 4], vec![2; 4]); // wrong basis
        assert!(o.stage_all(vec![good, bad], "set").is_err());
        assert!(!o.is_dirty(), "a half-staged record set is the failure to avoid");
        assert!(o.staged().is_empty());
    }

    #[test]
    fn past_the_end_is_refused() {
        let o = Overlay::new(src(64));
        assert!(matches!(
            o.stage(edit(60, vec![0; 8], vec![1; 8]), "x").unwrap_err(),
            StageError::PastEnd { .. }
        ));
    }

    #[test]
    fn revert_leaves_no_trace() {
        let inner = src(1024);
        let o = Overlay::new(inner.clone());
        o.stage(edit(100, inner.read_vec(100, 4).0, vec![9; 4]), "x").unwrap();
        assert!(o.is_dirty());
        o.revert();
        assert!(!o.is_dirty());
        assert_eq!(o.read_vec(100, 4).0, inner.read_vec(100, 4).0);
    }

    #[test]
    fn a_two_byte_edit_reports_the_whole_sector() {
        let inner = src(4096);
        let o = Overlay::new(inner.clone());
        o.stage(edit(600, inner.read_vec(600, 2).0, vec![0; 2]), "x").unwrap();
        let s = o.sectors_touched(512);
        assert_eq!(s, vec![(1, 2)]);
    }

    #[test]
    fn unreadable_reads_are_not_masked_by_the_overlay() {
        use blktamper_core::source::{FailingSource, MemSource as M};
        let inner: Arc<dyn BlockSource> =
            Arc::new(FailingSource { inner: M::new(vec![0; 1024]), fail_from: 512 });
        let o = Overlay::new(inner);
        let mut buf = [0u8; 16];
        assert_eq!(o.read_at(600, &mut buf), ReadOutcome::Unreadable);
    }
}
