//! Byte access. The only thing format modules know about the outside world.

use std::sync::Arc;

/// Outcome of a read. A failing sector is a distinct state, never zeros (R-2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// All requested bytes were filled.
    Ok,
    /// The request ran past the end of the device. `filled` bytes are valid.
    Short { filled: usize },
    /// The device returned an error. Buffer contents are undefined and must not be
    /// displayed as data.
    Unreadable,
}

impl ReadOutcome {
    pub fn is_ok(self) -> bool {
        matches!(self, ReadOutcome::Ok)
    }
    pub fn filled(self, requested: usize) -> usize {
        match self {
            ReadOutcome::Ok => requested,
            ReadOutcome::Short { filled } => filled,
            ReadOutcome::Unreadable => 0,
        }
    }
}

/// Read-only random access to a device or image.
///
/// Deliberately minimal: format modules must not be able to tell whether they are
/// looking at `/dev/sdc`, an `.img`, or a `Vec<u8>` in a unit test.
pub trait BlockSource: Send + Sync + std::fmt::Debug {
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Size LBAs are counted in. All LBA arithmetic uses this.
    fn logical_sector_size(&self) -> u32 {
        512
    }

    /// The device's real write granularity, when known. Informational.
    fn physical_sector_size(&self) -> u32 {
        self.logical_sector_size()
    }

    /// Fill `buf` from `offset`. Never partial without saying so.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ReadOutcome;

    /// Convenience: read `len` bytes, returning what was available plus the outcome.
    /// Truncated reads return the bytes that were readable; unreadable returns empty.
    fn read_vec(&self, offset: u64, len: usize) -> (Vec<u8>, ReadOutcome) {
        let mut buf = vec![0u8; len];
        let outcome = self.read_at(offset, &mut buf);
        match outcome {
            ReadOutcome::Ok => (buf, outcome),
            ReadOutcome::Short { filled } => {
                buf.truncate(filled);
                (buf, outcome)
            }
            ReadOutcome::Unreadable => (Vec::new(), outcome),
        }
    }

    /// Human label for the status bar: a path, or a description.
    fn name(&self) -> &str {
        "<source>"
    }
}

impl BlockSource for Arc<dyn BlockSource> {
    fn len(&self) -> u64 {
        (**self).len()
    }
    fn logical_sector_size(&self) -> u32 {
        (**self).logical_sector_size()
    }
    fn physical_sector_size(&self) -> u32 {
        (**self).physical_sector_size()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ReadOutcome {
        (**self).read_at(offset, buf)
    }
    fn name(&self) -> &str {
        (**self).name()
    }
}

/// An in-memory source. The unit-test and fuzzing backend, and the reason format
/// modules need no I/O layer to be tested.
#[derive(Debug)]
pub struct MemSource {
    data: Vec<u8>,
    sector_size: u32,
    name: String,
}

impl MemSource {
    pub fn new(data: Vec<u8>) -> MemSource {
        MemSource { data, sector_size: 512, name: "<memory>".into() }
    }
    pub fn with_sector_size(mut self, s: u32) -> MemSource {
        self.sector_size = s;
        self
    }
    pub fn with_name(mut self, n: impl Into<String>) -> MemSource {
        self.name = n.into();
        self
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl BlockSource for MemSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn logical_sector_size(&self) -> u32 {
        self.sector_size
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ReadOutcome {
        let Ok(start) = usize::try_from(offset) else {
            return ReadOutcome::Short { filled: 0 };
        };
        if start >= self.data.len() {
            buf.fill(0);
            return ReadOutcome::Short { filled: 0 };
        }
        let avail = self.data.len() - start;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        if n < buf.len() {
            buf[n..].fill(0);
            ReadOutcome::Short { filled: n }
        } else {
            ReadOutcome::Ok
        }
    }
    fn name(&self) -> &str {
        &self.name
    }
}

/// A source that fails every read past `fail_from`. Used to test that the tree
/// renders `Unreadable` rather than zeros.
#[derive(Debug)]
pub struct FailingSource {
    pub inner: MemSource,
    pub fail_from: u64,
}

impl BlockSource for FailingSource {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ReadOutcome {
        if offset >= self.fail_from {
            return ReadOutcome::Unreadable;
        }
        self.inner.read_at(offset, buf)
    }
    fn name(&self) -> &str {
        "<failing>"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_reads_report_how_much_was_filled() {
        let s = MemSource::new(vec![1, 2, 3, 4]);
        let mut buf = [0u8; 8];
        assert_eq!(s.read_at(2, &mut buf), ReadOutcome::Short { filled: 2 });
        assert_eq!(&buf[..2], &[3, 4]);
    }

    #[test]
    fn reads_past_the_end_are_short_not_zeros() {
        let s = MemSource::new(vec![1, 2, 3, 4]);
        let (v, o) = s.read_vec(100, 4);
        assert!(v.is_empty());
        assert_eq!(o, ReadOutcome::Short { filled: 0 });
    }

    #[test]
    fn unreadable_returns_no_data() {
        let s = FailingSource { inner: MemSource::new(vec![1, 2, 3, 4]), fail_from: 2 };
        let (v, o) = s.read_vec(2, 2);
        assert_eq!(o, ReadOutcome::Unreadable);
        assert!(v.is_empty());
    }

    #[test]
    fn huge_offsets_do_not_panic() {
        let s = MemSource::new(vec![0; 16]);
        let mut buf = [0u8; 4];
        assert!(!s.read_at(u64::MAX, &mut buf).is_ok());
    }
}

/// Write access. Deliberately a separate trait from `BlockSource`, so that "this
/// build cannot write" is a property you can check by looking for implementors
/// rather than by auditing call sites (ADR-007).
///
/// Implementors are expected to be opened for writing explicitly; nothing in this
/// crate ever turns a `BlockSource` into a `BlockSink`.
pub trait BlockSink: BlockSource {
    /// Write `data` at `offset`. Must write all of it or report an error.
    ///
    /// Note what this is not: a byte-granular operation. A block device's minimum
    /// unit is a sector, so writing two bytes is physically a read-modify-write of
    /// whichever sector holds them, and whatever else lives in that sector is
    /// rewritten along with them (doc/07-write-safety.md).
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), WriteError>;

    /// Push everything to the device. Returns only once the kernel says so.
    fn flush(&self) -> Result<(), WriteError>;

    /// Bytes that can be written; a write past this must be refused, not truncated.
    fn writable_len(&self) -> u64 {
        self.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("write of {len} bytes at {offset:#x} runs past the end of the device ({device_len} bytes)")]
    PastEnd { offset: u64, len: usize, device_len: u64 },
    #[error("the device is open read-only")]
    ReadOnly,
    #[error("I/O error writing {len} bytes at {offset:#x}: {source}")]
    Io {
        offset: u64,
        len: usize,
        #[source]
        source: std::io::Error,
    },
}
