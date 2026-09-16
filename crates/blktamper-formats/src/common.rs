//! Helpers shared by every format module.
//!
//! Arithmetic here is checked, not wrapping. On a corrupt header a wrapped offset
//! points at a real sector and gets displayed with full confidence, which is the
//! failure mode this whole tool exists to avoid (ADR-008).

use blktamper_core::{BlockSource, Node, ReadCtx, ReadOutcome, StructDesc};

/// Read a struct's bytes and hand both to the generic reader.
///
/// Every format module reads its records through this, so short reads and I/O
/// errors are handled identically everywhere.
///
/// `ctx.base` is overwritten with `at`: the two must agree or every offset in the
/// resulting subtree is wrong, and a viewer whose offsets are wrong is worse than
/// no viewer. Callers pass `ctx` for the render settings and region base only.
pub fn read_desc_at(
    src: &dyn BlockSource,
    desc: &'static StructDesc,
    at: u64,
    ctx: ReadCtx,
) -> Node {
    let size = desc.size.unwrap_or(0) as usize;
    let (bytes, outcome) = src.read_vec(at, size);
    let ctx = ReadCtx { base: at, ..ctx };
    blktamper_core::read_struct(desc, &bytes, outcome, ctx)
}

/// LBA -> byte offset, refusing to wrap.
#[inline]
pub fn lba_to_byte(lba: u64, sector_size: u32) -> Option<u64> {
    lba.checked_mul(sector_size as u64)
}

/// Bytes available from `at` to the end of `src`, saturating at zero.
#[inline]
pub fn remaining(src: &dyn BlockSource, at: u64) -> u64 {
    src.len().saturating_sub(at)
}

/// True when the whole range lies inside the device.
#[inline]
pub fn in_bounds(src: &dyn BlockSource, at: u64, len: u64) -> bool {
    match at.checked_add(len) {
        Some(end) => end <= src.len(),
        None => false,
    }
}

/// Read `len` bytes, returning `None` for an unreadable range so callers can tell
/// "the device refused" from "the device holds zeros" (R-2.7).
pub fn read_exact_opt(src: &dyn BlockSource, at: u64, len: usize) -> Option<Vec<u8>> {
    let (v, outcome) = src.read_vec(at, len);
    match outcome {
        ReadOutcome::Ok => Some(v),
        ReadOutcome::Short { .. } => Some(v),
        ReadOutcome::Unreadable => None,
    }
}

/// Read the two-byte little-endian value at `off` within `buf`, if present.
#[inline]
pub fn u16le(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*buf.get(off)?, *buf.get(off + 1)?]))
}

#[inline]
pub fn u32le(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *buf.get(off)?,
        *buf.get(off + 1)?,
        *buf.get(off + 2)?,
        *buf.get(off + 3)?,
    ]))
}

#[inline]
pub fn u64le(buf: &[u8], off: usize) -> Option<u64> {
    let mut b = [0u8; 8];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = *buf.get(off + i)?;
    }
    Some(u64::from_le_bytes(b))
}

/// A cheap, bounded guard for the linked structures in these formats: EBR chains,
/// FAT cluster chains, exFAT entry sets. A corrupt disk will happily describe a
/// cycle, and following it forever is not an option in a UI thread.
#[derive(Debug)]
pub struct ChainGuard {
    seen: std::collections::HashSet<u64>,
    limit: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Continue,
    /// This value has already been visited: the chain loops.
    Loop,
    /// The chain is longer than any legitimate structure.
    TooLong,
}

impl ChainGuard {
    pub fn new(limit: usize) -> ChainGuard {
        ChainGuard { seen: std::collections::HashSet::new(), limit }
    }

    pub fn visit(&mut self, value: u64) -> Step {
        if self.seen.len() >= self.limit {
            return Step::TooLong;
        }
        if !self.seen.insert(value) {
            return Step::Loop;
        }
        Step::Continue
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::MemSource;

    #[test]
    fn lba_conversion_refuses_to_wrap() {
        assert_eq!(lba_to_byte(2048, 512), Some(1_048_576));
        assert_eq!(lba_to_byte(u64::MAX, 4096), None);
    }

    #[test]
    fn bounds_checks_do_not_overflow() {
        let s = MemSource::new(vec![0; 100]);
        assert!(in_bounds(&s, 0, 100));
        assert!(!in_bounds(&s, 0, 101));
        assert!(!in_bounds(&s, u64::MAX, 1));
    }

    #[test]
    fn chain_guard_catches_loops_and_runaways() {
        let mut g = ChainGuard::new(4);
        assert_eq!(g.visit(1), Step::Continue);
        assert_eq!(g.visit(2), Step::Continue);
        assert_eq!(g.visit(1), Step::Loop);
        let mut g = ChainGuard::new(2);
        g.visit(1);
        g.visit(2);
        assert_eq!(g.visit(3), Step::TooLong);
    }

    #[test]
    fn short_buffer_reads_return_none_not_garbage() {
        let b = [1u8, 2, 3];
        assert_eq!(u16le(&b, 0), Some(0x0201));
        assert_eq!(u32le(&b, 0), None);
        assert_eq!(u64le(&b, 0), None);
    }
}

#[cfg(test)]
mod offset_tests {
    use super::*;
    use blktamper_core::desc::f;
    use blktamper_core::{MemSource, Repr, StructDesc, Width};

    static D: StructDesc = StructDesc {
        name: "d",
        size: Some(4),
        fields: &[f("a", 0, Width::U16le, Repr::Dec, "x"), f("b", 2, Width::U16le, Repr::Dec, "x")],
        checks: &[],
        links: &[],
        spec: "test",
    };

    #[test]
    fn the_read_offset_wins_over_the_context_base() {
        // Passing a stale ctx must not silently produce a subtree whose offsets all
        // point at the wrong place: that is the one bug a structure viewer may not have.
        let src = MemSource::new((0..64u8).collect());
        let n = read_desc_at(&src, &D, 0x10, ReadCtx::at(0));
        assert_eq!(n.extent.first().unwrap().start_byte(), 0x10);
        let kids = n.children.resolved().unwrap();
        assert_eq!(kids[0].extent.first().unwrap().start_byte(), 0x10);
        assert_eq!(kids[1].extent.first().unwrap().start_byte(), 0x12);
    }
}
