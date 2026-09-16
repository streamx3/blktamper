//! Byte/bit provenance. Every node in the tree knows exactly which bits it came from.

use core::fmt;

/// A contiguous run of bits on the device, absolute from byte 0.
///
/// Bit granularity exists because flag fields are real fields: GPT attribute bit 60,
/// the FAT directory attribute bits, the exFAT volume flags. A viewer that can only
/// point at bytes cannot highlight "this bit".
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Span {
    pub start_bit: u64,
    pub len_bits: u64,
}

impl Span {
    pub const EMPTY: Span = Span { start_bit: 0, len_bits: 0 };

    /// Saturating, not wrapping. `start` is routinely derived from a value read off
    /// the disk — a partition LBA, a cluster number — so it is attacker-controlled,
    /// and `start * 8` overflows for anything above 2^61. With `overflow-checks`
    /// on in release that is a panic, which would break the never-panic invariant
    /// (R-3.7). A saturated offset renders as an obviously absurd address, which is
    /// the correct outcome: a finding, not a crash.
    #[inline]
    pub const fn bytes(start: u64, len: u64) -> Span {
        Span { start_bit: start.saturating_mul(8), len_bits: len.saturating_mul(8) }
    }

    #[inline]
    pub const fn bits(start_bit: u64, len_bits: u64) -> Span {
        Span { start_bit, len_bits }
    }

    /// A single bit `bit` within the byte at `byte_off`, counting from the LSB —
    /// which is how every format in scope numbers its flag bits.
    #[inline]
    pub const fn flag_bit(byte_off: u64, bit: u32) -> Span {
        Span { start_bit: byte_off.saturating_mul(8).saturating_add(bit as u64), len_bits: 1 }
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len_bits == 0
    }

    /// First byte touched.
    #[inline]
    pub const fn start_byte(&self) -> u64 {
        self.start_bit / 8
    }

    /// One past the last byte touched (rounded up, so a single bit covers one byte).
    #[inline]
    pub const fn end_byte(&self) -> u64 {
        self.start_bit.saturating_add(self.len_bits).div_ceil(8)
    }

    #[inline]
    pub const fn byte_len(&self) -> u64 {
        self.end_byte().saturating_sub(self.start_byte())
    }

    /// True when the span starts and ends on a byte boundary.
    #[inline]
    pub const fn is_byte_aligned(&self) -> bool {
        self.start_bit % 8 == 0 && self.len_bits % 8 == 0
    }

    #[inline]
    pub const fn end_bit(&self) -> u64 {
        self.start_bit.saturating_add(self.len_bits)
    }

    pub const fn contains_bit(&self, bit: u64) -> bool {
        bit >= self.start_bit && bit < self.end_bit()
    }

    pub const fn contains_byte(&self, byte: u64) -> bool {
        byte >= self.start_byte() && byte < self.end_byte()
    }

    pub fn overlaps(&self, other: &Span) -> bool {
        self.start_bit < other.end_bit() && other.start_bit < self.end_bit()
    }

    /// Shift by a whole number of bytes, saturating rather than wrapping.
    #[inline]
    pub const fn offset_bytes(self, delta: u64) -> Span {
        Span { start_bit: self.start_bit.saturating_add(delta.saturating_mul(8)), len_bits: self.len_bits }
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_byte_aligned() {
            write!(f, "{:#010x}..{:#010x}", self.start_byte(), self.end_byte())
        } else {
            write!(f, "{:#010x}.{}..+{}b", self.start_byte(), self.start_bit % 8, self.len_bits)
        }
    }
}

/// Where a node's bytes live. Most nodes are one run; some are not.
///
/// `Many` is not an optimisation for later: a file following a cluster chain, an
/// exFAT directory entry set straddling a cluster boundary, and a FAT long-filename
/// run stored in reverse order are all genuinely discontiguous, and the hex pane has
/// to highlight all of their pieces.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Extent {
    /// A computed or synthetic node that owns no bytes of its own.
    #[default]
    None,
    One(Span),
    /// Ordered in *logical* order, which is not necessarily ascending on disk.
    Many(Vec<Span>),
}

impl Extent {
    pub fn bytes(start: u64, len: u64) -> Extent {
        Extent::One(Span::bytes(start, len))
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Extent::None)
    }

    /// The first span in logical order, if any.
    pub fn first(&self) -> Option<Span> {
        match self {
            Extent::None => None,
            Extent::One(s) => Some(*s),
            Extent::Many(v) => v.first().copied(),
        }
    }

    /// Total bits across all pieces.
    pub fn len_bits(&self) -> u64 {
        match self {
            Extent::None => 0,
            Extent::One(s) => s.len_bits,
            Extent::Many(v) => v.iter().map(|s| s.len_bits).sum(),
        }
    }

    pub fn len_bytes(&self) -> u64 {
        self.len_bits().div_ceil(8)
    }

    /// Lowest byte offset touched, for "where is this on the disk" ordering.
    pub fn min_byte(&self) -> Option<u64> {
        match self {
            Extent::None => None,
            Extent::One(s) => Some(s.start_byte()),
            Extent::Many(v) => v.iter().map(|s| s.start_byte()).min(),
        }
    }

    pub fn spans(&self) -> &[Span] {
        match self {
            Extent::None => &[],
            Extent::One(s) => core::slice::from_ref(s),
            Extent::Many(v) => v.as_slice(),
        }
    }

    pub fn contains_byte(&self, byte: u64) -> bool {
        self.spans().iter().any(|s| s.contains_byte(byte))
    }
}

impl From<Span> for Extent {
    fn from(s: Span) -> Self {
        Extent::One(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_spans_round_trip() {
        let s = Span::bytes(0x1be, 16);
        assert_eq!(s.start_byte(), 0x1be);
        assert_eq!(s.end_byte(), 0x1ce);
        assert_eq!(s.byte_len(), 16);
        assert!(s.is_byte_aligned());
    }

    #[test]
    fn single_bit_covers_one_byte() {
        let s = Span::flag_bit(0x0b, 4);
        assert_eq!(s.len_bits, 1);
        assert_eq!(s.start_byte(), 0x0b);
        assert_eq!(s.end_byte(), 0x0c);
        assert!(!s.is_byte_aligned());
        assert!(s.contains_byte(0x0b));
        assert!(!s.contains_byte(0x0c));
    }

    #[test]
    fn overlap_detection() {
        let a = Span::bytes(0, 4);
        let b = Span::bytes(3, 4);
        let c = Span::bytes(4, 4);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn extent_many_sums_and_orders() {
        let e = Extent::Many(vec![Span::bytes(100, 32), Span::bytes(20, 32)]);
        assert_eq!(e.len_bytes(), 64);
        // logical order is preserved; min_byte finds the on-disk minimum
        assert_eq!(e.first().unwrap().start_byte(), 100);
        assert_eq!(e.min_byte(), Some(20));
    }

    #[test]
    fn construction_saturates_instead_of_overflowing() {
        // Every one of these is reachable from a corrupt on-disk value.
        let s = Span::bytes(u64::MAX, 16);
        assert_eq!(s.start_bit, u64::MAX);
        assert_eq!(Span::bytes(0, u64::MAX).len_bits, u64::MAX);
        assert_eq!(Span::flag_bit(u64::MAX, 7).start_bit, u64::MAX);
        // and the derived accessors must not overflow either
        let _ = s.end_bit();
        let _ = s.end_byte();
        let _ = s.byte_len();
    }

    #[test]
    fn offset_saturates_instead_of_wrapping() {
        let s = Span::bytes(u64::MAX / 8, 1);
        let shifted = s.offset_bytes(u64::MAX);
        assert_eq!(shifted.start_bit, u64::MAX);
    }
}
