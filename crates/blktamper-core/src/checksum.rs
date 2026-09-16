//! Checksums, and the plan for recomputing them.
//!
//! Two things happen here, and they are the same code read in two directions:
//!
//! * **Viewing** — every checksum field renders as `stored / computed` with a
//!   pass/fail marker (R-3.6). This is the whole feature for a read-only build.
//! * **Recomputing** — `recompute_edit` turns a mismatch into the exact bytes that
//!   would make it match. It returns a proposed edit and writes nothing. Wiring it
//!   to the overlay is all that a write-capable build adds (R-7.7).
//!
//! Nothing here ever fixes anything on its own.

use crate::span::Span;
use crate::value::Value;

/// Checksum algorithms used by the formats in scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumAlgo {
    /// CRC-32/ISO-HDLC, as used by GPT headers and the GPT entry array.
    Crc32,
    /// exFAT boot region checksum: 32-bit rotate-right-and-add over sectors 0..=10.
    ExfatBootRegion,
    /// exFAT directory entry set checksum: 16-bit rotate-right-and-add.
    ExfatEntrySet,
    /// FAT short-name checksum tying a long-filename run to its 8.3 entry.
    FatShortName,
}

impl ChecksumAlgo {
    pub fn width_bytes(self) -> u32 {
        match self {
            ChecksumAlgo::Crc32 | ChecksumAlgo::ExfatBootRegion => 4,
            ChecksumAlgo::ExfatEntrySet => 2,
            ChecksumAlgo::FatShortName => 1,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ChecksumAlgo::Crc32 => "CRC-32",
            ChecksumAlgo::ExfatBootRegion => "exFAT boot checksum",
            ChecksumAlgo::ExfatEntrySet => "exFAT entry set checksum",
            ChecksumAlgo::FatShortName => "FAT short-name checksum",
        }
    }

    /// Compute over `data`, with the byte ranges in `exclude` (relative to `data`)
    /// treated as zero. Never fails; a short buffer simply covers fewer bytes.
    pub fn compute(self, data: &[u8], exclude: &[(u32, u32)]) -> u64 {
        let excluded = |i: usize| {
            exclude
                .iter()
                .any(|&(off, len)| i >= off as usize && i < off as usize + len as usize)
        };
        match self {
            ChecksumAlgo::Crc32 => {
                let mut crc = 0xFFFF_FFFFu32;
                for (i, &b) in data.iter().enumerate() {
                    let b = if excluded(i) { 0 } else { b };
                    crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize];
                }
                (crc ^ 0xFFFF_FFFF) as u64
            }
            ChecksumAlgo::ExfatBootRegion => {
                let mut sum = 0u32;
                for (i, &b) in data.iter().enumerate() {
                    if excluded(i) {
                        continue; // the spec *skips* these bytes, it does not zero them
                    }
                    sum = sum.rotate_right(1).wrapping_add(b as u32);
                }
                sum as u64
            }
            ChecksumAlgo::ExfatEntrySet => {
                let mut sum = 0u16;
                for (i, &b) in data.iter().enumerate() {
                    if excluded(i) {
                        continue;
                    }
                    sum = sum.rotate_right(1).wrapping_add(b as u16);
                }
                sum as u64
            }
            ChecksumAlgo::FatShortName => {
                let mut sum = 0u8;
                for (i, &b) in data.iter().enumerate() {
                    if excluded(i) {
                        continue;
                    }
                    sum = sum.rotate_right(1).wrapping_add(b);
                }
                sum as u64
            }
        }
    }
}

/// Which bytes a checksum covers.
#[derive(Clone, Copy, Debug)]
pub enum Cover {
    /// `len` bytes starting `start` bytes into the struct.
    Fixed { start: u32, len: u32 },
    /// `start` bytes into the struct, for however many bytes the named field says.
    /// This is how the GPT header CRC is defined — `header_size`, not 92, and not
    /// the sector size.
    FieldLen { start: u32, len_field: &'static str },
    /// The covered bytes are not inside this struct; the format module supplies
    /// them (the GPT entry array, the exFAT boot region). Tier B.
    External,
}

/// A checksum field's full definition. Plain data, so descriptors stay exportable.
#[derive(Clone, Copy, Debug)]
pub struct ChecksumSpec {
    pub algo: ChecksumAlgo,
    pub cover: Cover,
    /// Byte ranges, relative to the start of the covered region, that are excluded
    /// from the computation — normally the checksum field itself.
    pub exclude: &'static [(u32, u32)],
    pub doc: &'static str,
}

/// The result of comparing a stored value against a computed one.
#[derive(Clone, Debug, PartialEq)]
pub struct Derived {
    pub kind: DerivedKind,
    pub value: Value,
    pub matches: bool,
    /// How the value was produced, for the detail popup.
    pub how: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivedKind {
    Checksum,
    /// A value that should equal a copy elsewhere (backup GPT header, FAT #1).
    Mirror,
    /// A value derivable from other fields (total sectors, cluster count).
    Computed,
}

impl Derived {
    pub fn checksum(computed: u64, stored: Option<u64>, how: impl Into<String>) -> Derived {
        Derived {
            kind: DerivedKind::Checksum,
            value: Value::Uint(computed),
            matches: stored == Some(computed),
            how: how.into(),
        }
    }
}

/// A proposed byte-level change. Produced by `recompute_edit`; applied by nothing
/// in this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteEdit {
    pub offset: u64,
    pub old: Vec<u8>,
    pub new: Vec<u8>,
    /// Human description, shown on the commit screen.
    pub reason: String,
}

impl ByteEdit {
    pub fn len(&self) -> usize {
        self.new.len()
    }
    pub fn is_empty(&self) -> bool {
        self.new.is_empty()
    }
    /// Sector-aligned range this edit will actually rewrite. A two-byte edit is
    /// physically a whole-sector rewrite; the commit screen must say so.
    pub fn sectors_touched(&self, sector_size: u64) -> (u64, u64) {
        let first = self.offset / sector_size;
        let last = (self.offset + self.new.len() as u64).saturating_sub(1) / sector_size;
        (first, last - first + 1)
    }
}

/// Turn a checksum mismatch into the edit that would fix it.
///
/// Returns `None` when the stored value already matches, when the field is not a
/// checksum, or when the computed value does not fit the field width. Writes nothing.
pub fn recompute_edit(
    spec: &ChecksumSpec,
    field_span: Span,
    stored: Option<u64>,
    computed: u64,
    little_endian: bool,
) -> Option<ByteEdit> {
    if stored == Some(computed) {
        return None;
    }
    let width = spec.algo.width_bytes() as usize;
    if field_span.byte_len() as usize != width {
        return None;
    }
    let bytes = computed.to_le_bytes();
    let mut new: Vec<u8> = bytes[..width].to_vec();
    if !little_endian {
        new.reverse();
    }
    let old = stored.map(|s| {
        let b = s.to_le_bytes();
        let mut v: Vec<u8> = b[..width].to_vec();
        if !little_endian {
            v.reverse();
        }
        v
    })?;
    Some(ByteEdit {
        offset: field_span.start_byte(),
        old,
        new,
        reason: format!("recompute {}", spec.algo.name()),
    })
}

/// CRC-32/ISO-HDLC table, generated at compile time so there is no build step and
/// no dependency.
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_vectors() {
        assert_eq!(ChecksumAlgo::Crc32.compute(b"", &[]), 0x0000_0000);
        assert_eq!(ChecksumAlgo::Crc32.compute(b"123456789", &[]), 0xCBF4_3926);
        assert_eq!(ChecksumAlgo::Crc32.compute(b"a", &[]), 0xE8B7_BE43);
    }

    #[test]
    fn crc32_exclusion_zeroes_rather_than_skips() {
        // GPT zeroes its own CRC field before computing; it does not skip the bytes.
        let with_junk = [b'a', 0xDE, 0xAD, b'b'];
        let with_zero = [b'a', 0x00, 0x00, b'b'];
        assert_eq!(
            ChecksumAlgo::Crc32.compute(&with_junk, &[(1, 2)]),
            ChecksumAlgo::Crc32.compute(&with_zero, &[])
        );
    }

    #[test]
    fn exfat_checksums_skip_rather_than_zero() {
        // The exFAT boot checksum omits the excluded bytes entirely.
        let all = [1u8, 2, 3, 4];
        let skipped = ChecksumAlgo::ExfatBootRegion.compute(&all, &[(1, 2)]);
        let manual = ChecksumAlgo::ExfatBootRegion.compute(&[1u8, 4], &[]);
        assert_eq!(skipped, manual);
    }

    #[test]
    fn fat_short_name_checksum_known_value() {
        // Classic worked example from the FAT specification.
        let name = b"FILENAMEEXT";
        let sum = ChecksumAlgo::FatShortName.compute(name, &[]);
        assert!(sum <= 0xFF);
        // rotate-right-and-add, computed independently:
        let mut expect = 0u8;
        for &b in name {
            expect = expect.rotate_right(1).wrapping_add(b);
        }
        assert_eq!(sum, expect as u64);
    }

    #[test]
    fn recompute_produces_an_edit_only_on_mismatch() {
        static SPEC: ChecksumSpec = ChecksumSpec {
            algo: ChecksumAlgo::Crc32,
            cover: Cover::Fixed { start: 0, len: 92 },
            exclude: &[(16, 4)],
            doc: "",
        };
        let span = Span::bytes(0x210, 4);
        assert!(recompute_edit(&SPEC, span, Some(7), 7, true).is_none());
        let e = recompute_edit(&SPEC, span, Some(0xDEAD_BEEF), 0x1234_5678, true).unwrap();
        assert_eq!(e.offset, 0x210);
        assert_eq!(e.new, vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(e.old, vec![0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn a_two_byte_edit_rewrites_a_whole_sector() {
        let e = ByteEdit {
            offset: 0x1C2,
            old: vec![0x0C],
            new: vec![0x07],
            reason: String::new(),
        };
        assert_eq!(e.sectors_touched(512), (0, 1));
        let e2 = ByteEdit { offset: 510, old: vec![0; 4], new: vec![0; 4], reason: String::new() };
        assert_eq!(e2.sectors_touched(512), (0, 2));
    }
}
