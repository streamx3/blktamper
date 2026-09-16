//! Declarative record descriptions — Tier A of ADR-002.
//!
//! A `StructDesc` is plain `const` data: no closures, no function pointers. That is
//! what lets one generic reader turn any descriptor into a node tree, and what would
//! let a future exporter emit `.ksy`/`.hexpat`/JSON from the same tables.
//!
//! Anything that needs real computation is expressed as a *named* check or link and
//! dispatched by the owning format module. That is Tier B, and it is deliberately
//! not expressible here.

use crate::checksum::ChecksumSpec;
use crate::value::{FlagTable, Repr};

/// Storage width and byte order of a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    U8,
    U16le,
    U16be,
    U24le,
    U32le,
    U32be,
    U64le,
    U64be,
    I8,
    I16le,
    I32le,
    I64le,
    /// Opaque run of bytes.
    Bytes(u32),
    /// Fixed-length ASCII, space- or NUL-padded.
    Ascii(u32),
    /// Fixed byte length holding UTF-16LE code units.
    Utf16Le(u32),
    /// 16 bytes, mixed-endian GUID.
    Guid,
    /// 3-byte packed cylinder/head/sector.
    Chs,
}

impl Width {
    pub const fn size(self) -> u32 {
        match self {
            Width::U8 | Width::I8 => 1,
            Width::U16le | Width::U16be | Width::I16le => 2,
            Width::U24le => 3,
            Width::U32le | Width::U32be | Width::I32le => 4,
            Width::U64le | Width::U64be | Width::I64le => 8,
            Width::Bytes(n) | Width::Ascii(n) | Width::Utf16Le(n) => n,
            Width::Guid => 16,
            Width::Chs => 3,
        }
    }

    pub const fn is_scalar(self) -> bool {
        matches!(
            self,
            Width::U8
                | Width::U16le
                | Width::U16be
                | Width::U24le
                | Width::U32le
                | Width::U32be
                | Width::U64le
                | Width::U64be
                | Width::I8
                | Width::I16le
                | Width::I32le
                | Width::I64le
        )
    }
}

/// Semantic annotations that drive filtering and anomaly detection.
///
/// A small hand-rolled bitset rather than the `bitflags` crate: `blktamper-core`
/// keeps its dependency list to one entry (ADR-006).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldFlags(pub u16);

impl FieldFlags {
    pub const NONE: FieldFlags = FieldFlags(0);
    /// Documented as reserved. Non-zero content is a finding, not noise.
    pub const RESERVED: FieldFlags = FieldFlags(1 << 0);
    /// Specification says this must be zero.
    pub const MUST_ZERO: FieldFlags = FieldFlags(1 << 1);
    /// Derived from other fields (checksums, mirrored counts). Never silently
    /// recomputed; see `checksum::recompute`.
    pub const DERIVED: FieldFlags = FieldFlags(1 << 2);
    /// Present for backwards compatibility and meaningless in practice: legacy CHS
    /// on a large disk, the FAT `fs_type` string.
    pub const LEGACY: FieldFlags = FieldFlags(1 << 3);
    /// Opaque code or payload; do not try to interpret.
    pub const OPAQUE: FieldFlags = FieldFlags(1 << 4);
    /// Identifies a location: rendered with its resolved byte offset.
    pub const POINTER: FieldFlags = FieldFlags(1 << 5);
    /// Set by a format module for fields it knows are usually zero in practice,
    /// so "hide empty" can collapse them without them counting as anomalies.
    pub const OFTEN_ZERO: FieldFlags = FieldFlags(1 << 6);

    pub const fn or(self, other: FieldFlags) -> FieldFlags {
        FieldFlags(self.0 | other.0)
    }

    pub const fn has(self, other: FieldFlags) -> bool {
        self.0 & other.0 == other.0 && other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for FieldFlags {
    type Output = FieldFlags;
    fn bitor(self, rhs: FieldFlags) -> FieldFlags {
        FieldFlags(self.0 | rhs.0)
    }
}

impl core::fmt::Debug for FieldFlags {
    fn fmt(&self, fmtr: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (bit, name) in [
            (FieldFlags::RESERVED, "RESERVED"),
            (FieldFlags::MUST_ZERO, "MUST_ZERO"),
            (FieldFlags::DERIVED, "DERIVED"),
            (FieldFlags::LEGACY, "LEGACY"),
            (FieldFlags::OPAQUE, "OPAQUE"),
            (FieldFlags::POINTER, "POINTER"),
            (FieldFlags::OFTEN_ZERO, "OFTEN_ZERO"),
        ] {
            if self.has(bit) {
                if !first {
                    fmtr.write_str("|")?;
                }
                fmtr.write_str(name)?;
                first = false;
            }
        }
        if first {
            fmtr.write_str("NONE")?;
        }
        Ok(())
    }
}

/// A validity check attached to a field or a struct.
///
/// Variants that can be evaluated from the descriptor alone are evaluated by the
/// generic reader. `Cross` is a *named* invariant the format module resolves —
/// the explicit seam between Tier A and Tier B.
#[derive(Clone, Copy, Debug)]
pub enum Check {
    /// Must equal this unsigned value.
    Eq(u64),
    /// Must equal these bytes exactly (signatures).
    EqBytes(&'static [u8]),
    /// Must be one of these unsigned values.
    OneOf(&'static [u64]),
    /// Inclusive range.
    Range(u64, u64),
    /// Must be a power of two (sector sizes, cluster sizes).
    PowerOfTwo,
    NonZero,
    Zero,
    /// A named invariant evaluated by the owning format module.
    Cross(&'static str),
}

/// A followable reference from a field to somewhere else on the device.
#[derive(Clone, Copy, Debug)]
pub struct LinkDesc {
    /// Name of the field in this struct whose value is the target.
    pub from_field: &'static str,
    pub kind: LinkKind,
    pub label: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// Value is an absolute byte offset.
    ToByte,
    /// Value is an LBA, absolute on the device.
    ToLba,
    /// Value is an LBA relative to the containing region's base.
    ToLbaRelative,
    /// Value is a cluster number in the containing filesystem.
    ToCluster,
    /// Value is an LBA; probe there and offer whatever matches.
    ProbeAtLba,
    /// Value is a byte offset; probe there.
    ProbeAtByte,
    /// A fixed named sibling region (primary <-> backup).
    ToNamedRegion(&'static str),
}

impl LinkDesc {
    pub const fn new(from_field: &'static str, kind: LinkKind, label: &'static str) -> Self {
        LinkDesc { from_field, kind, label }
    }
    pub const fn probe_at_lba(from_field: &'static str, label: &'static str) -> Self {
        LinkDesc { from_field, kind: LinkKind::ProbeAtLba, label }
    }
}

/// One field of a fixed-layout record.
#[derive(Clone, Copy, Debug)]
pub struct FieldDesc {
    pub name: &'static str,
    /// Byte offset from the start of the struct.
    pub off: u32,
    pub width: Width,
    pub repr: Repr,
    pub doc: &'static str,
    pub flags: FieldFlags,
    pub checks: &'static [Check],
    /// Present when `repr` is `Repr::Checksum`.
    pub checksum: Option<&'static ChecksumSpec>,
    /// When set, the field is a bitfield and expands into one child per bit.
    pub sub_flags: Option<&'static FlagTable>,
}

impl FieldDesc {
    pub const fn end(&self) -> u32 {
        self.off + self.width.size()
    }
}

/// A fixed-layout record.
#[derive(Clone, Copy, Debug)]
pub struct StructDesc {
    pub name: &'static str,
    /// `None` for variable-size records whose length the format module computes.
    pub size: Option<u32>,
    pub fields: &'static [FieldDesc],
    pub checks: &'static [Check],
    pub links: &'static [LinkDesc],
    /// Where the layout came from, shown in the field detail popup.
    pub spec: &'static str,
}

impl StructDesc {
    pub fn field(&self, name: &str) -> Option<&'static FieldDesc> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Bytes claimed by no field, as `(offset, len)` pairs. These become `Gap` nodes.
    ///
    /// A gap is either a bug in our descriptor or something interesting on the disk.
    /// Both are worth showing, which is why they are modelled rather than ignored.
    pub fn gaps(&self) -> Vec<(u32, u32)> {
        let Some(size) = self.size else { return Vec::new() };
        let mut claimed: Vec<(u32, u32)> =
            self.fields.iter().map(|f| (f.off, f.end())).collect();
        claimed.sort_unstable();
        let mut gaps = Vec::new();
        let mut cursor = 0u32;
        for (start, end) in claimed {
            if start > cursor {
                gaps.push((cursor, start - cursor));
            }
            cursor = cursor.max(end);
        }
        if cursor < size {
            gaps.push((cursor, size - cursor));
        }
        gaps
    }

    /// Fields that overlap each other — always a descriptor bug.
    pub fn overlaps(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        for (i, a) in self.fields.iter().enumerate() {
            for b in &self.fields[i + 1..] {
                if a.off < b.end() && b.off < a.end() {
                    out.push((a.name, b.name));
                }
            }
        }
        out
    }

    /// Fields that run past the declared struct size — always a descriptor bug.
    pub fn out_of_bounds(&self) -> Vec<&'static str> {
        let Some(size) = self.size else { return Vec::new() };
        self.fields.iter().filter(|f| f.end() > size).map(|f| f.name).collect()
    }
}

/// Terse constructors for descriptor tables. Keeping these `const fn` is what makes
/// a field one readable line instead of eight.
pub const fn f(
    name: &'static str,
    off: u32,
    width: Width,
    repr: Repr,
    doc: &'static str,
) -> FieldDesc {
    FieldDesc {
        name,
        off,
        width,
        repr,
        doc,
        flags: FieldFlags::NONE,
        checks: &[],
        checksum: None,
        sub_flags: None,
    }
}

pub const fn fx(
    name: &'static str,
    off: u32,
    width: Width,
    repr: Repr,
    doc: &'static str,
    flags: FieldFlags,
    checks: &'static [Check],
) -> FieldDesc {
    FieldDesc { name, off, width, repr, doc, flags, checks, checksum: None, sub_flags: None }
}

pub const fn f_reserved(name: &'static str, off: u32, len: u32, doc: &'static str) -> FieldDesc {
    FieldDesc {
        name,
        off,
        width: Width::Bytes(len),
        repr: Repr::Raw,
        doc,
        flags: FieldFlags::RESERVED,
        checks: &[Check::Zero],
        checksum: None,
        sub_flags: None,
    }
}

pub const fn f_flags(
    name: &'static str,
    off: u32,
    width: Width,
    table: &'static FlagTable,
    doc: &'static str,
) -> FieldDesc {
    FieldDesc {
        name,
        off,
        width,
        repr: Repr::Flags(table),
        doc,
        flags: FieldFlags::NONE,
        checks: &[],
        checksum: None,
        sub_flags: Some(table),
    }
}

pub const fn f_checksum(
    name: &'static str,
    off: u32,
    width: Width,
    spec: &'static ChecksumSpec,
    doc: &'static str,
) -> FieldDesc {
    FieldDesc {
        name,
        off,
        width,
        repr: Repr::Checksum,
        doc,
        flags: FieldFlags::DERIVED,
        checks: &[],
        checksum: Some(spec),
        sub_flags: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Repr;

    static S: StructDesc = StructDesc {
        name: "t",
        size: Some(16),
        fields: &[
            f("a", 0, Width::U32le, Repr::Dec, ""),
            f("b", 8, Width::U32le, Repr::Dec, ""),
        ],
        checks: &[],
        links: &[],
        spec: "",
    };

    #[test]
    fn gaps_are_found() {
        assert_eq!(S.gaps(), vec![(4, 4), (12, 4)]);
    }

    #[test]
    fn overlaps_are_found() {
        static O: StructDesc = StructDesc {
            name: "o",
            size: Some(8),
            fields: &[
                f("a", 0, Width::U32le, Repr::Dec, ""),
                f("b", 2, Width::U32le, Repr::Dec, ""),
            ],
            checks: &[],
            links: &[],
            spec: "",
        };
        assert_eq!(O.overlaps(), vec![("a", "b")]);
    }

    #[test]
    fn out_of_bounds_is_found() {
        static B: StructDesc = StructDesc {
            name: "b",
            size: Some(4),
            fields: &[f("a", 2, Width::U32le, Repr::Dec, "")],
            checks: &[],
            links: &[],
            spec: "",
        };
        assert_eq!(B.out_of_bounds(), vec!["a"]);
    }

    #[test]
    fn widths_are_right() {
        assert_eq!(Width::U24le.size(), 3);
        assert_eq!(Width::Guid.size(), 16);
        assert_eq!(Width::Utf16Le(72).size(), 72);
        assert!(Width::U64be.is_scalar());
        assert!(!Width::Guid.is_scalar());
    }
}
