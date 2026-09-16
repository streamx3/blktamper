//! The generic struct reader — the engine shared by every format.
//!
//! Give it a `StructDesc` and the bytes, and it produces a complete node tree:
//! decoded values, bit expansion, gap detection, check evaluation, checksum
//! verification and resolved links. Every format module gets all of that by writing
//! a table (ADR-002), which is the entire reason for the table.
//!
//! It never fails. Short reads produce `Unreadable` fields; unreadable regions
//! produce an `Unreadable` struct. Both still render with full labels.

use crate::checksum::{ByteEdit, Cover, Derived};
use crate::desc::{Check, FieldDesc, FieldFlags, LinkDesc, LinkKind, StructDesc, Width};
use crate::node::{Diagnostic, Link, Node, NodeKind, Status};
use crate::source::ReadOutcome;
use crate::span::{Extent, Span};
use crate::value::{RenderCtx, Repr, Value};
use std::collections::HashMap;

/// Everything the reader needs that is not in the descriptor.
#[derive(Clone, Copy, Debug)]
pub struct ReadCtx {
    /// Absolute byte offset of the struct on the device.
    pub base: u64,
    /// Base the struct's relative LBA links are measured from (a partition start).
    pub region_base: u64,
    pub render: RenderCtx,
}

impl ReadCtx {
    pub fn at(base: u64) -> ReadCtx {
        ReadCtx { base, region_base: 0, render: RenderCtx::default() }
    }
    pub fn with_render(mut self, r: RenderCtx) -> ReadCtx {
        self.render = r;
        self
    }
    pub fn with_region_base(mut self, b: u64) -> ReadCtx {
        self.region_base = b;
        self
    }
}

/// Decode a scalar or byte field. Short input yields `Value::Unset` rather than a
/// value assembled from bytes that were never read.
pub fn decode(width: Width, bytes: &[u8]) -> Value {
    let need = width.size() as usize;
    if bytes.len() < need {
        return Value::Unset;
    }
    let b = &bytes[..need];
    let le = |b: &[u8]| -> u64 {
        let mut v = 0u64;
        for (i, &x) in b.iter().enumerate() {
            v |= (x as u64) << (8 * i);
        }
        v
    };
    let be = |b: &[u8]| -> u64 {
        let mut v = 0u64;
        for &x in b.iter() {
            v = (v << 8) | x as u64;
        }
        v
    };
    match width {
        Width::U8 => Value::Uint(b[0] as u64),
        Width::U16le | Width::U24le | Width::U32le | Width::U64le => Value::Uint(le(b)),
        Width::U16be | Width::U32be | Width::U64be => Value::Uint(be(b)),
        Width::I8 => Value::Int(b[0] as i8 as i64),
        Width::I16le => Value::Int(i16::from_le_bytes([b[0], b[1]]) as i64),
        Width::I32le => Value::Int(i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64),
        Width::I64le => Value::Int(i64::from_le_bytes(b.try_into().unwrap())),
        Width::Bytes(_) => Value::Bytes(b.to_vec()),
        Width::Ascii(_) => Value::Text(crate::value::ascii_lossy(b, true)),
        Width::Utf16Le(_) => Value::Text(crate::value::utf16le_lossy(b, true)),
        Width::Guid => Value::Guid(b.try_into().unwrap()),
        Width::Chs => {
            // head | sector(6 bits) + cylinder high 2 bits | cylinder low 8 bits
            let head = b[0];
            let sector = b[1] & 0x3F;
            let cylinder = (((b[1] & 0xC0) as u16) << 2) | b[2] as u16;
            Value::Chs { head, sector, cylinder }
        }
    }
}

/// Evaluate a descriptor-level check. `Check::Cross` is never evaluated here — it is
/// a named invariant the owning format module resolves (the Tier A/B seam).
fn eval_check(check: &Check, value: &Value, raw: &[u8]) -> Option<Diagnostic> {
    match check {
        Check::Eq(want) => match value.as_u64() {
            Some(v) if v == *want => None,
            Some(v) => Some(Diagnostic::bad(format!("expected {want:#x}, found {v:#x}"))),
            None => None,
        },
        Check::EqBytes(want) => {
            if raw.len() < want.len() {
                Some(Diagnostic::bad(format!("truncated: need {} bytes", want.len())))
            } else if &raw[..want.len()] == *want {
                None
            } else {
                Some(Diagnostic::bad(format!(
                    "expected {}, found {}",
                    crate::value::hex_bytes(want),
                    crate::value::hex_bytes(&raw[..want.len()])
                )))
            }
        }
        Check::OneOf(allowed) => match value.as_u64() {
            Some(v) if allowed.contains(&v) => None,
            Some(v) => Some(Diagnostic::warn(format!("{v:#x} is not a documented value"))),
            None => None,
        },
        Check::Range(lo, hi) => match value.as_u64() {
            Some(v) if v >= *lo && v <= *hi => None,
            Some(v) => Some(Diagnostic::warn(format!("{v} is outside {lo}..={hi}"))),
            None => None,
        },
        Check::PowerOfTwo => match value.as_u64() {
            Some(v) if v != 0 && v.is_power_of_two() => None,
            Some(v) => Some(Diagnostic::bad(format!("{v} is not a power of two"))),
            None => None,
        },
        Check::NonZero => match value.as_u64() {
            Some(0) => Some(Diagnostic::warn("zero")),
            _ => None,
        },
        Check::Zero => {
            if raw.iter().all(|&b| b == 0) {
                None
            } else {
                Some(Diagnostic::warn("reserved field is not zero").with_hint(
                    "could be an extension, a different implementation, or leftover data",
                ))
            }
        }
        Check::Cross(_) => None,
    }
}

/// Build the bit children of a bitfield.
fn bit_children(fd: &FieldDesc, base: u64, value: &Value) -> Vec<Node> {
    let Some(table) = fd.sub_flags else { return Vec::new() };
    let Some(v) = value.as_u64() else { return Vec::new() };
    let field_base = base.saturating_add(fd.off as u64);
    table
        .bits
        .iter()
        .map(|fb| {
            let set = (v >> fb.bit) & 1 == 1;
            let byte = field_base.saturating_add((fb.bit / 8) as u64);
            let mut n = Node {
                label: format!("{}.{}", fb.bit, fb.label).into(),
                extent: Extent::One(Span::flag_bit(byte, fb.bit % 8)),
                kind: NodeKind::Bit,
                value: Value::Bool(set),
                repr: Repr::Dec,
                doc: Some(fb.doc),
                raw: vec![set as u8],
                flags: if fb.reserved { FieldFlags::RESERVED } else { FieldFlags::NONE },
                ..Default::default()
            };
            if fb.reserved && set {
                n = n.with_diag(Diagnostic::warn("reserved bit is set"));
            }
            n
        })
        .collect()
}

fn resolve_link(ld: &LinkDesc, raw_value: u64, ctx: &ReadCtx) -> Link {
    let ss = ctx.render.sector_size as u64;
    let resolved = match ld.kind {
        LinkKind::ToByte | LinkKind::ProbeAtByte => Some(raw_value),
        LinkKind::ToLba | LinkKind::ProbeAtLba => raw_value.checked_mul(ss),
        LinkKind::ToLbaRelative => raw_value.checked_mul(ss).and_then(|b| b.checked_add(ctx.region_base)),
        LinkKind::ToCluster => ctx.render.cluster_to_byte(raw_value),
        LinkKind::ToNamedRegion(_) => None,
    };
    Link { label: ld.label.to_string(), kind: ld.kind, raw: raw_value, resolved }
}

/// Read one struct into a node.
///
/// Offset arithmetic here saturates rather than wrapping. `ctx.base` comes from a
/// value read off the disk (a partition's start LBA, a cluster number), so it is
/// attacker-controlled; with `overflow-checks = true` in the release profile a plain
/// `+` is a panic, and a panic in the parser breaks the one invariant this crate has
/// (R-3.7). Found independently by two reviewers, which is how it should be.
///
/// `bytes` is whatever could be read at `ctx.base`; it may be short or empty.
/// `outcome` says why.
pub fn read_struct(
    desc: &'static StructDesc,
    bytes: &[u8],
    outcome: ReadOutcome,
    ctx: ReadCtx,
) -> Node {
    let size = desc.size.unwrap_or(bytes.len() as u32);
    let span = Span::bytes(ctx.base, size as u64);

    let mut root = Node {
        label: desc.name.into(),
        extent: Extent::One(span),
        kind: NodeKind::Struct,
        value: Value::Composite,
        repr: Repr::Raw,
        raw: bytes.to_vec(),
        ..Default::default()
    };

    if outcome == ReadOutcome::Unreadable {
        return root
            .with_status(Status::Unreadable)
            .with_diag(Diagnostic {
                status: Status::Unreadable,
                message: format!("could not read {} bytes at {:#x}", size, ctx.base),
                hint: Some("the device returned an I/O error; this is not zeroed data".into()),
            });
    }

    // Pass 1: decode scalars so checksum covers and cross-checks can reference them.
    let mut scalars: HashMap<&'static str, u64> = HashMap::new();
    for fd in desc.fields {
        let s = fd.off as usize;
        let e = fd.end() as usize;
        if e <= bytes.len() {
            if let Some(v) = decode(fd.width, &bytes[s..e]).as_u64() {
                scalars.insert(fd.name, v);
            }
        }
    }

    // Pass 2: build a node per field.
    let mut kids: Vec<Node> = Vec::with_capacity(desc.fields.len() + 2);
    for fd in desc.fields {
        kids.push(read_field(fd, desc, bytes, &scalars, &ctx));
    }

    // Gaps: bytes in range that no field claimed.
    for (off, len) in desc.gaps() {
        let s = off as usize;
        let e = (off + len) as usize;
        let raw = if e <= bytes.len() { bytes[s..e].to_vec() } else { Vec::new() };
        let nonzero = !raw.is_empty() && !raw.iter().all(|&b| b == 0);
        let mut n = Node {
            label: format!("(unclaimed {off:#x}..{:#x})", off + len).into(),
            extent: Extent::bytes(ctx.base.saturating_add(off as u64), len as u64),
            kind: NodeKind::Gap,
            value: Value::Bytes(raw.clone()),
            repr: Repr::Raw,
            raw,
            doc: Some("bytes no field in this descriptor claims"),
            ..Default::default()
        };
        if nonzero {
            n = n.with_diag(Diagnostic::info("unclaimed bytes are not zero").with_hint(
                "either the descriptor is incomplete or there is undocumented data here",
            ));
        }
        kids.push(n);
    }
    kids.sort_by_key(|n| n.extent.min_byte().unwrap_or(u64::MAX));

    if let ReadOutcome::Short { filled } = outcome {
        root = root.with_diag(
            Diagnostic::warn(format!("only {filled} of {size} bytes were readable"))
                .with_hint("the structure runs past the end of the device or image"),
        );
    }

    let deep = kids.iter().fold(Status::Ok, |acc, k| acc.merge(k.deep_status()));
    root.status = root.status.merge(deep.min(Status::Warn).max(root.status));
    root.with_children(kids)
}

fn read_field(
    fd: &'static FieldDesc,
    desc: &'static StructDesc,
    bytes: &[u8],
    scalars: &HashMap<&'static str, u64>,
    ctx: &ReadCtx,
) -> Node {
    let s = fd.off as usize;
    let e = fd.end() as usize;
    let span = Span::bytes(ctx.base.saturating_add(fd.off as u64), fd.width.size() as u64);

    let (raw, value, short) = if e <= bytes.len() {
        let raw = bytes[s..e].to_vec();
        let v = decode(fd.width, &raw);
        (raw, v, false)
    } else if s < bytes.len() {
        (bytes[s..].to_vec(), Value::Unset, true)
    } else {
        (Vec::new(), Value::Unset, true)
    };

    let mut n = Node {
        label: fd.name.into(),
        extent: Extent::One(span),
        kind: NodeKind::Field,
        value: value.clone(),
        repr: fd.repr,
        flags: fd.flags,
        doc: Some(fd.doc),
        raw: raw.clone(),
        ..Default::default()
    };

    if short {
        n = n.with_diag(Diagnostic::warn("field extends past the readable range"));
    } else {
        for c in fd.checks {
            if let Some(d) = eval_check(c, &value, &raw) {
                n = n.with_diag(d);
            }
        }
    }

    // Bitfield expansion.
    if fd.sub_flags.is_some() {
        let bits = bit_children(fd, ctx.base, &value);
        if !bits.is_empty() {
            let deep = bits.iter().fold(Status::Ok, |a, b| a.merge(b.status));
            n.status = n.status.merge(deep);
            n = n.with_children(bits);
        }
    }

    // Checksum verification.
    if let Some(spec) = fd.checksum {
        let covered: Option<&[u8]> = match spec.cover {
            Cover::Fixed { start, len } => {
                let (a, b) = (start as usize, (start + len) as usize);
                bytes.get(a..b.min(bytes.len()))
            }
            Cover::FieldLen { start, len_field } => {
                let len = scalars.get(len_field).copied().unwrap_or(0) as usize;
                let a = start as usize;
                let b = a.saturating_add(len);
                if len == 0 {
                    None
                } else {
                    bytes.get(a..b.min(bytes.len()))
                }
            }
            // Supplied by the format module; it attaches `derived` itself.
            Cover::External => None,
        };
        if let Some(data) = covered {
            let computed = spec.algo.compute(data, spec.exclude);
            let stored = value.as_u64();
            let matches = stored == Some(computed);
            n.derived = Some(Derived {
                kind: crate::checksum::DerivedKind::Checksum,
                value: Value::Uint(computed),
                matches,
                how: format!("{} over {} bytes", spec.algo.name(), data.len()),
            });
            if !matches {
                n = n.with_diag(
                    Diagnostic::bad(format!(
                        "stored {:#010X}, computed {:#010X}",
                        stored.unwrap_or(0),
                        computed
                    ))
                    .with_hint("the structure has been modified without updating this checksum"),
                );
            }
        }
    }

    // Links.
    for ld in desc.links.iter().filter(|l| l.from_field == fd.name) {
        if let Some(v) = value.as_u64() {
            n = n.with_link(resolve_link(ld, v, ctx));
            n.flags = n.flags.or(FieldFlags::POINTER);
        }
    }

    n
}

/// The proposed edit that would make a node's stored checksum match its computed
/// one. Returns `None` when there is nothing to fix. Writes nothing (R-7.7).
pub fn recompute_edit_for(node: &Node, fd: &FieldDesc) -> Option<ByteEdit> {
    let spec = fd.checksum?;
    let derived = node.derived.as_ref()?;
    if derived.matches {
        return None;
    }
    let span = node.extent.first()?;
    let little_endian = !matches!(fd.width, Width::U16be | Width::U32be | Width::U64be);
    crate::checksum::recompute_edit(
        spec,
        span,
        node.value.as_u64(),
        derived.value.as_u64()?,
        little_endian,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desc::{f, f_reserved, fx, Width};
    use crate::value::Repr;

    static T: StructDesc = StructDesc {
        name: "t",
        size: Some(12),
        fields: &[
            fx("sig", 0, Width::Bytes(4), Repr::Ascii, "", FieldFlags::NONE, &[Check::EqBytes(b"MAGI")]),
            f("num", 4, Width::U32le, Repr::Dec, ""),
            f_reserved("rsvd", 8, 4, ""),
        ],
        checks: &[],
        links: &[LinkDesc::new("num", LinkKind::ToLba, "target")],
        spec: "",
    };

    fn body(sig: &[u8; 4], num: u32, rsvd: [u8; 4]) -> Vec<u8> {
        let mut v = sig.to_vec();
        v.extend_from_slice(&num.to_le_bytes());
        v.extend_from_slice(&rsvd);
        v
    }

    #[test]
    fn a_good_struct_is_clean() {
        let n = read_struct(&T, &body(b"MAGI", 2048, [0; 4]), ReadOutcome::Ok, ReadCtx::at(0));
        assert_eq!(n.deep_status(), Status::Ok);
        assert_eq!(n.find_child("num").unwrap().value, Value::Uint(2048));
    }

    #[test]
    fn a_bad_signature_still_renders_every_field() {
        let n = read_struct(&T, &body(b"XXXX", 7, [0; 4]), ReadOutcome::Ok, ReadCtx::at(0));
        assert_eq!(n.deep_status(), Status::Bad);
        // the point: nothing was refused
        assert_eq!(n.children.resolved().unwrap().len(), 3);
        assert_eq!(n.find_child("num").unwrap().value, Value::Uint(7));
    }

    #[test]
    fn garbage_never_panics_and_always_produces_a_full_tree() {
        for seed in 0u8..=255 {
            let data = vec![seed; 12];
            let n = read_struct(&T, &data, ReadOutcome::Ok, ReadCtx::at(0));
            assert_eq!(n.children.resolved().unwrap().len(), 3);
        }
    }

    #[test]
    fn truncated_input_marks_fields_not_the_whole_struct() {
        let n = read_struct(&T, b"MAGI\x01", ReadOutcome::Short { filled: 5 }, ReadCtx::at(0));
        assert_eq!(n.find_child("sig").unwrap().status, Status::Ok);
        assert_eq!(n.find_child("num").unwrap().value, Value::Unset);
        assert!(n.find_child("num").unwrap().status.is_anomaly());
    }

    #[test]
    fn unreadable_is_not_zeros() {
        let n = read_struct(&T, &[], ReadOutcome::Unreadable, ReadCtx::at(0));
        assert_eq!(n.status, Status::Unreadable);
        assert!(n.children.is_none());
    }

    #[test]
    fn nonzero_reserved_is_flagged() {
        let n = read_struct(&T, &body(b"MAGI", 1, [0, 0, 9, 0]), ReadOutcome::Ok, ReadCtx::at(0));
        let r = n.find_child("rsvd").unwrap();
        assert!(r.is_anomaly());
    }

    #[test]
    fn links_resolve_lba_to_bytes() {
        let n = read_struct(&T, &body(b"MAGI", 2048, [0; 4]), ReadOutcome::Ok, ReadCtx::at(0));
        let l = &n.find_child("num").unwrap().links[0];
        assert_eq!(l.raw, 2048);
        assert_eq!(l.resolved, Some(2048 * 512));
    }

    #[test]
    fn gaps_are_emitted_and_ordered() {
        static G: StructDesc = StructDesc {
            name: "g",
            size: Some(8),
            fields: &[f("a", 0, Width::U16le, Repr::Dec, "")],
            checks: &[],
            links: &[],
            spec: "",
        };
        let n = read_struct(&G, &[1, 0, 0, 0, 0, 0, 0, 0], ReadOutcome::Ok, ReadCtx::at(0));
        let kids = n.children.resolved().unwrap();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].label, "a");
        assert_eq!(kids[1].kind, NodeKind::Gap);
        assert_eq!(kids[1].extent.len_bytes(), 6);
    }

    #[test]
    fn a_base_near_the_end_of_the_address_space_saturates_rather_than_panicking() {
        // A corrupt table can claim a partition starts at an absurd LBA. The tree
        // must still render; nonsense offsets are a finding, not a crash.
        let n = read_struct(
            &T,
            &body(b"MAGI", 1, [0; 4]),
            ReadOutcome::Ok,
            ReadCtx::at(u64::MAX - 2),
        );
        assert_eq!(n.children.resolved().unwrap().len(), 3);
        for k in n.children.resolved().unwrap() {
            assert!(k.extent.first().is_some());
        }
    }

    #[test]
    fn a_bitfield_at_an_absurd_base_saturates_too() {
        static FT: crate::value::FlagTable = crate::value::FlagTable {
            name: "f",
            bits: &[crate::value::FlagBit::new(0, "a", ""), crate::value::FlagBit::new(63, "b", "")],
        };
        static B: StructDesc = StructDesc {
            name: "b",
            size: Some(8),
            fields: &[crate::desc::f_flags("flags", 0, Width::U64le, &FT, "x")],
            checks: &[],
            links: &[],
            spec: "test",
        };
        let n = read_struct(&B, &[0xFF; 8], ReadOutcome::Ok, ReadCtx::at(u64::MAX - 1));
        let flags = n.find_child("flags").unwrap();
        assert_eq!(flags.children.resolved().unwrap().len(), 2);
    }

    #[test]
    fn chs_unpacks_the_six_and_ten_bit_split() {
        // head=254, sector=63, cylinder=1023 -> FE FF FF
        let v = decode(Width::Chs, &[0xFE, 0xFF, 0xFF]);
        assert_eq!(v, Value::Chs { head: 254, sector: 63, cylinder: 1023 });
    }

    #[test]
    fn big_endian_widths_decode_the_other_way() {
        assert_eq!(decode(Width::U32be, &[0, 0, 1, 0]), Value::Uint(256));
        assert_eq!(decode(Width::U32le, &[0, 0, 1, 0]), Value::Uint(65536));
        assert_eq!(decode(Width::U24le, &[0x01, 0x02, 0x03]), Value::Uint(0x030201));
    }
}
