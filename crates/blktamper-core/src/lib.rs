//! # blktamper-core
//!
//! The provenance-first model for on-disk structures.
//!
//! Two invariants define this crate, and everything else follows from them:
//!
//! 1. **Parsing never fails.** There is no `Result` on the read path. Garbage
//!    produces a fully-labelled tree with diagnostics attached, because a viewer
//!    that refuses bad input goes blank exactly when you need it.
//! 2. **Every node knows its bytes.** Absolute offset, bit offset, bit length, and
//!    a list of extents when the data is not contiguous. The hex highlight, the
//!    editor, copy-with-offset and the "hide empty" filter are all downstream of
//!    this one property.
//!
//! Nothing here knows about terminals, colours, files, or operating systems.
//!
//! See `doc/04-architecture.md` for the design and `doc/03-decisions.md` for why.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod checksum;
pub mod desc;
pub mod node;
pub mod path;
pub mod reader;
pub mod registry;
pub mod render;
pub mod scrub;
pub mod source;
pub mod span;
pub mod value;

pub use checksum::{ByteEdit, ChecksumAlgo, ChecksumSpec, Cover, Derived, DerivedKind};
pub use desc::{f, f_checksum, f_flags, f_reserved, fx, Check, FieldDesc, FieldFlags, LinkDesc, LinkKind, StructDesc, Width};
pub use node::{Children, Diagnostic, Expander, Link, Node, NodeKind, Status};
pub use path::{NodePath, Seg};
pub use reader::{decode, read_struct, ReadCtx};
pub use registry::{FormatId, FormatProbe, RegionReader, Registry, Score};
pub use scrub::{Fill, RecordClass, RecordShape, ScrubMode, ScrubPlan, ZeroRefusal};
pub use source::{BlockSink, BlockSource, MemSource, ReadOutcome, WriteError};
pub use span::{Extent, Span};
pub use value::{EnumEntry, EnumTable, FlagBit, FlagTable, RenderCtx, Repr, Value};

/// Errors that escape the library. Deliberately few: the read path does not produce
/// them at all.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("no format registered with id {0}")]
    UnknownFormat(String),
    #[error("value {value} does not fit a {width}-byte field")]
    ValueTooWide { value: u64, width: u32 },
    #[error("cannot encode {0} into this field")]
    Unencodable(&'static str),
}

/// Descriptor self-checks. Run over every table in the workspace by an integration
/// test: a mistyped offset or width shows up as a failing assertion the moment it
/// is added, which is worth more than proofreading (see doc/06-format-scope.md).
pub fn validate_desc(d: &'static StructDesc) -> Vec<String> {
    let mut errs = Vec::new();
    for (a, b) in d.overlaps() {
        errs.push(format!("{}: fields {a} and {b} overlap", d.name));
    }
    for f in d.out_of_bounds() {
        errs.push(format!("{}: field {f} runs past the declared size", d.name));
    }
    if let Some(size) = d.size {
        let covered: u32 = d.fields.iter().map(|f| f.width.size()).sum();
        let gap_bytes: u32 = d.gaps().iter().map(|(_, l)| l).sum();
        if covered + gap_bytes != size {
            errs.push(format!(
                "{}: fields cover {covered} + {gap_bytes} gap bytes, but size is {size}",
                d.name
            ));
        }
    }
    let mut names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
    names.sort_unstable();
    for w in names.windows(2) {
        if w[0] == w[1] {
            errs.push(format!("{}: duplicate field name {}", d.name, w[0]));
        }
    }
    for l in d.links {
        if d.field(l.from_field).is_none() {
            errs.push(format!("{}: link references unknown field {}", d.name, l.from_field));
        }
    }
    errs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Repr;

    #[test]
    fn validate_catches_a_mistyped_width() {
        static BAD: StructDesc = StructDesc {
            name: "bad",
            size: Some(16),
            // "b" should be U32le; typed as U64le it overlaps nothing but overruns.
            fields: &[f("a", 0, Width::U32le, Repr::Dec, ""), f("b", 12, Width::U64le, Repr::Dec, "")],
            checks: &[],
            links: &[],
            spec: "",
        };
        let errs = validate_desc(&BAD);
        assert!(errs.iter().any(|e| e.contains("runs past the declared size")), "{errs:?}");
    }

    #[test]
    fn validate_catches_a_bad_link_target() {
        static BAD: StructDesc = StructDesc {
            name: "bad",
            size: Some(4),
            fields: &[f("a", 0, Width::U32le, Repr::Dec, "")],
            checks: &[],
            links: &[LinkDesc::probe_at_lba("nope", "x")],
            spec: "",
        };
        assert!(validate_desc(&BAD).iter().any(|e| e.contains("unknown field")));
    }

    #[test]
    fn a_well_formed_descriptor_is_clean() {
        static OK: StructDesc = StructDesc {
            name: "ok",
            size: Some(8),
            fields: &[f("a", 0, Width::U32le, Repr::Dec, ""), f("b", 4, Width::U32le, Repr::Dec, "")],
            checks: &[],
            links: &[],
            spec: "",
        };
        assert!(validate_desc(&OK).is_empty());
    }
}
