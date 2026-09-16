//! # blktamper-formats
//!
//! On-disk format knowledge. Every module is two halves:
//!
//! * **`desc.rs`** — record layouts as `const` data. One line per field, and that
//!   one line is simultaneously the parser, the renderer, the filter, the copy
//!   format and the tooltip.
//! * **`mod.rs`** — traversal: chains, arrays, cross-record invariants. Ordinary
//!   Rust, because a description language that needs loops and arithmetic is a
//!   programming language wearing a hat (ADR-002).
//!
//! Nothing here knows about files or terminals — only `blktamper_core::BlockSource`.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod common;

#[cfg(feature = "mbr")]
pub mod mbr;
#[cfg(feature = "gpt")]
pub mod gpt;
#[cfg(feature = "fat")]
pub mod fat;
#[cfg(feature = "exfat")]
pub mod exfat;

use blktamper_core::Registry;

/// A registry with every format this build enabled.
pub fn registry() -> Registry {
    let mut r = Registry::new();
    #[cfg(feature = "mbr")]
    mbr::register(&mut r);
    #[cfg(feature = "gpt")]
    gpt::register(&mut r);
    #[cfg(feature = "fat")]
    fat::register(&mut r);
    #[cfg(feature = "exfat")]
    exfat::register(&mut r);
    r
}

/// Every descriptor in this build, for the validation test that asserts each one
/// tiles its record exactly (doc/06-format-scope.md).
pub fn all_descriptors() -> Vec<&'static blktamper_core::StructDesc> {
    let mut v: Vec<&'static blktamper_core::StructDesc> = Vec::new();
    #[cfg(feature = "mbr")]
    v.extend_from_slice(mbr::desc::ALL);
    #[cfg(feature = "gpt")]
    v.extend_from_slice(gpt::desc::ALL);
    #[cfg(feature = "fat")]
    v.extend_from_slice(fat::desc::ALL);
    #[cfg(feature = "exfat")]
    v.extend_from_slice(exfat::desc::ALL);
    v
}
