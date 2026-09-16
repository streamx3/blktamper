//! # blktamper-io
//!
//! The only crate that knows about operating systems.
//!
//! Format modules see nothing but `blktamper_core::BlockSource`; swapping
//! `/dev/sdc` for an `.img` or a `Vec<u8>` is invisible to them. That is what makes
//! the parsers unit-testable and fuzzable without root, and what keeps a future
//! FreeBSD port confined to one directory (R-1.2).

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod cache;
pub mod file;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod journal;
pub mod open;
pub mod overlay;

pub use cache::CachedSource;
pub use file::{FileSink, FileSource};
pub use journal::{Journal, JournalError};
pub use open::{open_path, Access, DeviceInfo, OpenError};
pub use overlay::{Overlay, StageError, Staged};

/// What kind of thing we are looking at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// A whole block device: `/dev/sdc`.
    BlockDevice,
    /// A partition on a block device: `/dev/sdc1`.
    Partition,
    /// A regular file: a disk image.
    Image,
}

impl SourceKind {
    pub fn label(self) -> &'static str {
        match self {
            SourceKind::BlockDevice => "block device",
            SourceKind::Partition => "partition",
            SourceKind::Image => "image",
        }
    }
}
