//! exFAT constant tables: directory entry types, volume flags, file attributes.
//!
//! This is the layer no public format description carries and the layer that makes
//! a viewer worth using (ADR-002). Values are from Microsoft's exFAT File System
//! Specification revision 1.00, section 6 (directory entries) and section 3 (the
//! boot sector), cross-checked against ImHex's `exFAT.hexpat` and libyal's
//! `libfsfat` documentation.

use blktamper_core::{EnumEntry, EnumTable, FlagBit, FlagTable};

// ---------------------------------------------------------------- entry types

/// Bit 7 of the entry type byte. Spec §6.2.1.4: `InUse`.
///
/// Clearing it is the *entire* delete operation in exFAT — the other 31 bytes of
/// the record are left alone. That is why a deleted entry set still holds a
/// readable filename, and why this module shows them.
pub const IN_USE: u8 = 0x80;

pub const ALLOCATION_BITMAP: u8 = 0x81;
pub const UPCASE_TABLE: u8 = 0x82;
pub const VOLUME_LABEL: u8 = 0x83;
pub const FILE: u8 = 0x85;
pub const VOLUME_GUID: u8 = 0xA0;
pub const TEXFAT_PADDING: u8 = 0xA1;
pub const WINCE_ACL: u8 = 0xA2;
pub const STREAM_EXTENSION: u8 = 0xC0;
pub const FILE_NAME: u8 = 0xC1;
pub const VENDOR_EXTENSION: u8 = 0xC2;
pub const VENDOR_ALLOCATION: u8 = 0xC3;
/// Spec §6.2.1: a zero entry type ends the directory. Everything at or after it is
/// unallocated — which is exactly where deleted records survive longest.
pub const END_OF_DIRECTORY: u8 = 0x00;

/// True when the record is live. Everything else in this module still parses.
pub const fn is_in_use(t: u8) -> bool {
    t & IN_USE != 0
}

/// The type this entry had before someone cleared `InUse`. Meaningless for 0x00.
pub const fn undeleted(t: u8) -> u8 {
    t | IN_USE
}

/// Spec §6.2.1.3: bit 6 tells a primary entry (0) from a secondary one (1).
pub const fn is_secondary(t: u8) -> bool {
    undeleted(t) & 0x40 != 0
}

/// Spec §6.2.1.2: bit 5 clear means the implementation may not mount a volume it
/// does not understand this entry on; set means it may safely ignore it.
pub const fn is_benign(t: u8) -> bool {
    undeleted(t) & 0x20 != 0
}

/// Every entry type this module knows, live and deleted.
///
/// The deleted spellings are listed explicitly rather than derived, because a
/// viewer that renders `0x05` as "unknown" when it is a deleted file record is
/// hiding the one thing the user opened it to see.
pub static ENTRY_TYPES: EnumTable = EnumTable {
    name: "exFAT directory entry type",
    entries: &[
        EnumEntry::num(0x00, "end of directory", "No further entries are allocated in this directory."),
        EnumEntry::num(0x01, "deleted allocation bitmap", "0x81 with InUse cleared."),
        EnumEntry::num(0x02, "deleted up-case table", "0x82 with InUse cleared."),
        EnumEntry::num(0x03, "deleted volume label", "0x83 with InUse cleared."),
        EnumEntry::num(0x05, "deleted file", "0x85 with InUse cleared: a deleted file or directory record."),
        EnumEntry::num(0x20, "deleted volume GUID", "0xA0 with InUse cleared."),
        EnumEntry::num(0x40, "deleted stream extension", "0xC0 with InUse cleared."),
        EnumEntry::num(0x41, "deleted file name", "0xC1 with InUse cleared: still holds the UTF-16 filename."),
        EnumEntry::num(0x81, "allocation bitmap", "Critical primary: locates the cluster allocation bitmap."),
        EnumEntry::num(0x82, "up-case table", "Critical primary: locates the file-name up-case table."),
        EnumEntry::num(0x83, "volume label", "Critical primary: the volume label, up to 11 UTF-16 units."),
        EnumEntry::num(0x85, "file", "Critical primary: a file or directory, first entry of an entry set."),
        EnumEntry::num(0xA0, "volume GUID", "Benign primary: a GUID identifying the volume."),
        EnumEntry::num(0xA1, "TexFAT padding", "Benign primary, TexFAT only."),
        EnumEntry::num(0xA2, "Windows CE access control", "Benign primary, Windows CE only."),
        EnumEntry::num(0xC0, "stream extension", "Critical secondary: length, first cluster and name hash."),
        EnumEntry::num(0xC1, "file name", "Critical secondary: 15 UTF-16 units of the filename."),
        EnumEntry::num(0xC2, "vendor extension", "Benign secondary, vendor defined."),
        EnumEntry::num(0xC3, "vendor allocation", "Benign secondary, vendor defined."),
    ],
};

/// A label for any entry type byte, including ones the table does not list.
pub fn entry_type_label(t: u8) -> &'static str {
    ENTRY_TYPES
        .lookup(&blktamper_core::Value::Uint(t as u64))
        .map(|e| e.label)
        .unwrap_or("unknown entry type")
}

// ---------------------------------------------------------------------- flags

/// Spec §3.1.13 `VolumeFlags`.
///
/// Bits 4..15 are reserved; they are checked in `mod.rs` rather than listed here,
/// because twelve rows of "reserved: no" would bury the four that matter.
pub static VOLUME_FLAGS: FlagTable = FlagTable {
    name: "exFAT volume flags",
    bits: &[
        FlagBit::new(
            0,
            "ActiveFat",
            "Which FAT and allocation bitmap are active. 0 = the first; 1 = the \
             second, which only exists on a TexFAT volume with NumberOfFats = 2.",
        ),
        FlagBit::new(
            1,
            "VolumeDirty",
            "The volume was mounted for write and not cleanly unmounted, so the \
             metadata may be inconsistent. Set while mounted; cleared on a clean \
             unmount.",
        ),
        FlagBit::new(
            2,
            "MediaFailure",
            "The implementation has seen an unrecoverable media error and the \
             affected clusters are marked bad in the FAT.",
        ),
        FlagBit::new(
            3,
            "ClearToZero",
            "Advisory: an implementation should clear this bit before modifying any \
             other metadata. Its value carries no meaning on its own.",
        ),
    ],
};

/// Spec §7.4.4 `FileAttributes` — the same bit layout FAT has used since DOS.
pub static FILE_ATTRIBUTES: FlagTable = FlagTable {
    name: "exFAT file attributes",
    bits: &[
        FlagBit::new(0, "ReadOnly", "The file may not be modified."),
        FlagBit::new(1, "Hidden", "Conventionally omitted from directory listings."),
        FlagBit::new(2, "System", "Belongs to the operating system."),
        FlagBit::reserved(3, "Reserved1. Holds FAT's volume-label bit, which exFAT does not use."),
        FlagBit::new(
            4,
            "Directory",
            "The entry set describes a directory: its clusters hold further entry \
             sets rather than file data.",
        ),
        FlagBit::new(5, "Archive", "Set on modification; cleared by backup software."),
    ],
};

/// Spec §7.4.2 / §7.5.1 `GeneralSecondaryFlags` and `GeneralPrimaryFlags`.
///
/// `NoFatChain` is the field most easily read backwards, and reading it backwards
/// means following a chain that was never written. See the note on bit 1.
pub static ALLOCATION_FLAGS: FlagTable = FlagTable {
    name: "exFAT allocation flags",
    bits: &[
        FlagBit::new(
            0,
            "AllocationPossible",
            "The FirstCluster and DataLength fields are meaningful. When clear they \
             must both be zero and the record describes no clusters.",
        ),
        FlagBit::new(
            1,
            "NoFatChain",
            "SET means the allocation is contiguous and the FAT holds nothing for \
             it — walk clusters arithmetically and do not read the FAT. CLEAR means \
             the FAT chain from FirstCluster is authoritative. Getting this backwards \
             produces a chain that does not exist.",
        ),
    ],
};

/// Spec §7.1.2 `BitmapFlags`.
pub static BITMAP_FLAGS: FlagTable = FlagTable {
    name: "exFAT allocation bitmap flags",
    bits: &[FlagBit::new(
        0,
        "BitmapIdentifier",
        "0 = the first allocation bitmap, 1 = the second. A second bitmap exists \
         only on a TexFAT volume with NumberOfFats = 2.",
    )],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_delete_operation_is_one_bit() {
        assert!(!is_in_use(0x05));
        assert_eq!(undeleted(0x05), FILE);
        assert_eq!(undeleted(0x40), STREAM_EXTENSION);
        assert_eq!(undeleted(0x41), FILE_NAME);
        assert_eq!(undeleted(0x20), VOLUME_GUID);
    }

    #[test]
    fn primary_and_secondary_are_told_apart_even_when_deleted() {
        assert!(!is_secondary(FILE));
        assert!(!is_secondary(0x05));
        assert!(is_secondary(STREAM_EXTENSION));
        assert!(is_secondary(0x41));
    }

    #[test]
    fn criticality_survives_deletion() {
        assert!(!is_benign(FILE));
        assert!(is_benign(VOLUME_GUID));
        assert!(is_benign(0x20));
    }

    #[test]
    fn deleted_types_are_named_not_unknown() {
        assert_eq!(entry_type_label(0x05), "deleted file");
        assert_eq!(entry_type_label(0xC1), "file name");
        assert_eq!(entry_type_label(0x7E), "unknown entry type");
    }
}
