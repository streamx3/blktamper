//! GPT record layouts — Tier A of ADR-002.
//!
//! Offsets are transcribed from the UEFI specification chapter 5.3: table 5-5 for
//! the header and table 5-6 for the partition entry, with the attribute bits from
//! table 5-7. Cross-checked against Kaitai's `gpt_partition_table.ksy` and against
//! the bytes `sgdisk` wrote into `tests/fixtures/gen/gpt-basic.img`.
//! `tests/descriptors.rs` asserts both records tile exactly.
//!
//! The header descriptor covers 92 bytes, not 512. The rest of the block is
//! reserved-and-must-be-zero, and the reader hangs it off the header node as its own
//! child so that a non-zero tail — residue from whatever occupied LBA 1 before — is
//! visible rather than silently outside the model.

use super::guids::PARTITION_TYPES;
use blktamper_core::{
    f_checksum, f_flags, f_reserved, fx, Check, ChecksumAlgo, ChecksumSpec, Cover, FieldFlags,
    FlagBit, FlagTable, LinkDesc, LinkKind, Repr, StructDesc, Width,
};

/// UEFI 5.3.2: the header signature, and the only 8 bytes that identify a GPT.
pub const SIGNATURE: &[u8; 8] = b"EFI PART";

/// Revision 1.0, encoded as major in the high 16 bits. Every GPT in the wild.
pub const REVISION_1_0: u32 = 0x0001_0000;

/// UEFI 5.3.2: the header is at least this many bytes and no more than one block.
pub const MIN_HEADER_SIZE: u32 = 92;

/// UEFI 5.3.2: an entry is at least 128 bytes and a multiple of 8.
pub const MIN_ENTRY_SIZE: u32 = 128;

/// Bytes of an entry this descriptor actually knows. Anything past it is reserved
/// for the entry's own type GUID to define, and the reader shows it as raw bytes.
pub const ENTRY_DESC_SIZE: u64 = 128;

/// The header CRC covers `header_size` bytes — not 92, and not the block size —
/// with its own four bytes taken as zero. Off-by-one here is the classic GPT bug,
/// which is why the length is a named field reference rather than a constant.
static HEADER_CRC: ChecksumSpec = ChecksumSpec {
    algo: ChecksumAlgo::Crc32,
    cover: Cover::FieldLen { start: 0, len_field: "header_size" },
    exclude: &[(16, 4)],
    doc: "CRC-32 over header_size bytes of this header with header_crc32 itself \
          zeroed (UEFI 5.3.2).",
};

/// The entry-array CRC covers bytes that are not in this struct, so the format
/// module computes it and attaches the result. `Cover::External` is the declared
/// seam between Tier A and Tier B for checksums.
static ENTRIES_CRC: ChecksumSpec = ChecksumSpec {
    algo: ChecksumAlgo::Crc32,
    cover: Cover::External,
    exclude: &[],
    doc: "CRC-32 over num_entries * entry_size bytes at entries_lba — not over the \
          whole 16 KiB the array normally occupies. The two differ whenever \
          entry_size is not 128 (UEFI 5.3.2).",
};

/// UEFI 5.3.3 table 5-7 reserves bits 3..=47 and requires them to be zero.
const fn resv(bit: u32) -> FlagBit {
    FlagBit::reserved(
        bit,
        "Reserved by UEFI and required to be zero. A set bit means a newer \
         specification than this table knows, a non-standard writer, or residue.",
    )
}

/// Bits 48..=63 are delegated to the partition *type* GUID. Microsoft defines
/// 60..=63 for basic data partitions and ChromeOS packs boot counters into 48..=55,
/// so a set bit here is meaningful only once you know the type.
const fn tspec(bit: u32) -> FlagBit {
    FlagBit::new(
        bit,
        "type_specific",
        "Defined by the partition type GUID, not by UEFI. ChromeOS keeps its \
         priority/tries/successful boot counters in this range.",
    )
}

/// All 64 attribute bits. Naming every one of them is what turns "attributes = \
/// 0x1000000000000004" into a readable row, and what makes a stray reserved bit a
/// diagnostic instead of a number nobody reads.
pub static ENTRY_ATTRIBUTES: FlagTable = FlagTable {
    name: "GPT partition attributes",
    bits: &[
        FlagBit::new(
            0,
            "required_partition",
            "Platform-required: the partition is part of what makes the machine \
             boot. UEFI tools must not delete or move it.",
        ),
        FlagBit::new(
            1,
            "no_block_io_protocol",
            "Firmware must not publish an EFI_BLOCK_IO_PROTOCOL for this partition, \
             so nothing above firmware will see it as a block device.",
        ),
        FlagBit::new(
            2,
            "legacy_bios_bootable",
            "The legacy CSM may boot from this partition. Set by tools that make a \
             GPT disk bootable on a BIOS machine.",
        ),
        resv(3),
        resv(4),
        resv(5),
        resv(6),
        resv(7),
        resv(8),
        resv(9),
        resv(10),
        resv(11),
        resv(12),
        resv(13),
        resv(14),
        resv(15),
        resv(16),
        resv(17),
        resv(18),
        resv(19),
        resv(20),
        resv(21),
        resv(22),
        resv(23),
        resv(24),
        resv(25),
        resv(26),
        resv(27),
        resv(28),
        resv(29),
        resv(30),
        resv(31),
        resv(32),
        resv(33),
        resv(34),
        resv(35),
        resv(36),
        resv(37),
        resv(38),
        resv(39),
        resv(40),
        resv(41),
        resv(42),
        resv(43),
        resv(44),
        resv(45),
        resv(46),
        resv(47),
        tspec(48),
        tspec(49),
        tspec(50),
        tspec(51),
        tspec(52),
        tspec(53),
        tspec(54),
        tspec(55),
        tspec(56),
        tspec(57),
        tspec(58),
        tspec(59),
        FlagBit::new(
            60,
            "read_only",
            "Microsoft basic data: the volume is read-only. Windows honours it; \
             Linux mostly does not.",
        ),
        FlagBit::new(
            61,
            "shadow_copy",
            "Microsoft basic data: the partition is a Volume Shadow Copy of another \
             partition. Mounting it read-write corrupts the pair.",
        ),
        FlagBit::new(
            62,
            "hidden",
            "Microsoft basic data: hidden from Windows. Does nothing to the bytes — \
             the filesystem is still entirely there.",
        ),
        FlagBit::new(
            63,
            "no_automount",
            "Microsoft basic data: do not assign a drive letter automatically.",
        ),
    ],
};

/// The GPT header: 92 bytes at the start of LBA 1 (and of the last LBA).
///
/// Every LBA in it is absolute on the device, which is what makes a GPT copied
/// between disks of different sizes detectable: `alternate_lba` still names the old
/// disk's last sector.
pub static GPT_HEADER: StructDesc = StructDesc {
    name: "GPT header",
    size: Some(92),
    fields: &[
        fx(
            "signature",
            0x00,
            Width::Ascii(8),
            Repr::Ascii,
            "Must be the ASCII \"EFI PART\". The only thing that identifies a GPT; \
             everything else in this record is plausible-looking numbers.",
            FieldFlags::NONE,
            &[Check::EqBytes(SIGNATURE)],
        ),
        fx(
            "revision",
            0x08,
            Width::U32le,
            Repr::Hex,
            "Header revision, major in the high 16 bits: 0x00010000 is 1.0, which is \
             every GPT written since 2005. A different value here does not stop the \
             rest of the header being read.",
            FieldFlags::NONE,
            &[Check::OneOf(&[REVISION_1_0 as u64])],
        ),
        fx(
            "header_size",
            0x0C,
            Width::U32le,
            Repr::Dec,
            "Size of this header in bytes, at least 92 and at most one block. It is \
             also the length header_crc32 covers, so a wrong value here breaks CRC \
             verification rather than the field layout.",
            FieldFlags::NONE,
            &[Check::Range(MIN_HEADER_SIZE as u64, 4096), Check::Cross("header_size_fits_block")],
        ),
        f_checksum(
            "header_crc32",
            0x10,
            Width::U32le,
            &HEADER_CRC,
            "CRC-32 of the first header_size bytes with these four bytes taken as \
             zero. Computed and compared on sight; never silently repaired (R-7.7).",
        ),
        f_reserved(
            "reserved",
            0x14,
            4,
            "Reserved by UEFI and required to be zero. It is inside the CRC, so a \
             non-zero value here is data somebody wrote deliberately and then \
             re-checksummed.",
        ),
        fx(
            "my_lba",
            0x18,
            Width::U64le,
            Repr::Lba,
            "The LBA this header claims to occupy. It is inside the CRC, which is \
             what makes the primary and backup copies differ legitimately — and what \
             makes a header copied to the wrong disk detectable.",
            FieldFlags::POINTER,
            &[Check::Cross("my_lba_matches_location")],
        ),
        fx(
            "alternate_lba",
            0x20,
            Width::U64le,
            Repr::Lba,
            "LBA of the other copy of this header. In the primary it is the device's \
             last LBA; in the backup it is 1. The two are swapped between the copies \
             by design, not by damage.",
            FieldFlags::POINTER,
            &[Check::Cross("alternate_lba_within_device")],
        ),
        fx(
            "first_usable_lba",
            0x28,
            Width::U64le,
            Repr::Lba,
            "First LBA a partition may start at: the sector after the primary entry \
             array. Partitions below it overlap the table that describes them.",
            FieldFlags::NONE,
            &[Check::Cross("usable_range_sane")],
        ),
        fx(
            "last_usable_lba",
            0x30,
            Width::U64le,
            Repr::Lba,
            "Last LBA a partition may end at: the sector before the backup entry \
             array. On a disk image that was resized without rewriting the GPT this \
             is the clearest single sign of it.",
            FieldFlags::NONE,
            &[Check::Cross("usable_range_sane")],
        ),
        fx(
            "disk_guid",
            0x38,
            Width::Guid,
            Repr::Guid,
            "Identifies the disk, not the partitioning. Linux exposes it as the \
             disk's PARTUUID. Stored mixed-endian: first three groups little-endian, \
             last two as written.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "entries_lba",
            0x48,
            Width::U64le,
            Repr::Lba,
            "LBA where the partition entry array starts. Conventionally 2 for the \
             primary and last_usable_lba + 1 for the backup, but the spec only \
             requires it to be outside the usable range.",
            FieldFlags::POINTER,
            &[Check::Cross("entry_array_within_device")],
        ),
        fx(
            "num_entries",
            0x50,
            Width::U32le,
            Repr::Dec,
            "Number of entries in the array, almost always 128. Attacker-controlled \
             and 32 bits wide: multiplied by entry_size it is an allocation request \
             from the disk, so the reader clamps it before doing arithmetic.",
            FieldFlags::NONE,
            &[Check::Cross("entry_count_sane")],
        ),
        fx(
            "entry_size",
            0x54,
            Width::U32le,
            Repr::Dec,
            "Bytes per entry: at least 128 and a multiple of 8. Larger values are \
             legal and mean each entry has a vendor tail past the 128 bytes UEFI \
             defines.",
            FieldFlags::NONE,
            &[Check::Range(MIN_ENTRY_SIZE as u64, 4096), Check::Cross("entry_size_sane")],
        ),
        f_checksum(
            "entries_crc32",
            0x58,
            Width::U32le,
            &ENTRIES_CRC,
            "CRC-32 over num_entries * entry_size bytes of the entry array. The \
             bytes are outside this struct, so the format module computes it; if the \
             array cannot be read in full, no computed value is shown rather than a \
             wrong one.",
        ),
    ],
    checks: &[Check::Cross("primary_backup_agree"), Check::Cross("protective_mbr_present")],
    links: &[
        LinkDesc::new("alternate_lba", LinkKind::ToLba, "the other GPT header"),
        LinkDesc::new("entries_lba", LinkKind::ToLba, "partition entry array"),
        LinkDesc::new("first_usable_lba", LinkKind::ToLba, "first usable sector"),
    ],
    spec: "UEFI specification 5.3.2, table 5-5",
};

/// One partition entry: 128 bytes, however many of them the array holds.
///
/// An unused entry is a zero type GUID and nothing more. The other 112 bytes are not
/// required to be cleared, and frequently are not — a name and a unique GUID left
/// behind by a deleted partition is the highest-value thing this whole module shows.
pub static GPT_ENTRY: StructDesc = StructDesc {
    name: "GPT partition entry",
    size: Some(128),
    fields: &[
        fx(
            "type_guid",
            0x00,
            Width::Guid,
            Repr::Enum(&PARTITION_TYPES),
            "What the partition is for. All-zero means the slot is unused — and says \
             nothing about the remaining 112 bytes. Unknown GUIDs still render as \
             GUIDs; the table only ever adds a name.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "unique_guid",
            0x10,
            Width::Guid,
            Repr::Guid,
            "Identifies this partition across disks and reformats. Linux mounts by \
             it as PARTUUID=. Surviving in an otherwise-cleared slot, it identifies \
             what used to be there.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "first_lba",
            0x20,
            Width::U64le,
            Repr::Lba,
            "First sector of the partition, absolute on the device and inclusive.",
            FieldFlags::POINTER,
            &[Check::Cross("entry_within_usable_range")],
        ),
        fx(
            "last_lba",
            0x28,
            Width::U64le,
            Repr::Lba,
            "Last sector of the partition, inclusive — not a length, and not an \
             exclusive end. Off-by-one here is how a partition ends up one sector \
             short of its filesystem.",
            FieldFlags::POINTER,
            &[Check::Cross("entry_within_usable_range")],
        ),
        f_flags(
            "attributes",
            0x30,
            Width::U64le,
            &ENTRY_ATTRIBUTES,
            "Attribute bits. 0..=2 are UEFI's, 48..=63 belong to the type GUID, and \
             everything between is reserved and should be zero.",
        ),
        fx(
            "name",
            0x38,
            Width::Utf16Le(72),
            Repr::Utf16Le,
            "Partition name: 36 UTF-16LE code units, NUL-padded. Nothing guarantees \
             it is valid UTF-16, so it is decoded lossily and never refused. Bytes \
             after the terminating NUL are not required to be zero, and when they \
             are not, they are residue.",
            FieldFlags::NONE,
            &[],
        ),
    ],
    checks: &[Check::Cross("entry_no_overlap")],
    links: &[LinkDesc::probe_at_lba("first_lba", "volume header")],
    spec: "UEFI specification 5.3.3, tables 5-6 and 5-7",
};

/// Every descriptor this module defines, for the workspace-wide validation test.
pub static ALL: &[&StructDesc] = &[&GPT_HEADER, &GPT_ENTRY];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_tiles_ninety_two_bytes_with_fourteen_fields() {
        assert_eq!(GPT_HEADER.fields.len(), 14);
        assert_eq!(GPT_HEADER.size, Some(92));
        assert!(GPT_HEADER.gaps().is_empty(), "{:?}", GPT_HEADER.gaps());
        assert!(blktamper_core::validate_desc(&GPT_HEADER).is_empty());
    }

    #[test]
    fn the_entry_tiles_one_hundred_and_twenty_eight_bytes_with_six_fields() {
        assert_eq!(GPT_ENTRY.fields.len(), 6);
        assert_eq!(GPT_ENTRY.size, Some(128));
        assert!(GPT_ENTRY.gaps().is_empty(), "{:?}", GPT_ENTRY.gaps());
        assert!(blktamper_core::validate_desc(&GPT_ENTRY).is_empty());
    }

    #[test]
    fn every_attribute_bit_is_described_exactly_once() {
        let mut bits: Vec<u32> = ENTRY_ATTRIBUTES.bits.iter().map(|b| b.bit).collect();
        bits.sort_unstable();
        assert_eq!(bits, (0..64).collect::<Vec<u32>>());
        // 3..=47 are the reserved run; nothing else is reserved.
        for b in ENTRY_ATTRIBUTES.bits {
            assert_eq!(b.reserved, (3..=47).contains(&b.bit), "bit {}", b.bit);
        }
    }
}
