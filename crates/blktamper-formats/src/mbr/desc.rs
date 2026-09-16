//! MBR record layouts — Tier A of ADR-002.
//!
//! Offsets cross-checked against the Wikipedia MBR article, util-linux's
//! `include/pt-mbr.h` layout, and Kaitai's `mbr_partition_table.ksy`. Every
//! descriptor here is verified by `tests/descriptors.rs`, which asserts the fields
//! tile the record exactly.

use super::types::{MBR_STATUS, MBR_TYPES};
use blktamper_core::desc::{f, f_reserved, fx};
use blktamper_core::{Check, FieldFlags, LinkDesc, Repr, StructDesc, Width};

/// One 16-byte partition entry. Used for both the MBR's four slots and the two
/// slots in every EBR.
pub static PART_ENTRY: StructDesc = StructDesc {
    name: "partition entry",
    size: Some(16),
    fields: &[
        fx(
            "status",
            0x00,
            Width::U8,
            Repr::Enum(&MBR_STATUS),
            "0x80 = active/bootable, 0x00 = inactive. Anything else is nonstandard \
             and was historically used as a drive number.",
            FieldFlags::NONE,
            &[Check::OneOf(&[0x00, 0x80])],
        ),
        fx(
            "chs_first",
            0x01,
            Width::Chs,
            Repr::Chs,
            "Cylinder/head/sector of the first sector. Cannot address past ~8 GiB, \
             so on any modern disk this is either a placeholder or wrong. Only \
             lba_first is meaningful.",
            FieldFlags::LEGACY,
            &[],
        ),
        fx(
            "part_type",
            0x04,
            Width::U8,
            Repr::Enum(&MBR_TYPES),
            "Partition type byte. Conventional, not standardised: the same value \
             means different things to different systems. 0x05/0x0F/0x85 mean the \
             entry points at a chain of extended boot records rather than a \
             filesystem.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "chs_last",
            0x05,
            Width::Chs,
            Repr::Chs,
            "CHS of the last sector. FE FF FF (h254 s63 c1023) is the conventional \
             marker for 'does not fit in CHS'.",
            FieldFlags::LEGACY,
            &[],
        ),
        fx(
            "lba_first",
            0x08,
            Width::U32le,
            Repr::Lba,
            "First sector of the partition. In the MBR this is absolute; in an EBR \
             it is relative to that EBR's own sector.",
            FieldFlags::POINTER,
            &[],
        ),
        fx(
            "num_sectors",
            0x0C,
            Width::U32le,
            Repr::SizeSectors,
            "Length in sectors. With 512-byte sectors this caps a partition at 2 TiB, \
             which is the reason GPT exists.",
            FieldFlags::NONE,
            &[],
        ),
    ],
    checks: &[Check::Cross("entry_within_device")],
    links: &[LinkDesc::probe_at_lba("lba_first", "volume header")],
    spec: "conventional; see the Wikipedia MBR article and util-linux pt-mbr.h",
};

/// The parts of sector 0 that are not partition entries.
///
/// The four entries are read separately as an array so they can be indexed and
/// filtered; this descriptor covers everything around them.
pub static MBR_HEADER: StructDesc = StructDesc {
    name: "MBR",
    size: Some(512),
    fields: &[
        fx(
            "bootstrap",
            0x000,
            Width::Bytes(440),
            Repr::Raw,
            "Bootstrap code. Executed by the BIOS on a legacy boot. Opaque here: \
             disassembly is out of scope.",
            FieldFlags::OPAQUE,
            &[],
        ),
        fx(
            "disk_signature",
            0x1B8,
            Width::U32le,
            Repr::Hex,
            "Windows NT disk signature. Linux exposes it as the disk's PARTUUID \
             prefix. Zero on many disks, which is legal.",
            FieldFlags::OFTEN_ZERO,
            &[],
        ),
        f_reserved(
            "copy_protect",
            0x1BC,
            2,
            "Usually zero. 0x5A5A historically meant 'copy protected' to some DOS \
             versions.",
        ),
        fx(
            "entries",
            0x1BE,
            Width::Bytes(64),
            Repr::Raw,
            "Four 16-byte partition entries. The reader replaces this node's \
             children with the parsed entries, so the descriptor still tiles \
             sector 0 exactly and no spurious gap appears.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "boot_signature",
            0x1FE,
            Width::Bytes(2),
            Repr::Hex,
            "Must be 55 AA. Its absence means this sector is not a partition table \
             — though the rest is still shown, because that is the point.",
            FieldFlags::NONE,
            &[Check::EqBytes(&[0x55, 0xAA])],
        ),
    ],
    checks: &[],
    links: &[],
    spec: "conventional; see the Wikipedia MBR article",
};

/// Offset of the first partition entry within sector 0 (and within every EBR).
pub const ENTRIES_OFFSET: u64 = 0x1BE;
/// Size of one entry.
pub const ENTRY_SIZE: u64 = 16;
/// Number of entries in the MBR. An EBR uses only the first two.
pub const ENTRY_COUNT: usize = 4;
/// Offset of the 55 AA marker.
pub const BOOT_SIG_OFFSET: u64 = 0x1FE;

/// A whole MBR sector, including the entry array, used only for descriptor
/// validation and for the "raw sector" view.
pub static MBR_SECTOR_SPAN: (u64, u64) = (0, 512);

/// Fields describing an EBR's own record. The layout is identical to the MBR's;
/// only the meaning of the two used entries differs, which is documented on the
/// nodes the reader builds rather than in a second table.
pub static EBR_HEADER: StructDesc = StructDesc {
    name: "EBR",
    size: Some(512),
    fields: &[
        fx(
            "unused_code",
            0x000,
            Width::Bytes(440),
            Repr::Raw,
            "Bootstrap area. Normally zero in an EBR: nothing boots from here.",
            FieldFlags::OPAQUE.or(FieldFlags::OFTEN_ZERO),
            &[],
        ),
        f("unused_signature", 0x1B8, Width::U32le, Repr::Hex, "Normally zero in an EBR."),
        f_reserved("reserved", 0x1BC, 2, "Normally zero."),
        fx(
            "entries",
            0x1BE,
            Width::Bytes(64),
            Repr::Raw,
            "Four entry slots, of which an EBR uses only the first two: entry 0 is \
             the logical partition and entry 1 points at the next EBR. Slots 2 and 3 \
             must be zero.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "boot_signature",
            0x1FE,
            Width::Bytes(2),
            Repr::Hex,
            "Must be 55 AA, same as the MBR.",
            FieldFlags::NONE,
            &[Check::EqBytes(&[0x55, 0xAA])],
        ),
    ],
    checks: &[],
    links: &[],
    spec: "conventional; see the Wikipedia Extended boot record article",
};

/// Every descriptor this module defines, for the workspace-wide validation test.
pub static ALL: &[&StructDesc] = &[&PART_ENTRY, &MBR_HEADER, &EBR_HEADER];
