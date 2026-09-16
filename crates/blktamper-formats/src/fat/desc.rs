//! FAT12/FAT16/FAT32 record layouts — Tier A of ADR-002.
//!
//! Offsets transcribed from the Microsoft *FAT32 File System Specification*
//! (fatgen103, §3.1 "Boot Sector and BPB", §4 "FAT Type Determination", §5 "FSInfo"
//! and §6 "Directory Structure"), cross-checked against libyal's `libfsfat`
//! documentation, Kaitai's `vfat.ksy` and ImHex's `FAT32.hexpat`. Every descriptor
//! here is verified by `tests/descriptors.rs`, which asserts the fields tile the
//! record exactly.
//!
//! The BPB is split into three tables rather than one, because that is how the
//! format is actually shaped: bytes 0x00..0x24 are common to every FAT variant, and
//! what follows depends on the FAT type — which is *not* declared anywhere in the
//! boot sector and must be computed from the cluster count (fatgen §4). Splitting
//! the tables keeps that fork visible instead of burying it in a 90-field record
//! where half the fields are wrong for any given volume.

use blktamper_core::desc::{f_checksum, f_flags, f_reserved, fx};
use blktamper_core::{
    Check, ChecksumAlgo, ChecksumSpec, Cover, EnumEntry, EnumTable, FieldFlags, FlagBit, FlagTable,
    LinkDesc, LinkKind, Repr, StructDesc, Width,
};

/// Media descriptor bytes. The value must also appear as the low byte of FAT[0],
/// which is the only self-check the FAT itself carries.
pub static FAT_MEDIA: EnumTable = EnumTable {
    name: "FAT media descriptor",
    entries: &[
        EnumEntry::num(0xF0, "removable", "1.44 MB or 2.88 MB floppy, or any removable medium"),
        EnumEntry::num(0xF8, "fixed disk", "the conventional value for a hard disk, SSD or card"),
        EnumEntry::num(0xF9, "720 KB / 1.2 MB", "double-sided floppy"),
        EnumEntry::num(0xFA, "320 KB / RAM disk", "single-sided 320 KB floppy"),
        EnumEntry::num(0xFB, "640 KB", "double-sided 640 KB floppy"),
        EnumEntry::num(0xFC, "180 KB", "single-sided 180 KB floppy"),
        EnumEntry::num(0xFD, "360 KB", "double-sided 360 KB floppy"),
        EnumEntry::num(0xFE, "160 KB", "single-sided 160 KB floppy"),
        EnumEntry::num(0xFF, "320 KB", "double-sided 320 KB floppy"),
    ],
};

/// `BPB_ExtFlags` (fatgen §3.3). Four bits of FAT number plus one mirroring switch,
/// which together decide whether FAT #1 is a mirror or an independent table — and
/// therefore whether a divergence between the two is a corruption or the design.
pub static EXT_FLAGS: FlagTable = FlagTable {
    name: "FAT32 ext_flags",
    bits: &[
        FlagBit::new(0, "active_fat[0]", "bit 0 of the zero-based active FAT number"),
        FlagBit::new(1, "active_fat[1]", "bit 1 of the zero-based active FAT number"),
        FlagBit::new(2, "active_fat[2]", "bit 2 of the zero-based active FAT number"),
        FlagBit::new(3, "active_fat[3]", "bit 3 of the zero-based active FAT number"),
        FlagBit::reserved(4, "reserved; not part of the active-FAT number"),
        FlagBit::reserved(5, "reserved; not part of the active-FAT number"),
        FlagBit::reserved(6, "reserved; not part of the active-FAT number"),
        FlagBit::new(
            7,
            "no_mirroring",
            "set: only the FAT named by bits 0-3 is live and the others are stale. \
             Clear: every FAT is mirrored on write, so they must agree.",
        ),
        FlagBit::reserved(8, "reserved; the high byte of ext_flags is unused"),
        FlagBit::reserved(9, "reserved; the high byte of ext_flags is unused"),
        FlagBit::reserved(10, "reserved; the high byte of ext_flags is unused"),
        FlagBit::reserved(11, "reserved; the high byte of ext_flags is unused"),
        FlagBit::reserved(12, "reserved; the high byte of ext_flags is unused"),
        FlagBit::reserved(13, "reserved; the high byte of ext_flags is unused"),
        FlagBit::reserved(14, "reserved; the high byte of ext_flags is unused"),
        FlagBit::reserved(15, "reserved; the high byte of ext_flags is unused"),
    ],
};

/// `DIR_Attr` (fatgen §6.1). The low four bits set together — 0x0F — are not an
/// attribute combination at all: they are the marker that says "this 32 bytes is a
/// long-filename fragment, not a file". Every pre-VFAT implementation skipped such
/// entries as nonsense, which is exactly why that encoding was chosen.
pub static DIR_ATTR: FlagTable = FlagTable {
    name: "FAT directory attributes",
    bits: &[
        FlagBit::new(0, "read_only", "ATTR_READ_ONLY: writers should refuse to modify"),
        FlagBit::new(1, "hidden", "ATTR_HIDDEN: omitted from a normal directory listing"),
        FlagBit::new(2, "system", "ATTR_SYSTEM: belongs to the operating system"),
        FlagBit::new(
            3,
            "volume_id",
            "ATTR_VOLUME_ID: this entry carries the volume label, not a file. Only \
             legal in the root directory, and there must be at most one.",
        ),
        FlagBit::new(4, "directory", "ATTR_DIRECTORY: first_cluster points at a directory"),
        FlagBit::new(5, "archive", "ATTR_ARCHIVE: set on every write; backup tools clear it"),
        FlagBit::reserved(6, "reserved; ATTR_DEVICE in some DOS versions"),
        FlagBit::reserved(7, "reserved; no attribute is defined for this bit"),
    ],
};

/// The long-filename checksum ties an LFN run to one specific 8.3 entry.
///
/// `Cover::External` because the covered bytes are the *next* record's first 11
/// bytes, not anything inside this one — the traversal in `mod.rs` supplies them
/// (the Tier A/B seam). Getting this check to pass is the only evidence that a run
/// of LFN fragments and the short entry after it belong together; on a directory
/// where entries have been deleted and partly reused it is the difference between
/// a recovered name and a fabricated one.
pub static LFN_CHECKSUM: ChecksumSpec = ChecksumSpec {
    algo: ChecksumAlgo::FatShortName,
    cover: Cover::External,
    exclude: &[],
    doc: "rotate-right-and-add over the 11 raw name bytes of the 8.3 entry this run \
          belongs to (fatgen §7.2)",
};

/// The BIOS Parameter Block common to FAT12, FAT16 and FAT32 (fatgen §3.1).
///
/// Note what is *not* here: the FAT type. There is no field for it anywhere in the
/// boot sector. fatgen §4 is explicit that the count of clusters — derived from
/// eight of the fields below — is the only determination, and that any other method
/// "will lead to failures". `fs_type` in the extended BPBs is a comment.
pub static BPB: StructDesc = StructDesc {
    name: "FAT BPB",
    size: Some(0x24),
    fields: &[
        fx(
            "jmp_boot",
            0x00,
            Width::Bytes(3),
            Repr::Raw,
            "EB xx 90 (short jump + NOP) or E9 xx xx (near jump). A real x86 branch \
             over the BPB to the boot code, and the cheapest first discriminator \
             against an MBR, which normally starts with code that is not a jump.",
            FieldFlags::OPAQUE,
            &[],
        ),
        fx(
            "oem_name",
            0x03,
            Width::Ascii(8),
            Repr::Ascii,
            "Formatter's signature, e.g. \"mkfs.fat\" or \"MSDOS5.0\". fatgen says to \
             ignore it, but it is the field that tells FAT from exFAT (\"EXFAT   \") \
             and NTFS (\"NTFS    \"), whose boot sectors are otherwise the same shape.",
            FieldFlags::LEGACY,
            &[],
        ),
        fx(
            "bytes_per_sector",
            0x0B,
            Width::U16le,
            Repr::Dec,
            "512, 1024, 2048 or 4096. Every offset in the volume is counted in these, \
             not in the device's own sectors, so a wrong value here relocates the \
             entire filesystem.",
            FieldFlags::NONE,
            &[Check::PowerOfTwo, Check::Range(512, 4096)],
        ),
        fx(
            "sectors_per_cluster",
            0x0D,
            Width::U8,
            Repr::Dec,
            "Power of two, 1..=128. Together with bytes_per_sector this caps the \
             cluster at 32 KiB in the spec; larger values exist in the wild and are \
             shown rather than rejected.",
            FieldFlags::NONE,
            &[Check::PowerOfTwo, Check::Range(1, 128)],
        ),
        fx(
            "reserved_sectors",
            0x0E,
            Width::U16le,
            Repr::Dec,
            "Sectors before FAT #0, including the boot sector itself. 1 on FAT12/16, \
             usually 32 on FAT32 to leave room for the FSInfo and backup sectors. \
             Never zero — NTFS puts zero here, which is a useful discriminator.",
            FieldFlags::NONE,
            &[Check::NonZero],
        ),
        fx(
            "num_fats",
            0x10,
            Width::U8,
            Repr::Dec,
            "Number of file allocation tables. Always 2 in practice; the spec allows \
             1 and warns that anything else confuses disk utilities.",
            FieldFlags::NONE,
            &[Check::Range(1, 2)],
        ),
        fx(
            "root_entries",
            0x11,
            Width::U16le,
            Repr::Dec,
            "Size of the fixed root directory, in 32-byte entries. Must be zero on \
             FAT32, where the root is an ordinary cluster chain instead; must be \
             non-zero on FAT12/16, where this is the hard ceiling on root files.",
            FieldFlags::NONE,
            &[Check::Cross("root_entries_match_fat_type")],
        ),
        fx(
            "total_sectors_16",
            0x13,
            Width::U16le,
            Repr::Dec,
            "Volume size in sectors when it fits in 16 bits. Exactly one of this and \
             total_sectors_32 is non-zero; FAT32 always uses the 32-bit field.",
            FieldFlags::NONE,
            &[Check::Cross("exactly_one_total_sectors")],
        ),
        fx(
            "media",
            0x15,
            Width::U8,
            Repr::Enum(&FAT_MEDIA),
            "Legacy medium type. Its only remaining job is that the same byte must \
             appear as the low byte of FAT[0], which is the one internal consistency \
             check the allocation table carries.",
            FieldFlags::LEGACY,
            &[Check::OneOf(&[0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])],
        ),
        fx(
            "fat_size_16",
            0x16,
            Width::U16le,
            Repr::Dec,
            "Sectors per FAT on FAT12/16. Must be zero on FAT32, which uses \
             fat_size_32 instead. Both zero means the volume has no allocation table \
             at all and nothing can be followed.",
            FieldFlags::NONE,
            &[Check::Cross("exactly_one_fat_size")],
        ),
        fx(
            "sectors_per_track",
            0x18,
            Width::U16le,
            Repr::Dec,
            "INT 13h geometry. Meaningless on anything made after about 1996, and \
             never used by the driver — only by the boot code.",
            FieldFlags::LEGACY,
            &[],
        ),
        fx(
            "num_heads",
            0x1A,
            Width::U16le,
            Repr::Dec,
            "INT 13h geometry, as legacy as sectors_per_track.",
            FieldFlags::LEGACY,
            &[],
        ),
        fx(
            "hidden_sectors",
            0x1C,
            Width::U32le,
            Repr::Dec,
            "Sectors before this volume on the device — i.e. the partition's start \
             LBA. Zero on an unpartitioned medium, and frequently left zero by \
             formatters that were handed an offset, so a mismatch with the partition \
             table is worth noticing but is not corruption.",
            FieldFlags::LEGACY.or(FieldFlags::OFTEN_ZERO),
            &[],
        ),
        fx(
            "total_sectors_32",
            0x20,
            Width::U32le,
            Repr::SizeSectors,
            "Volume size in sectors, 32-bit form. This is the number that says how \
             far the filesystem believes it extends; when it runs past the end of the \
             partition the volume was formatted with the wrong size and the tail is \
             unreadable.",
            FieldFlags::NONE,
            &[Check::Cross("volume_fits_device")],
        ),
    ],
    checks: &[Check::Cross("geometry_self_consistent")],
    spec: "Microsoft FAT32 File System Specification (fatgen103) §3.1",
    links: &[],
};

/// The FAT32 extended BPB, 0x24..0x5A (fatgen §3.3).
pub static EBPB32: StructDesc = StructDesc {
    name: "FAT32 EBPB",
    size: Some(0x36),
    fields: &[
        fx(
            "fat_size_32",
            0x00,
            Width::U32le,
            Repr::Dec,
            "Sectors per FAT. With 4 bytes per entry this is what fixes the highest \
             addressable cluster, and it is the multiplier that places FAT #1, the \
             root directory and every cluster after it.",
            FieldFlags::NONE,
            &[Check::NonZero],
        ),
        f_flags(
            "ext_flags",
            0x04,
            Width::U16le,
            &EXT_FLAGS,
            "Which FAT is live and whether the others are mirrored. Zero — the usual \
             value — means all FATs are written together, which is what makes a \
             divergence between them meaningful rather than expected.",
        ),
        fx(
            "fs_version",
            0x06,
            Width::U16le,
            Repr::Hex,
            "Must be 0x0000. A non-zero version is a filesystem this driver has never \
             seen, and the spec says to refuse to mount it — we still show it.",
            FieldFlags::NONE,
            &[Check::Eq(0)],
        ),
        fx(
            "root_cluster",
            0x08,
            Width::U32le,
            Repr::Cluster,
            "First cluster of the root directory. Normally 2, the first data cluster, \
             but the spec permits any cluster — which is why the root must be found \
             through this field rather than assumed.",
            FieldFlags::POINTER,
            &[Check::Cross("root_cluster_in_range")],
        ),
        fx(
            "fs_info",
            0x0C,
            Width::U16le,
            Repr::Lba,
            "Sector number of the FSInfo structure, relative to the start of the \
             volume. Conventionally 1.",
            FieldFlags::POINTER,
            &[],
        ),
        fx(
            "backup_boot_sector",
            0x0E,
            Width::U16le,
            Repr::Lba,
            "Sector holding a copy of this boot sector, relative to the volume start. \
             Conventionally 6, and zero means there is no backup — which matters, \
             because a FAT32 volume whose sector 0 is damaged is recoverable only \
             from here.",
            FieldFlags::POINTER,
            &[],
        ),
        f_reserved(
            "reserved",
            0x10,
            12,
            "Reserved for future expansion; must be zero. Non-zero bytes here are \
             either an extension or residue from whatever occupied the sector before.",
        ),
        fx(
            "drive_number",
            0x1C,
            Width::U8,
            Repr::Hex,
            "INT 13h drive number: 0x80 for a fixed disk, 0x00 for a floppy. Used only \
             by the boot code.",
            FieldFlags::LEGACY,
            &[Check::OneOf(&[0x00, 0x80])],
        ),
        f_reserved(
            "reserved1",
            0x1D,
            1,
            "Reserved. Windows NT used it as a dirty/chkdsk flag, so a non-zero value \
             is more likely a bit of history than corruption.",
        ),
        fx(
            "boot_signature",
            0x1E,
            Width::U8,
            Repr::Hex,
            "0x29 when volume_id, volume_label and fs_type that follow are present. \
             0x28 means only volume_id follows. Any other value means the three \
             fields below are whatever was on the medium before.",
            FieldFlags::NONE,
            &[Check::OneOf(&[0x28, 0x29])],
        ),
        fx(
            "volume_id",
            0x1F,
            Width::U32le,
            Repr::Hex,
            "Volume serial number, normally derived from the format timestamp. Shown \
             by Windows as XXXX-XXXX and by mtools as the volume serial; it is the \
             cheapest way to recognise a specific formatting event.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "volume_label",
            0x23,
            Width::Ascii(11),
            Repr::Ascii,
            "Space-padded label, kept only for backwards compatibility. The label the \
             system actually reports lives in the root directory's ATTR_VOLUME_ID \
             entry; the two are updated independently and routinely disagree.",
            FieldFlags::LEGACY,
            &[],
        ),
        fx(
            "fs_type",
            0x2E,
            Width::Ascii(8),
            Repr::Ascii,
            "\"FAT32   \". Documentation only: fatgen §4 states plainly that this \
             string must not be used to determine the FAT type, because formatters \
             write whatever they like here. The cluster count decides.",
            FieldFlags::LEGACY,
            &[Check::Cross("fs_type_matches_cluster_count")],
        ),
    ],
    checks: &[Check::Cross("fat_mirroring")],
    links: &[
        LinkDesc::new("fs_info", LinkKind::ToLbaRelative, "FSInfo sector"),
        LinkDesc::new("backup_boot_sector", LinkKind::ToLbaRelative, "backup boot sector"),
        LinkDesc::new("root_cluster", LinkKind::ToCluster, "root directory"),
    ],
    spec: "Microsoft FAT32 File System Specification (fatgen103) §3.3",
};

/// The FAT12/FAT16 extended BPB, 0x24..0x3E (fatgen §3.2).
///
/// The same five trailing fields as FAT32, 22 bytes earlier, because FAT32 inserted
/// its own block in front of them. Reading a FAT16 volume with the FAT32 table — or
/// the reverse — puts the label and serial number 22 bytes out and produces
/// confident nonsense, which is why the FAT type must be settled before either table
/// is applied.
pub static EBPB16: StructDesc = StructDesc {
    name: "FAT12/16 EBPB",
    size: Some(0x1A),
    fields: &[
        fx(
            "drive_number",
            0x00,
            Width::U8,
            Repr::Hex,
            "INT 13h drive number: 0x80 fixed disk, 0x00 floppy.",
            FieldFlags::LEGACY,
            &[Check::OneOf(&[0x00, 0x80])],
        ),
        f_reserved("reserved1", 0x01, 1, "Reserved; used by Windows NT as a dirty flag."),
        fx(
            "boot_signature",
            0x02,
            Width::U8,
            Repr::Hex,
            "0x29 when the three fields that follow are present, 0x28 when only \
             volume_id is.",
            FieldFlags::NONE,
            &[Check::OneOf(&[0x28, 0x29])],
        ),
        fx(
            "volume_id",
            0x03,
            Width::U32le,
            Repr::Hex,
            "Volume serial number.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "volume_label",
            0x07,
            Width::Ascii(11),
            Repr::Ascii,
            "Space-padded label, superseded by the root directory's ATTR_VOLUME_ID \
             entry.",
            FieldFlags::LEGACY,
            &[],
        ),
        fx(
            "fs_type",
            0x12,
            Width::Ascii(8),
            Repr::Ascii,
            "\"FAT12   \" or \"FAT16   \". Documentation only — the cluster count is \
             what determines the type (fatgen §4).",
            FieldFlags::LEGACY,
            &[Check::Cross("fs_type_matches_cluster_count")],
        ),
    ],
    checks: &[],
    links: &[],
    spec: "Microsoft FAT32 File System Specification (fatgen103) §3.2",
};

/// The FAT32 FSInfo sector (fatgen §5).
///
/// Three signatures and two numbers, and the spec is blunt that the two numbers are
/// hints: "the operating system must verify at volume mount". A free count that
/// disagrees with the FAT is therefore not corruption — but it *is* a record of what
/// the last writer believed, which is evidence.
pub static FSINFO: StructDesc = StructDesc {
    name: "FAT32 FSInfo",
    size: Some(512),
    fields: &[
        fx(
            "lead_sig",
            0x000,
            Width::U32le,
            Repr::Hex,
            "0x41615252, \"RRaA\" on disk. First of three signatures, placed so that \
             an FSInfo sector cannot be mistaken for a boot sector or for data.",
            FieldFlags::NONE,
            &[Check::Eq(0x4161_5252)],
        ),
        f_reserved(
            "reserved",
            0x004,
            480,
            "480 reserved bytes; must be zero. The largest single reserved run in any \
             format here, and a natural hiding place — non-zero content is worth a \
             look rather than a shrug.",
        ),
        fx(
            "struct_sig",
            0x1E4,
            Width::U32le,
            Repr::Hex,
            "0x61417272, \"rrAa\". Immediately precedes the two counters, so a reader \
             that seeks straight to them can still confirm it is in the right place.",
            FieldFlags::NONE,
            &[Check::Eq(0x6141_7272)],
        ),
        fx(
            "free_count",
            0x1E8,
            Width::U32le,
            Repr::Dec,
            "Last known count of free clusters, or 0xFFFFFFFF for \"unknown\". A hint, \
             not the truth: the FAT is authoritative. When it disagrees, the \
             difference is usually exactly the clusters a delete released.",
            FieldFlags::NONE,
            &[Check::Cross("free_count_plausible")],
        ),
        fx(
            "next_free",
            0x1EC,
            Width::U32le,
            Repr::Dec,
            "Cluster the allocator should search from, or 0xFFFFFFFF for \"no hint\". \
             Because it moves forward as files are written, it is a rough high-water \
             mark of where data has been placed.",
            FieldFlags::NONE,
            &[Check::Cross("next_free_plausible")],
        ),
        f_reserved("reserved2", 0x1F0, 12, "Reserved; must be zero."),
        fx(
            "trail_sig",
            0x1FC,
            Width::U32le,
            Repr::Hex,
            "0xAA550000 — on disk the four bytes 00 00 55 AA, so the sector ends with \
             the same 55 AA a boot sector does.",
            FieldFlags::NONE,
            &[Check::Eq(0xAA55_0000)],
        ),
    ],
    checks: &[],
    links: &[],
    spec: "Microsoft FAT32 File System Specification (fatgen103) §5",
};

/// A 32-byte 8.3 directory entry (fatgen §6).
///
/// The first byte carries two meanings that have nothing to do with the name: 0xE5
/// marks the entry free-but-used-to-exist, and 0x00 marks it free and never used,
/// which also terminates the directory scan. Deleting a file on FAT writes one byte
/// — this one — and clears the cluster chain. Everything else in the record survives
/// untouched, which is why a deleted entry still names its size, its timestamps and
/// its first cluster, and why this viewer shows them.
pub static DIR_ENTRY: StructDesc = StructDesc {
    name: "FAT directory entry",
    size: Some(32),
    fields: &[
        fx(
            "name",
            0x00,
            Width::Ascii(11),
            Repr::Ascii,
            "8.3 name, space-padded, no dot stored. Upper case by convention. A first \
             byte of 0xE5 means deleted — the original character is destroyed and can \
             only be recovered from a surviving long-filename run. 0x05 means the \
             real first byte is 0xE5 (a KANJI lead byte), not a deletion.",
            FieldFlags::NONE,
            &[],
        ),
        f_flags(
            "attr",
            0x0B,
            Width::U8,
            &DIR_ATTR,
            "File attributes. The combination 0x0F is not an attribute set: it marks \
             the record as a long-filename fragment, deliberately chosen so that \
             pre-VFAT systems would ignore it.",
        ),
        fx(
            "nt_reserved",
            0x0C,
            Width::U8,
            Repr::Hex,
            "Reserved by the spec; used by Windows NT to remember that the base name \
             (0x08) or the extension (0x10) was entered in lower case, so that a name \
             like \"readme.txt\" needs no long-filename entry at all.",
            FieldFlags::OFTEN_ZERO,
            &[],
        ),
        fx(
            "crt_time_tenth",
            0x0D,
            Width::U8,
            Repr::Dec,
            "Creation time, hundredths of a second, 0..=199 — the odd-second half that \
             crt_time's two-second resolution cannot hold.",
            FieldFlags::NONE,
            &[Check::Range(0, 199)],
        ),
        fx(
            "crt_time",
            0x0E,
            Width::U16le,
            Repr::DosTime,
            "Creation time, two-second resolution, in whatever the writer's local time \
             happened to be. FAT stores no time zone, so these are not comparable \
             across machines.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "crt_date",
            0x10,
            Width::U16le,
            Repr::DosDate,
            "Creation date, years from 1980. The epoch is why a wiped-to-zero entry \
             reads as 1980-00-00 rather than as an obviously invalid date.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "last_access_date",
            0x12,
            Width::U16le,
            Repr::DosDate,
            "Date of last read or write. Optional, and many drivers mount noatime and \
             never touch it — so equal to crt_date means nothing in particular.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "first_cluster_hi",
            0x14,
            Width::U16le,
            Repr::Hex,
            "High 16 bits of the first cluster. Always zero on FAT12/16, where these \
             two bytes were the OS/2 extended-attribute pointer — so a non-zero value \
             on a FAT16 volume is residue, not a cluster.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "write_time",
            0x16,
            Width::U16le,
            Repr::DosTime,
            "Last modification time, two-second resolution. The only timestamp the \
             spec requires a writer to maintain.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "write_date",
            0x18,
            Width::U16le,
            Repr::DosDate,
            "Last modification date.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "first_cluster_lo",
            0x1A,
            Width::U16le,
            Repr::Hex,
            "Low 16 bits of the first cluster. The reader adds a computed \
             `first_cluster` node that joins this with first_cluster_hi and owns both \
             byte ranges, because the split is a storage detail and the cluster number \
             is the thing you want to follow.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "file_size",
            0x1C,
            Width::U32le,
            Repr::SizeBytes,
            "Size in bytes; zero for directories, whose length is the cluster chain. \
             Survives deletion intact, so it still says how much data was here even \
             after the chain that held it has been released.",
            FieldFlags::NONE,
            &[],
        ),
    ],
    checks: &[Check::Cross("entry_consistent")],
    links: &[],
    spec: "Microsoft FAT32 File System Specification (fatgen103) §6.1",
};

/// A 32-byte long-filename fragment (fatgen §7).
///
/// The layout is shaped entirely by backwards compatibility: `attr` sits where an
/// 8.3 entry's attribute byte sits and holds 0x0F so old systems skip the record,
/// and `first_cluster_lo` sits where an 8.3 entry's cluster field sits and holds
/// zero so an old `chkdsk` does not free a cluster. The name is therefore chopped
/// into three runs — 5, 6 and 2 UTF-16 units — around those two fields.
///
/// A run is stored **in reverse**: the fragment carrying 0x40 in `order` comes first
/// on disk and holds the *last* part of the name, and the fragment with order 1 sits
/// immediately before the 8.3 entry it names.
pub static LFN_ENTRY: StructDesc = StructDesc {
    name: "FAT long-filename entry",
    size: Some(32),
    fields: &[
        fx(
            "order",
            0x00,
            Width::U8,
            Repr::Hex,
            "Sequence number 1..=20 in the low bits, with 0x40 set on the fragment \
             that comes first on disk and last in the name. Deleting the file \
             overwrites this byte with 0xE5 in every fragment, which is why a deleted \
             run has no sequence numbers left — only its physical order.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "name1",
            0x01,
            Width::Utf16Le(10),
            Repr::Utf16Le,
            "First 5 UTF-16LE units of this fragment. Padding after the terminating \
             0x0000 is 0xFFFF, so the decoded field value can show trailing filler — \
             the reader's assembled name strips it; this field does not, because the \
             padding is what is actually on the disk.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "attr",
            0x0B,
            Width::U8,
            Repr::Hex,
            "Must be 0x0F (read-only + hidden + system + volume-id). Placed at the \
             same offset as an 8.3 entry's attribute byte so that implementations \
             which predate long filenames skip the record instead of corrupting it.",
            FieldFlags::NONE,
            &[Check::Eq(0x0F)],
        ),
        fx(
            "type",
            0x0C,
            Width::U8,
            Repr::Hex,
            "Must be zero. Reserved for future sub-components of a name; none were \
             ever defined.",
            FieldFlags::MUST_ZERO,
            &[Check::Zero],
        ),
        f_checksum(
            "checksum",
            0x0D,
            Width::U8,
            &LFN_CHECKSUM,
            "Checksum of the 11 raw name bytes of the 8.3 entry this run belongs to. \
             The only thing binding a long name to a short one: if a legacy tool \
             renamed the 8.3 entry, the checksum stops matching and the long name must \
             be discarded rather than trusted.",
        ),
        fx(
            "name2",
            0x0E,
            Width::Utf16Le(12),
            Repr::Utf16Le,
            "Next 6 UTF-16LE units, split from name1 by the attribute and checksum \
             bytes that had to keep their 8.3 offsets.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "first_cluster_lo",
            0x1A,
            Width::U16le,
            Repr::Hex,
            "Must be zero. Occupies the 8.3 entry's first-cluster field so that a \
             pre-VFAT chkdsk reading this record as a file finds no cluster to free.",
            FieldFlags::MUST_ZERO,
            &[Check::Zero],
        ),
        fx(
            "name3",
            0x1C,
            Width::Utf16Le(4),
            Repr::Utf16Le,
            "Final 2 UTF-16LE units of this fragment. 13 units per fragment, 20 \
             fragments maximum, hence the 255-character limit on FAT long names.",
            FieldFlags::NONE,
            &[],
        ),
    ],
    checks: &[Check::Cross("lfn_run_checksum")],
    links: &[],
    spec: "Microsoft FAT32 File System Specification (fatgen103) §7",
};

/// Size of one directory record, 8.3 and long-filename alike.
pub const ENTRY_SIZE: u64 = 32;
/// Offset of the FAT32 extended BPB within the boot sector.
pub const EBPB_OFFSET: u64 = 0x24;
/// Offset of the 55 AA marker within the boot sector.
pub const BOOT_SIG_OFFSET: u64 = 0x1FE;
/// `DIR_Attr` value that marks a long-filename fragment rather than a file.
pub const ATTR_LONG_NAME: u8 = 0x0F;
/// Mask applied before testing for `ATTR_LONG_NAME` (fatgen §6.1).
pub const ATTR_LONG_NAME_MASK: u8 = 0x3F;
/// First name byte of an entry that was deleted.
pub const DELETED_MARK: u8 = 0xE5;
/// First name byte of an entry that has never been used; also ends the directory.
pub const FREE_MARK: u8 = 0x00;
/// First name byte meaning "the real first byte is 0xE5", not a deletion.
pub const KANJI_E5: u8 = 0x05;

/// Every descriptor this module defines, for the workspace-wide validation test.
pub static ALL: &[&StructDesc] = &[&BPB, &EBPB32, &EBPB16, &FSINFO, &DIR_ENTRY, &LFN_ENTRY];
