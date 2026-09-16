//! exFAT record layouts — Tier A of ADR-002.
//!
//! Offsets transcribed from Microsoft's exFAT File System Specification revision
//! 1.00 (sections 3, 6 and 7) and cross-checked against ImHex's `exFAT.hexpat` and
//! libyal's `libfsfat` documentation. Every descriptor here is verified by
//! `tests/descriptors.rs`, which asserts the fields tile the record exactly.
//!
//! Nothing in this file computes anything. The boot-region checksum, the entry-set
//! checksum, the geometry shifts and the cluster chains are all `Cover::External`
//! or `Check::Cross` and live in `mod.rs`, because they need arithmetic on values
//! read from other records.

use super::types::{
    ALLOCATION_FLAGS, BITMAP_FLAGS, ENTRY_TYPES, FILE_ATTRIBUTES, VOLUME_FLAGS,
};
use blktamper_core::desc::{f, f_checksum, f_flags, f_reserved, fx};
use blktamper_core::{
    Check, ChecksumAlgo, ChecksumSpec, Cover, FieldDesc, FieldFlags, LinkDesc, LinkKind, Repr,
    StructDesc, Width,
};

/// One 32-byte directory entry. Every entry descriptor in this file is this size,
/// and the whole directory model depends on it (spec §6.2).
pub const ENTRY_SIZE: u64 = 32;

/// Sectors 0..=11 of a volume, and again at 12..=23 as the backup (spec §3).
pub const BOOT_REGION_SECTORS: u64 = 12;
/// Sector index, within a boot region, of the first extended boot sector.
pub const EXT_BOOT_FIRST_SECTOR: u64 = 1;
pub const EXT_BOOT_SECTOR_COUNT: u64 = 8;
/// Sector index of the OEM parameters sector.
pub const OEM_PARAM_SECTOR: u64 = 9;
/// Sector index of the reserved sector.
pub const RESERVED_SECTOR: u64 = 10;
/// Sector index of the boot checksum sector.
pub const BOOT_CHECKSUM_SECTOR: u64 = 11;
/// Sector index at which the backup boot region starts.
pub const BACKUP_BOOT_SECTOR: u64 = 12;

/// Number of 48-byte OEM parameter records in the OEM parameters sector (spec §3.3).
pub const OEM_PARAM_COUNT: u64 = 10;
pub const OEM_PARAM_SIZE: u64 = 48;

/// Byte offsets, within the main boot sector, that the boot-region checksum skips
/// (spec §3.4). These are `VolumeFlags` and `PercentInUse` — the two fields an
/// implementation may rewrite while mounted, which would otherwise invalidate the
/// checksum on every mount.
pub const CHECKSUM_SKIPPED_BYTES: [u32; 3] = [106, 107, 112];

/// The boot region checksum (spec §3.4), stored in sector 11 rather than in any
/// record, so the covered bytes are `Cover::External` and `mod.rs` supplies them.
///
/// The algorithm **skips** the excluded bytes; it does not treat them as zero.
/// `ChecksumAlgo::ExfatBootRegion` does that, but only when handed these ranges.
pub static BOOT_REGION_CHECKSUM: ChecksumSpec = ChecksumSpec {
    algo: ChecksumAlgo::ExfatBootRegion,
    cover: Cover::External,
    exclude: &[(CHECKSUM_SKIPPED_BYTES[0], 2), (CHECKSUM_SKIPPED_BYTES[2], 1)],
    doc: "Sectors 0..=10 of the boot region, skipping VolumeFlags (bytes 106..108) \
          and PercentInUse (byte 112) of the first sector only.",
};

/// The directory entry set checksum (spec §6.3.3). Covers every byte of every
/// record in the set except the two the checksum itself occupies, so the covered
/// bytes reach past the end of the record holding it: `Cover::External` again.
pub static ENTRY_SET_CHECKSUM: ChecksumSpec = ChecksumSpec {
    algo: ChecksumAlgo::ExfatEntrySet,
    cover: Cover::External,
    exclude: &[(2, 2)],
    doc: "All 32 x (secondary_count + 1) bytes of the entry set, skipping bytes 2 \
          and 3 of the primary entry.",
};

/// The up-case table checksum (spec §7.2.3). The table lives in the cluster heap,
/// so once again the bytes are not in the record that stores the checksum.
pub static UPCASE_CHECKSUM: ChecksumSpec = ChecksumSpec {
    algo: ChecksumAlgo::ExfatBootRegion,
    cover: Cover::External,
    exclude: &[],
    doc: "Every byte of the up-case table. The same rotate-right-and-add as the \
          boot region checksum, with nothing excluded.",
};

// ------------------------------------------------------------- boot sub-region

/// The main boot sector, and byte-for-byte the backup at sector 12 (spec §3.1).
///
/// The first 11 bytes are a deliberate trap for FAT drivers: a jump instruction and
/// an OEM name where a FAT BPB would be, followed by 53 bytes that *must* be zero
/// so that a FAT driver computing `BPB_BytsPerSec` sees zero and refuses the volume
/// instead of mounting it wrongly.
pub static MAIN_BOOT_SECTOR: StructDesc = StructDesc {
    name: "exFAT boot sector",
    size: Some(512),
    fields: &[
        fx(
            "jump_boot",
            0x00,
            Width::Bytes(3),
            Repr::Raw,
            "EB 76 90 — a jump to the boot code at offset 120. Present so a legacy \
             BIOS boot works and so the sector looks like a boot sector; carries no \
             filesystem meaning.",
            FieldFlags::LEGACY,
            &[Check::EqBytes(&[0xEB, 0x76, 0x90])],
        ),
        fx(
            "fs_name",
            0x03,
            Width::Ascii(8),
            Repr::Ascii,
            "\"EXFAT   \" with three trailing spaces. The only unambiguous signature \
             this filesystem has: FAT puts an arbitrary OEM name here and NTFS puts \
             \"NTFS    \", so this field alone separates the three.",
            FieldFlags::NONE,
            &[Check::EqBytes(b"EXFAT   ")],
        ),
        fx(
            "must_be_zero",
            0x0B,
            Width::Bytes(53),
            Repr::Raw,
            "Exactly where a FAT BPB lives. The spec requires zero here so that a \
             FAT driver reads BytesPerSector = 0 and declines the volume rather than \
             mounting it as a corrupt FAT. Non-zero content means either a FAT BPB \
             was written over an exFAT volume or the reverse.",
            FieldFlags::MUST_ZERO,
            &[Check::Zero],
        ),
        fx(
            "partition_offset",
            0x40,
            Width::U64le,
            Repr::Dec,
            "Media-relative sector offset of the partition holding this volume, as a \
             hint to boot code. Zero means 'no meaningful value, ignore me' — it does \
             not mean the volume starts at sector 0.",
            FieldFlags::OFTEN_ZERO,
            &[Check::Cross("partition_offset_agrees")],
        ),
        fx(
            "volume_length",
            0x48,
            Width::U64le,
            Repr::SizeSectors,
            "Size of the whole volume in sectors, including this boot region. Must \
             be at least 2^20 / bytes_per_sector so the volume can hold both boot \
             regions, a FAT and a cluster heap.",
            FieldFlags::NONE,
            &[Check::NonZero, Check::Cross("volume_fits_device")],
        ),
        fx(
            "fat_offset",
            0x50,
            Width::U32le,
            Repr::Dec,
            "Volume-relative sector offset of the first FAT. At least 24, because \
             sectors 0..23 are the two boot regions.",
            FieldFlags::POINTER,
            &[Check::Range(24, 0x00FF_FFFF)],
        ),
        fx(
            "fat_length",
            0x54,
            Width::U32le,
            Repr::Dec,
            "Length of one FAT in sectors. Must be large enough for cluster_count + 2 \
             32-bit entries; a shorter FAT means the tail of the heap has no entries \
             at all.",
            FieldFlags::NONE,
            &[Check::NonZero, Check::Cross("fat_covers_clusters")],
        ),
        fx(
            "cluster_heap_offset",
            0x58,
            Width::U32le,
            Repr::Dec,
            "Volume-relative sector offset of cluster 2 — exFAT has no cluster 0 or \
             1, exactly as FAT does not. Must lie past every FAT.",
            FieldFlags::POINTER,
            &[Check::NonZero, Check::Cross("heap_after_fats")],
        ),
        fx(
            "cluster_count",
            0x5C,
            Width::U32le,
            Repr::Dec,
            "Number of clusters in the heap. Capped at 0xFFFFFFF5 because the four \
             highest FAT values are reserved for the bad-cluster and end-of-chain \
             markers.",
            FieldFlags::NONE,
            &[Check::Cross("cluster_count_fits")],
        ),
        fx(
            "first_cluster_of_root",
            0x60,
            Width::U32le,
            Repr::Cluster,
            "Cluster holding the first directory entries of the root directory. The \
             root has no directory entry of its own, so its length comes only from \
             following the FAT chain.",
            FieldFlags::POINTER,
            &[Check::Cross("root_cluster_in_heap")],
        ),
        fx(
            "volume_serial_number",
            0x64,
            Width::U32le,
            Repr::Hex,
            "Identifies the volume; conventionally derived from the time of \
             formatting. Windows shows it as the volume serial number.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "fs_revision",
            0x68,
            Width::U16le,
            Repr::Hex,
            "Major version in the high byte, minor in the low: 0x0100 is revision \
             1.00, the only revision Microsoft has published.",
            FieldFlags::NONE,
            &[Check::Cross("fs_revision_known")],
        ),
        f_flags(
            "volume_flags",
            0x6A,
            Width::U16le,
            &VOLUME_FLAGS,
            "Mount state. Excluded from the boot-region checksum along with \
             percent_in_use, because a driver rewrites it on every mount and the \
             checksum would otherwise have to be recomputed each time.",
        ),
        fx(
            "bytes_per_sector_shift",
            0x6C,
            Width::U8,
            Repr::Dec,
            "log2 of the sector size, valid 9..=12 — 512 bytes to 4096. Validate \
             before shifting: a value of 200 read from a corrupt header shifts a \
             64-bit register into undefined territory.",
            FieldFlags::NONE,
            &[Check::Range(9, 12)],
        ),
        fx(
            "sectors_per_cluster_shift",
            0x6D,
            Width::U8,
            Repr::Dec,
            "log2 of the cluster size in sectors, valid 0..=(25 - \
             bytes_per_sector_shift) so a cluster never exceeds 32 MiB.",
            FieldFlags::NONE,
            &[Check::Range(0, 25), Check::Cross("cluster_size_limit")],
        ),
        fx(
            "number_of_fats",
            0x6E,
            Width::U8,
            Repr::Dec,
            "1 on every ordinary volume. 2 exists only for TexFAT, Microsoft's \
             transaction-safe variant, which no mainstream driver writes.",
            FieldFlags::NONE,
            &[Check::OneOf(&[1, 2])],
        ),
        fx(
            "drive_select",
            0x6F,
            Width::U8,
            Repr::Hex,
            "INT 13h drive number handed to the boot code; 0x80 conventionally. \
             Meaningless outside a BIOS boot.",
            FieldFlags::LEGACY,
            &[],
        ),
        fx(
            "percent_in_use",
            0x70,
            Width::U8,
            Repr::Dec,
            "Rounded percentage of clusters allocated, or 0xFF for 'not available'. \
             Advisory only — the allocation bitmap is authoritative — and excluded \
             from the boot checksum for the same reason volume_flags is.",
            FieldFlags::NONE,
            &[Check::Cross("percent_in_use_valid")],
        ),
        f_reserved("reserved", 0x71, 7, "Reserved by the specification; must be zero."),
        fx(
            "boot_code",
            0x78,
            Width::Bytes(390),
            Repr::Raw,
            "Bootstrap code, jumped to from offset 0. Opaque here: disassembly is out \
             of scope. mkfs.exfat leaves it zero.",
            FieldFlags::OPAQUE.or(FieldFlags::OFTEN_ZERO),
            &[],
        ),
        fx(
            "boot_signature",
            0x1FE,
            Width::U16le,
            Repr::Hex,
            "0xAA55, stored little-endian as 55 AA. Shared with MBR, FAT and NTFS, so \
             it confirms nothing on its own.",
            FieldFlags::NONE,
            &[Check::Eq(0xAA55)],
        ),
    ],
    checks: &[Check::Cross("boot_region_checksum")],
    links: &[
        LinkDesc::new("fat_offset", LinkKind::ToLbaRelative, "first FAT"),
        LinkDesc::new("cluster_heap_offset", LinkKind::ToLbaRelative, "cluster heap"),
        LinkDesc::new("first_cluster_of_root", LinkKind::ToCluster, "root directory"),
    ],
    spec: "exFAT File System Specification rev 1.00 §3.1",
};

/// One of the eight extended boot sectors, sectors 1..=8 of each boot region
/// (spec §3.2).
///
/// The payload is free for boot code; only the trailing signature is defined. Every
/// one of the eight carries it, so eight missing signatures is eight findings and
/// not one.
pub static EXT_BOOT_SECTOR: StructDesc = StructDesc {
    name: "exFAT extended boot sector",
    size: Some(512),
    fields: &[
        fx(
            "ext_boot_code",
            0x000,
            Width::Bytes(508),
            Repr::Raw,
            "Continuation of the boot code, or zero. The spec fixes only the length: \
             bytes_per_sector - 4. This descriptor assumes the 512-byte case; a \
             volume with a larger sector size is read by mod.rs, which sizes the \
             sector from bytes_per_sector_shift.",
            FieldFlags::OPAQUE.or(FieldFlags::OFTEN_ZERO),
            &[],
        ),
        fx(
            "ext_boot_signature",
            508,
            Width::U32le,
            Repr::Hex,
            "0xAA550000, stored as 00 00 55 AA. Note it is the last four bytes of the \
             sector, so on a 4096-byte sector it is not at offset 508.",
            FieldFlags::NONE,
            &[Check::Eq(0xAA55_0000)],
        ),
    ],
    checks: &[],
    spec: "exFAT File System Specification rev 1.00 §3.2",
    links: &[],
};

/// One of the ten OEM parameter records in sector 9 of a boot region (spec §3.3).
///
/// Microsoft defines only a flash-parameters record; everything else is vendor
/// space. mkfs.exfat writes 0xFF over the whole sector, which is neither the
/// all-zero "null" GUID the spec describes nor a defined parameter — worth showing
/// rather than hiding.
pub static OEM_PARAM: StructDesc = StructDesc {
    name: "exFAT OEM parameter",
    size: Some(48),
    fields: &[
        fx(
            "parameters_guid",
            0x00,
            Width::Guid,
            Repr::Guid,
            "Identifies which vendor record this is. All zero marks the record null. \
             0A0C7E46-3399-4021-90C8-FA6D389C4BA2 is Microsoft's flash parameters.",
            FieldFlags::NONE,
            &[],
        ),
        fx(
            "custom_defined",
            0x10,
            Width::Bytes(32),
            Repr::Raw,
            "Payload, interpreted only by whoever owns the GUID above.",
            FieldFlags::OPAQUE,
            &[],
        ),
    ],
    checks: &[],
    links: &[],
    spec: "exFAT File System Specification rev 1.00 §3.3",
};

// ------------------------------------------------------------ directory entries

/// The 0x81 allocation bitmap entry (spec §7.1).
///
/// One of the three critical primary entries the root directory must contain. The
/// bitmap it points at is the authority on which clusters are allocated; the FAT
/// only describes chains, and a contiguous file has no chain at all.
pub static ALLOCATION_BITMAP: StructDesc = StructDesc {
    name: "exFAT allocation bitmap entry",
    size: Some(32),
    fields: &[
        entry_type("0x81 when in use, 0x01 once deleted."),
        f_flags(
            "bitmap_flags",
            0x01,
            Width::U8,
            &BITMAP_FLAGS,
            "Which of the (at most two) allocation bitmaps this entry describes.",
        ),
        f_reserved("reserved", 0x02, 18, "Reserved by the specification; must be zero."),
        fx(
            "first_cluster",
            0x14,
            Width::U32le,
            Repr::Cluster,
            "First cluster of the bitmap. The bitmap is always contiguous in \
             practice, but nothing in the spec requires it, so the FAT still governs.",
            FieldFlags::POINTER,
            &[],
        ),
        fx(
            "data_length",
            0x18,
            Width::U64le,
            Repr::SizeBytes,
            "Length of the bitmap in bytes. Must be ceil(cluster_count / 8): one bit \
             per cluster, starting at cluster 2 in bit 0 of byte 0.",
            FieldFlags::NONE,
            &[Check::Cross("bitmap_length_matches_cluster_count")],
        ),
    ],
    checks: &[],
    links: &[LinkDesc::new("first_cluster", LinkKind::ToCluster, "allocation bitmap")],
    spec: "exFAT File System Specification rev 1.00 §7.1",
};

/// The 0x82 up-case table entry (spec §7.2).
pub static UPCASE_TABLE: StructDesc = StructDesc {
    name: "exFAT up-case table entry",
    size: Some(32),
    fields: &[
        entry_type("0x82 when in use, 0x02 once deleted."),
        f_reserved("reserved1", 0x01, 3, "Reserved by the specification; must be zero."),
        f_checksum(
            "table_checksum",
            0x04,
            Width::U32le,
            &UPCASE_CHECKSUM,
            "Rotate-right-and-add over every byte of the table. Verified in mod.rs \
             because the covered bytes are elsewhere on the device.",
        ),
        f_reserved("reserved2", 0x08, 12, "Reserved by the specification; must be zero."),
        fx(
            "first_cluster",
            0x14,
            Width::U32le,
            Repr::Cluster,
            "First cluster of the up-case table.",
            FieldFlags::POINTER,
            &[],
        ),
        fx(
            "data_length",
            0x18,
            Width::U64le,
            Repr::SizeBytes,
            "Length of the table in bytes. The table maps UTF-16 code units to their \
             upper-case form and may be run-length compressed, so this is not a fixed \
             size — it is 5836 bytes as mkfs.exfat writes it and 0x1FFFF*2 at most.",
            FieldFlags::NONE,
            &[],
        ),
    ],
    checks: &[],
    links: &[LinkDesc::new("first_cluster", LinkKind::ToCluster, "up-case table")],
    spec: "exFAT File System Specification rev 1.00 §7.2",
};

/// The 0x83 volume label entry (spec §7.3).
pub static VOLUME_LABEL: StructDesc = StructDesc {
    name: "exFAT volume label entry",
    size: Some(32),
    fields: &[
        entry_type("0x83 when in use, 0x03 once deleted. A label is cleared by \
                    clearing this bit, so the old label survives in the 22 bytes below."),
        fx(
            "character_count",
            0x01,
            Width::U8,
            Repr::Dec,
            "Length of the label in UTF-16 code units, 0..=11. Characters past this \
             count are not part of the label but are still on the disk.",
            FieldFlags::NONE,
            &[Check::Range(0, 11)],
        ),
        fx(
            "volume_label",
            0x02,
            Width::Utf16Le(22),
            Repr::Utf16Le,
            "Up to 11 UTF-16LE code units. No NUL terminator is required, which is \
             why character_count exists.",
            FieldFlags::NONE,
            &[],
        ),
        f_reserved("reserved", 0x18, 8, "Reserved by the specification; must be zero."),
    ],
    checks: &[],
    links: &[],
    spec: "exFAT File System Specification rev 1.00 §7.3",
};

/// The 0x85 file entry — the primary entry of every file and directory (spec §7.4).
///
/// It is the first record of an *entry set*: this entry, then `secondary_count`
/// secondaries, of which the first is a 0xC0 stream extension and the rest are
/// 0xC1 file names. The set is only meaningful as a whole, which is why mod.rs
/// presents it as one `Group`.
pub static FILE_ENTRY: StructDesc = StructDesc {
    name: "exFAT file entry",
    size: Some(32),
    fields: &[
        entry_type("0x85 when in use, 0x05 once deleted."),
        fx(
            "secondary_count",
            0x01,
            Width::U8,
            Repr::Dec,
            "Number of entries following this one in the set, 2..=18: one stream \
             extension plus 1..17 file name entries. Deleting a file leaves this \
             count intact, which is what makes a deleted set reconstructable.",
            FieldFlags::NONE,
            &[Check::Range(2, 18)],
        ),
        f_checksum(
            "set_checksum",
            0x02,
            Width::U16le,
            &ENTRY_SET_CHECKSUM,
            "Rotate-right-and-add over every byte of the whole entry set except these \
             two. Verified in mod.rs, which owns the other entries of the set.",
        ),
        f_flags(
            "file_attributes",
            0x04,
            Width::U16le,
            &FILE_ATTRIBUTES,
            "DOS-compatible attribute bits. The Directory bit is what decides whether \
             the clusters hold data or further entry sets.",
        ),
        f_reserved("reserved1", 0x06, 2, "Reserved by the specification; must be zero."),
        f(
            "create_timestamp",
            0x08,
            Width::U32le,
            Repr::ExfatTime,
            "Creation time, in DOS packed form: two-second resolution, years from \
             1980. Refined by create_10ms_increment and create_utc_offset.",
        ),
        f(
            "last_modified_timestamp",
            0x0C,
            Width::U32le,
            Repr::ExfatTime,
            "Last modification time, same packed form.",
        ),
        f(
            "last_accessed_timestamp",
            0x10,
            Width::U32le,
            Repr::ExfatTime,
            "Last access time. Has no 10ms companion field: exFAT records access time \
             only to two seconds.",
        ),
        fx(
            "create_10ms_increment",
            0x14,
            Width::U8,
            Repr::Dec,
            "0..=199 tens of milliseconds added to create_timestamp, recovering the \
             odd second the DOS format cannot store.",
            FieldFlags::NONE,
            &[Check::Range(0, 199)],
        ),
        fx(
            "last_modified_10ms_increment",
            0x15,
            Width::U8,
            Repr::Dec,
            "0..=199 tens of milliseconds added to last_modified_timestamp.",
            FieldFlags::NONE,
            &[Check::Range(0, 199)],
        ),
        f(
            "create_utc_offset",
            0x16,
            Width::U8,
            Repr::Hex,
            "Bit 7 set means the offset is recorded; bits 0..6 are a two's-complement \
             count of 15-minute steps from UTC. Zero means the timestamp's zone is \
             simply unknown, not UTC.",
        ),
        f(
            "last_modified_utc_offset",
            0x17,
            Width::U8,
            Repr::Hex,
            "UTC offset for last_modified_timestamp, same encoding.",
        ),
        f(
            "last_accessed_utc_offset",
            0x18,
            Width::U8,
            Repr::Hex,
            "UTC offset for last_accessed_timestamp, same encoding.",
        ),
        f_reserved("reserved2", 0x19, 7, "Reserved by the specification; must be zero."),
    ],
    checks: &[Check::Cross("entry_set_checksum")],
    links: &[],
    spec: "exFAT File System Specification rev 1.00 §7.4",
};

/// The 0xC0 stream extension entry (spec §7.6). Exactly one per entry set, and it
/// carries everything about where the file's bytes are.
pub static STREAM_EXTENSION: StructDesc = StructDesc {
    name: "exFAT stream extension entry",
    size: Some(32),
    fields: &[
        entry_type("0xC0 when in use, 0x40 once deleted."),
        f_flags(
            "general_secondary_flags",
            0x01,
            Width::U8,
            &ALLOCATION_FLAGS,
            "AllocationPossible and NoFatChain. Bits 2..7 are vendor space. NoFatChain \
             decides whether the cluster list comes from arithmetic or from the FAT.",
        ),
        f_reserved("reserved1", 0x02, 1, "Reserved by the specification; must be zero."),
        fx(
            "name_length",
            0x03,
            Width::U8,
            Repr::Dec,
            "Filename length in UTF-16 code units, 1..=255. It, not a NUL, bounds the \
             name — so the tail of the last file-name entry may hold bytes from an \
             older, longer name.",
            FieldFlags::NONE,
            &[Check::Range(1, 255)],
        ),
        fx(
            "name_hash",
            0x04,
            Width::U16le,
            Repr::Hex,
            "Rotate-right-and-add over the up-cased filename, so a directory search \
             can reject entries without decoding names. Verified in mod.rs against \
             the assembled name.",
            FieldFlags::DERIVED,
            &[],
        ),
        f_reserved("reserved2", 0x06, 2, "Reserved by the specification; must be zero."),
        fx(
            "valid_data_length",
            0x08,
            Width::U64le,
            Repr::SizeBytes,
            "How much of the allocation has ever been written. Bytes between this and \
             data_length are allocated but never written — and on a disk that was not \
             zeroed at format time they hold whatever was there before.",
            FieldFlags::NONE,
            &[Check::Cross("valid_data_within_data_length")],
        ),
        f_reserved("reserved3", 0x10, 4, "Reserved by the specification; must be zero."),
        fx(
            "first_cluster",
            0x14,
            Width::U32le,
            Repr::Cluster,
            "First cluster of the file's data, or 0 when the file is empty.",
            FieldFlags::POINTER,
            &[],
        ),
        fx(
            "data_length",
            0x18,
            Width::U64le,
            Repr::SizeBytes,
            "File size in bytes. For a directory this must be a whole number of \
             clusters.",
            FieldFlags::NONE,
            &[],
        ),
    ],
    checks: &[],
    links: &[LinkDesc::new("first_cluster", LinkKind::ToCluster, "file data")],
    spec: "exFAT File System Specification rev 1.00 §7.6",
};

/// The 0xC1 file name entry (spec §7.7): 15 UTF-16 code units, no length and no
/// terminator of its own.
///
/// This is the single most valuable record in the format for the question this tool
/// exists to answer. Deleting a file clears one bit here and changes nothing else,
/// so a 0x41 entry is a readable filename that a "secure delete" did not remove.
pub static FILE_NAME: StructDesc = StructDesc {
    name: "exFAT file name entry",
    size: Some(32),
    fields: &[
        entry_type("0xC1 when in use, 0x41 once deleted — still holding the name."),
        f_flags(
            "general_secondary_flags",
            0x01,
            Width::U8,
            &ALLOCATION_FLAGS,
            "Must be zero on a file name entry: the record allocates nothing. A set \
             AllocationPossible bit here is a sign the bytes are not really a name \
             entry.",
        ),
        fx(
            "file_name",
            0x02,
            Width::Utf16Le(30),
            Repr::Utf16Le,
            "15 UTF-16LE code units of the filename, unterminated. Only the stream \
             extension's name_length says how many of them belong to the name; the \
             rest are padding that may still hold an older name.",
            FieldFlags::NONE,
            &[],
        ),
    ],
    checks: &[],
    links: &[],
    spec: "exFAT File System Specification rev 1.00 §7.7",
};

/// The 0xA0 volume GUID entry (spec §7.5). A benign primary entry forming a
/// one-record set of its own, so it carries its own set checksum.
pub static VOLUME_GUID: StructDesc = StructDesc {
    name: "exFAT volume GUID entry",
    size: Some(32),
    fields: &[
        entry_type(
            "0xA0 when in use, 0x20 once deleted. mkfs.exfat writes this entry \
             already deleted, as a pre-allocated slot for a GUID nobody set.",
        ),
        fx(
            "secondary_count",
            0x01,
            Width::U8,
            Repr::Dec,
            "Always zero: the volume GUID entry set is this record alone.",
            FieldFlags::NONE,
            &[Check::Eq(0)],
        ),
        f_checksum(
            "set_checksum",
            0x02,
            Width::U16le,
            &ENTRY_SET_CHECKSUM,
            "Rotate-right-and-add over this entry's other 30 bytes.",
        ),
        f_flags(
            "general_primary_flags",
            0x04,
            Width::U16le,
            &ALLOCATION_FLAGS,
            "Must be zero: a volume GUID entry allocates no clusters.",
        ),
        fx(
            "volume_guid",
            0x06,
            Width::Guid,
            Repr::Guid,
            "A GUID identifying the volume, which must not be all zero. Rendered in \
             Microsoft's mixed-endian layout; note that exfatprogs' tune.exfat writes \
             these 16 bytes in RFC 4122 string order instead, so the same bytes read \
             differently under the two conventions — the raw column is the authority.",
            FieldFlags::NONE,
            &[],
        ),
        f_reserved("reserved", 0x16, 10, "Reserved by the specification; must be zero."),
    ],
    checks: &[Check::Cross("entry_set_checksum")],
    links: &[],
    spec: "exFAT File System Specification rev 1.00 §7.5",
};

/// Any 32-byte record whose type byte this module does not recognise.
///
/// Unknown is not the same as absent: vendor entries, TexFAT padding and plain
/// corruption all land here, and all three are worth seeing with their offsets.
pub static GENERIC_ENTRY: StructDesc = StructDesc {
    name: "exFAT directory entry",
    size: Some(32),
    fields: &[
        entry_type("Type byte of an entry this build has no descriptor for."),
        fx(
            "entry_data",
            0x01,
            Width::Bytes(31),
            Repr::Raw,
            "The remaining 31 bytes, uninterpreted. Bit 6 of the type byte says \
             whether they belong to a primary or a secondary record; bit 5 says \
             whether a driver may ignore the record.",
            FieldFlags::OPAQUE,
            &[],
        ),
    ],
    checks: &[],
    links: &[],
    spec: "exFAT File System Specification rev 1.00 §6.2",
};

/// The type byte is field 0 of every directory entry, always with the same
/// rendering. Only the documentation differs, so only that is a parameter.
const fn entry_type(doc: &'static str) -> FieldDesc {
    fx("entry_type", 0x00, Width::U8, Repr::Enum(&ENTRY_TYPES), doc, FieldFlags::NONE, &[])
}

/// Every descriptor this module defines, for the workspace-wide validation test.
pub static ALL: &[&StructDesc] = &[
    &MAIN_BOOT_SECTOR,
    &EXT_BOOT_SECTOR,
    &OEM_PARAM,
    &ALLOCATION_BITMAP,
    &UPCASE_TABLE,
    &VOLUME_LABEL,
    &FILE_ENTRY,
    &STREAM_EXTENSION,
    &FILE_NAME,
    &VOLUME_GUID,
    &GENERIC_ENTRY,
];
