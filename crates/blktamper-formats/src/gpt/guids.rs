//! Well-known GPT partition type GUIDs.
//!
//! Unlike the MBR type byte, a type GUID is genuinely unique — vendors mint their
//! own — so this table is a naming convenience, never an authority. An unrecognised
//! GUID still renders as a GUID (`render::render_value` appends "(unknown)"), which
//! is the only behaviour that is honest on a disk we have never seen.
//!
//! Values were read back out of `sgdisk -i` after setting each type code on a
//! scratch image, then spot-checked against the fixture bytes with `xxd`: the EFI
//! System entry below is byte-for-byte what `sgdisk` wrote at offset 0x400 of
//! `tests/fixtures/gen/gpt-basic.img`. gdisk is GPL-2 and this crate is MIT, so the
//! *facts* are transcribed and the labels and prose are ours (ADR-001).

use blktamper_core::{EnumEntry, EnumTable};

/// The 16 on-disk bytes of a GUID, written the way a human reads it.
///
/// GPT stores a GUID **mixed-endian** (UEFI 5.3.1, following RFC 4122 as Microsoft
/// implements it): `time_low`, `time_mid` and `time_hi_and_version` are
/// little-endian; `clock_seq` and `node` are stored in the order they are printed.
/// Doing the swap here, once, is what lets every row below be proof-read straight
/// against `sgdisk -i` output. Getting it wrong scrambles every GUID on screen in a
/// way that still looks like a GUID.
pub const fn guid(d1: u32, d2: u16, d3: u16, d4: u16, node: u64) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    let d = d4.to_be_bytes();
    // `node` is 48 bits carried in a u64; the top two bytes are padding.
    let e = node.to_be_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], e[2], e[3], e[4], e[5], e[6], e[7]]
}

/// An entry that has never been used, or has been released. UEFI 5.3.3: a zero type
/// GUID means the slot is unused — and says nothing at all about the other 112 bytes.
pub const UNUSED: [u8; 16] = [0; 16];

/// The EFI System Partition. Verified against `gpt-basic.img` offset 0x400:
/// `28 73 2a c1 1f f8 d2 11 ba 4b 00 a0 c9 3e c9 3b`.
pub const EFI_SYSTEM: [u8; 16] = guid(0xC12A_7328, 0xF81F, 0x11D2, 0xBA4B, 0x00A0_C93E_C93B);

/// The type every Windows volume and most removable media carry.
pub const MS_BASIC_DATA: [u8; 16] = guid(0xEBD0_A0A2, 0xB9E5, 0x4433, 0x87C0, 0x68B6_B726_99C7);

/// Generic Linux data. What `mkfs.ext4` on a bare partition ends up under.
pub const LINUX_FILESYSTEM: [u8; 16] = guid(0x0FC6_3DAF, 0x8483, 0x4772, 0x8E79, 0x3D69_D847_7DE4);

/// A LUKS container. Worth naming in code because it is the case where a user is
/// most likely to be staring at this tool at 3am.
pub const LINUX_LUKS: [u8; 16] = guid(0xCA7D_7CCB, 0x63ED, 0x4C53, 0x861C, 0x1742_5360_59CC);

/// Name for a type GUID, or `None` when the table does not know it.
pub fn type_label(g: &[u8; 16]) -> Option<&'static str> {
    PARTITION_TYPES.entries.iter().find(|e| e.bytes == g.as_slice()).map(|e| e.label)
}

/// True when the slot is declared unused (UEFI 5.3.3). Note what this does *not*
/// mean: the name, the unique GUID and the LBAs may still hold a deleted partition.
pub fn is_unused(g: &[u8; 16]) -> bool {
    g.iter().all(|&b| b == 0)
}

pub static PARTITION_TYPES: EnumTable = EnumTable {
    name: "GPT partition type GUID",
    entries: &[
        EnumEntry::guid(
            &UNUSED,
            "unused",
            "Slot is not in use. UEFI defines only the type GUID as zero — the rest \
             of the 128 bytes is whatever was there before.",
        ),
        // ---- firmware and boot ----
        EnumEntry::guid(
            &EFI_SYSTEM,
            "EFI System",
            "The EFI System Partition: a FAT32 (or FAT16) volume holding boot \
             loaders, read by firmware before any OS runs. UEFI 13.3.1.",
        ),
        EnumEntry::guid(
            &guid(0x024D_EE41, 0x33E7, 0x11D3, 0x9D69, 0x0008_C781_F39F),
            "MBR partition scheme",
            "Marks a region that is itself described by an MBR. Rare, and a sign of \
             a nested or hybrid layout.",
        ),
        EnumEntry::guid(
            &guid(0x2168_6148, 0x6449, 0x6E6F, 0x744E, 0x6565_6445_4649),
            "BIOS boot",
            "Somewhere for GRUB's stage-1.5 to live on a GPT disk booted by a legacy \
             BIOS. The ASCII of the GUID reads \"Hah!IdontNeedEFI\".",
        ),
        EnumEntry::guid(
            &guid(0xBC13_C2FF, 0x59E6, 0x4262, 0xA352, 0xB275_FD6F_7172),
            "Linux extended boot (XBOOTLDR)",
            "The boot-loader spec's /boot partition, held separately from the ESP.",
        ),
        EnumEntry::guid(
            &guid(0xD3BF_E2DE, 0x3DAF, 0x11DF, 0xBA40, 0xE3A5_56D8_9593),
            "Intel Rapid Start",
            "Intel Fast Flash / Rapid Start hibernation cache.",
        ),
        EnumEntry::guid(
            &guid(0x9E1A_2D38, 0xC612, 0x4316, 0xAA26, 0x8B49_521E_5A8B),
            "PowerPC PReP boot",
            "PReP boot partition on IBM PowerPC hardware.",
        ),
        EnumEntry::guid(
            &guid(0x7412_F7D5, 0xA156, 0x4B13, 0x81DC, 0x8671_7492_9325),
            "ONIE boot",
            "Open Network Install Environment boot partition on network switches.",
        ),
        // ---- Microsoft ----
        EnumEntry::guid(
            &MS_BASIC_DATA,
            "Microsoft basic data",
            "NTFS, exFAT or FAT as Windows sees it. The default type for anything \
             Windows formats, and for most USB sticks.",
        ),
        EnumEntry::guid(
            &guid(0xE3C9_E316, 0x0B5C, 0x4DB8, 0x817D, 0xF92D_F002_15AE),
            "Microsoft reserved (MSR)",
            "Scratch space Windows reserves on every disk it initialises. Contains \
             no filesystem, which is why it looks empty.",
        ),
        EnumEntry::guid(
            &guid(0xDE94_BBA4, 0x06D1, 0x4D40, 0xA16A, 0xBFD5_0179_D6AC),
            "Windows Recovery",
            "Windows Recovery Environment (WinRE) image.",
        ),
        EnumEntry::guid(
            &guid(0x5808_C8AA, 0x7E8F, 0x42E0, 0x85D2, 0xE1E9_0434_CFB3),
            "Windows LDM metadata",
            "Logical Disk Manager metadata for a Windows dynamic disk.",
        ),
        EnumEntry::guid(
            &guid(0xAF9B_60A0, 0x1431, 0x4F62, 0xBC68, 0x3311_714A_69AD),
            "Windows LDM data",
            "Logical Disk Manager data volume; the real layout lives in the LDM \
             database, not in this table.",
        ),
        EnumEntry::guid(
            &guid(0xE75C_AF8F, 0xF680, 0x4CEE, 0xAFA3, 0xB001_E56E_FC2D),
            "Windows Storage Spaces",
            "A member of a Storage Spaces pool.",
        ),
        EnumEntry::guid(
            &guid(0x558D_43C5, 0xA1AC, 0x43C0, 0xAAC8, 0xD147_2B29_23D1),
            "Microsoft Storage Replica",
            "Storage Replica log volume.",
        ),
        // ---- Linux ----
        EnumEntry::guid(
            &LINUX_FILESYSTEM,
            "Linux filesystem",
            "Generic Linux data: ext2/3/4, XFS, btrfs, F2FS. The default `sgdisk` \
             type, so it carries no information about the filesystem inside.",
        ),
        EnumEntry::guid(
            &guid(0x0657_FD6D, 0xA4AB, 0x43C4, 0x84E5, 0x0933_C84B_4F4F),
            "Linux swap",
            "Swap area. Forensically interesting out of proportion to its size.",
        ),
        EnumEntry::guid(
            &guid(0xE6D6_D379, 0xF507, 0x44C2, 0xA23C, 0x238F_2A3D_F928),
            "Linux LVM",
            "LVM physical volume; the volume group's layout is in the PV metadata, \
             not here.",
        ),
        EnumEntry::guid(
            &LINUX_LUKS,
            "Linux LUKS",
            "A LUKS container. The header at the start of the partition says LUKS1 \
             or LUKS2 and holds the key slots.",
        ),
        EnumEntry::guid(
            &guid(0x7FFE_C5C9, 0x2D00, 0x49B7, 0x8941, 0x3EA1_0A55_86B7),
            "Linux dm-crypt",
            "Plain dm-crypt, with no on-disk header at all.",
        ),
        EnumEntry::guid(
            &guid(0xA19D_880F, 0x05FC, 0x4D3B, 0xA006, 0x743F_0F84_911E),
            "Linux RAID",
            "Linux software RAID member; the md superblock is inside the partition.",
        ),
        EnumEntry::guid(
            &guid(0x933A_C7E1, 0x2EB4, 0x4F13, 0xB844, 0x0E14_E2AE_F915),
            "Linux /home",
            "Discoverable Partitions Spec: mounted at /home.",
        ),
        EnumEntry::guid(
            &guid(0x3B8F_8425, 0x20E0, 0x4F3B, 0x907F, 0x1A25_A76F_98E8),
            "Linux /srv",
            "Discoverable Partitions Spec: mounted at /srv.",
        ),
        EnumEntry::guid(
            &guid(0x4D21_B016, 0xB534, 0x45C2, 0xA9FB, 0x5C16_E091_FD2D),
            "Linux /var",
            "Discoverable Partitions Spec: mounted at /var.",
        ),
        EnumEntry::guid(
            &guid(0x7EC6_F557, 0x3BC5, 0x4ACA, 0xB293, 0x16EF_5DF6_39D1),
            "Linux /var/tmp",
            "Discoverable Partitions Spec: mounted at /var/tmp.",
        ),
        EnumEntry::guid(
            &guid(0x773F_91EF, 0x66D4, 0x49B5, 0xBD83, 0xD683_BF40_AD16),
            "Linux per-user home",
            "systemd-homed portable home directory.",
        ),
        EnumEntry::guid(
            &guid(0x4F68_BCE3, 0xE8CD, 0x4DB1, 0x96E7, 0xFBCA_F984_B709),
            "Linux root (x86-64)",
            "Discoverable Partitions Spec: the root filesystem, architecture x86-64.",
        ),
        EnumEntry::guid(
            &guid(0x4447_9540, 0xF297, 0x41B2, 0x9AF7, 0xD131_D5F0_458A),
            "Linux root (x86)",
            "Discoverable Partitions Spec: root filesystem, architecture i386.",
        ),
        EnumEntry::guid(
            &guid(0xB921_B045, 0x1DF0, 0x41C3, 0xAF44, 0x4C6F_280D_3FAE),
            "Linux root (ARM64)",
            "Discoverable Partitions Spec: root filesystem, architecture aarch64.",
        ),
        EnumEntry::guid(
            &guid(0x69DA_D710, 0x2CE4, 0x4E3C, 0xB16C, 0x21A1_D49A_BED3),
            "Linux root (ARM32)",
            "Discoverable Partitions Spec: root filesystem, architecture arm.",
        ),
        EnumEntry::guid(
            &guid(0x8484_680C, 0x9521, 0x48C6, 0x9C11, 0xB072_0656_F69E),
            "Linux /usr (x86-64)",
            "Discoverable Partitions Spec: /usr, architecture x86-64.",
        ),
        EnumEntry::guid(
            &guid(0x8DA6_3339, 0x0007, 0x60C0, 0xC436, 0x083A_C823_0908),
            "Linux reserved",
            "Reserved by the Linux GPT type registry; should not appear in use.",
        ),
        // ---- Apple ----
        EnumEntry::guid(
            &guid(0x4846_5300, 0x0000, 0x11AA, 0xAA11, 0x0030_6543_ECAC),
            "Apple HFS+",
            "HFS+ volume. The GUID's first group is the ASCII \"HFS\\0\".",
        ),
        EnumEntry::guid(
            &guid(0x7C34_57EF, 0x0000, 0x11AA, 0xAA11, 0x0030_6543_ECAC),
            "Apple APFS",
            "APFS container. One container holds many volumes, so the partition \
             table says nothing about how many filesystems are inside.",
        ),
        EnumEntry::guid(
            &guid(0x5546_5300, 0x0000, 0x11AA, 0xAA11, 0x0030_6543_ECAC),
            "Apple UFS",
            "Legacy Apple UFS volume.",
        ),
        EnumEntry::guid(
            &guid(0x5241_4944, 0x0000, 0x11AA, 0xAA11, 0x0030_6543_ECAC),
            "Apple RAID",
            "Apple software RAID member.",
        ),
        EnumEntry::guid(
            &guid(0x5241_4944, 0x5F4F, 0x11AA, 0xAA11, 0x0030_6543_ECAC),
            "Apple RAID offline",
            "Apple software RAID member, marked offline.",
        ),
        EnumEntry::guid(
            &guid(0x426F_6F74, 0x0000, 0x11AA, 0xAA11, 0x0030_6543_ECAC),
            "Apple Recovery HD",
            "The macOS recovery partition. GUID reads \"Boot\".",
        ),
        EnumEntry::guid(
            &guid(0x4C61_6265, 0x6C00, 0x11AA, 0xAA11, 0x0030_6543_ECAC),
            "Apple label",
            "Apple partition label. GUID reads \"Label\".",
        ),
        EnumEntry::guid(
            &guid(0x5374_6F72, 0x6167, 0x11AA, 0xAA11, 0x0030_6543_ECAC),
            "Apple Core Storage",
            "Core Storage / FileVault logical volume family.",
        ),
        // ---- BSD ----
        EnumEntry::guid(
            &guid(0x516E_7CB4, 0x6ECF, 0x11D6, 0x8FF8, 0x0002_2D09_712B),
            "FreeBSD disklabel",
            "A FreeBSD slice containing its own disklabel, which subdivides it again.",
        ),
        EnumEntry::guid(
            &guid(0x83BD_6B9D, 0x7F41, 0x11DC, 0xBE0B, 0x0015_60B8_4F0F),
            "FreeBSD boot",
            "FreeBSD boot partition.",
        ),
        EnumEntry::guid(
            &guid(0x516E_7CB5, 0x6ECF, 0x11D6, 0x8FF8, 0x0002_2D09_712B),
            "FreeBSD swap",
            "FreeBSD swap area.",
        ),
        EnumEntry::guid(
            &guid(0x516E_7CB6, 0x6ECF, 0x11D6, 0x8FF8, 0x0002_2D09_712B),
            "FreeBSD UFS",
            "FreeBSD UFS/UFS2 filesystem.",
        ),
        EnumEntry::guid(
            &guid(0x516E_7CBA, 0x6ECF, 0x11D6, 0x8FF8, 0x0002_2D09_712B),
            "FreeBSD ZFS",
            "FreeBSD ZFS vdev.",
        ),
        EnumEntry::guid(
            &guid(0x49F4_8D5A, 0xB10E, 0x11DC, 0xB99B, 0x0019_D187_9648),
            "NetBSD FFS",
            "NetBSD fast filesystem.",
        ),
        EnumEntry::guid(
            &guid(0x49F4_8D32, 0xB10E, 0x11DC, 0xB99B, 0x0019_D187_9648),
            "NetBSD swap",
            "NetBSD swap area.",
        ),
        EnumEntry::guid(
            &guid(0x824C_C7A0, 0x36A8, 0x11E3, 0x890A, 0x9525_19AD_3F61),
            "OpenBSD data",
            "An OpenBSD slice; its disklabel subdivides it further.",
        ),
        // ---- Solaris, ChromeOS, hypervisors, storage ----
        EnumEntry::guid(
            &guid(0x6A82_CB45, 0x1DD2, 0x11B2, 0x99A6, 0x0800_2073_6631),
            "Solaris boot",
            "Solaris boot partition.",
        ),
        EnumEntry::guid(
            &guid(0x6A85_CF4D, 0x1DD2, 0x11B2, 0x99A6, 0x0800_2073_6631),
            "Solaris root",
            "Solaris root filesystem.",
        ),
        EnumEntry::guid(
            &guid(0x6A89_8CC3, 0x1DD2, 0x11B2, 0x99A6, 0x0800_2073_6631),
            "Solaris /usr or Apple ZFS",
            "One GUID, two meanings: Solaris /usr, and ZFS as Apple writes it. \
             Ambiguity is in the registry itself, not in this reader.",
        ),
        EnumEntry::guid(
            &guid(0xFE3A_2A5D, 0x4F32, 0x41A7, 0xB725, 0xACCC_3285_A309),
            "ChromeOS kernel",
            "ChromeOS kernel partition. Its priority/tries/successful counters live \
             in attribute bits 48..=55, which is why those bits are type-specific.",
        ),
        EnumEntry::guid(
            &guid(0x3CB8_E202, 0x3B7E, 0x47DD, 0x8A3C, 0x7FF2_A13C_FCEC),
            "ChromeOS rootfs",
            "ChromeOS root filesystem, verified by dm-verity.",
        ),
        EnumEntry::guid(
            &guid(0x2E0A_753D, 0x9E48, 0x43B0, 0x8337, 0xB151_92CB_1B5E),
            "ChromeOS reserved",
            "Reserved by ChromeOS.",
        ),
        EnumEntry::guid(
            &guid(0xAA31_E02A, 0x400F, 0x11DB, 0x9590, 0x000C_2911_D1B8),
            "VMware VMFS",
            "VMware ESXi VMFS datastore.",
        ),
        EnumEntry::guid(
            &guid(0x9198_EFFC, 0x31C0, 0x11DB, 0x8F78, 0x000C_2911_D1B8),
            "VMware reserved",
            "VMware ESXi reserved area.",
        ),
        EnumEntry::guid(
            &guid(0x4FBD_7E29, 0x9D25, 0x41B8, 0xAFD0, 0x062C_0CEF_F05D),
            "Ceph OSD",
            "Ceph object storage daemon data.",
        ),
        EnumEntry::guid(
            &guid(0x45B0_969E, 0x9B03, 0x4F30, 0xB4C6, 0xB4B8_0CEF_F106),
            "Ceph journal",
            "Ceph OSD journal.",
        ),
        EnumEntry::guid(
            &guid(0xC918_18F9, 0x8025, 0x47AF, 0x89D2, 0xF030_D700_0C2C),
            "Plan 9",
            "Plan 9 from Bell Labs partition.",
        ),
        EnumEntry::guid(
            &guid(0x37AF_FC90, 0xEF7D, 0x4E96, 0x91C3, 0x2D7A_E055_B174),
            "IBM GPFS",
            "IBM General Parallel File System member.",
        ),
        EnumEntry::guid(
            &guid(0x2568_845D, 0x2332, 0x4675, 0xBC39, 0x8FA5_A474_8D15),
            "Android bootloader",
            "Android bootloader partition; Android devices define a dozen more types \
             in the same family.",
        ),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::Value;

    #[test]
    fn mixed_endian_matches_the_bytes_sgdisk_wrote() {
        // gpt-basic.img offset 0x400, confirmed with `xxd -s 1024 -l 16`:
        // 28 73 2a c1 1f f8 d2 11 ba 4b 00 a0 c9 3e c9 3b
        // and `sgdisk -i 1` calls it C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
        assert_eq!(
            EFI_SYSTEM,
            [
                0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9,
                0x3E, 0xC9, 0x3B
            ]
        );
        assert_eq!(
            blktamper_core::value::format_guid_mixed_endian(&EFI_SYSTEM),
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
        );
    }

    #[test]
    fn the_table_is_reachable_by_guid_value() {
        assert_eq!(
            PARTITION_TYPES.lookup(&Value::Guid(MS_BASIC_DATA)).map(|e| e.label),
            Some("Microsoft basic data")
        );
        assert_eq!(type_label(&LINUX_LUKS), Some("Linux LUKS"));
        assert_eq!(type_label(&[0xAB; 16]), None);
    }

    #[test]
    fn the_table_has_no_duplicate_guids() {
        let mut v: Vec<&[u8]> = PARTITION_TYPES.entries.iter().map(|e| e.bytes).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "duplicate GUID in PARTITION_TYPES");
        assert!(n >= 40, "the table is meant to cover at least 40 types, has {n}");
    }

    #[test]
    fn every_entry_is_sixteen_bytes() {
        for e in PARTITION_TYPES.entries {
            assert_eq!(e.bytes.len(), 16, "{} is not 16 bytes", e.label);
            assert!(!e.doc.trim().is_empty(), "{} has no doc", e.label);
        }
    }

    #[test]
    fn unused_is_all_zero_and_nothing_else_is() {
        assert!(is_unused(&UNUSED));
        assert!(!is_unused(&EFI_SYSTEM));
    }
}
