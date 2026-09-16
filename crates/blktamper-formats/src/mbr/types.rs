//! MBR partition type bytes and status values.
//!
//! There is no authority for this table. It is convention, accreted since 1983 and
//! contradictory in places — the same byte means different things to different
//! operating systems. Entries below are transcribed from the public record
//! (util-linux's and gdisk's type lists, the Wikipedia MBR article, and the
//! historical Ralf Brown interrupt list), not copied from any implementation:
//! util-linux and gdisk are GPL-2 and this crate is MIT (ADR-001).
//!
//! Unknown bytes always still render as a number; the table only ever adds a name.

use blktamper_core::{EnumEntry, EnumTable};

pub static MBR_STATUS: EnumTable = EnumTable {
    name: "MBR partition status",
    entries: &[
        EnumEntry::num(0x00, "inactive", "not bootable"),
        EnumEntry::num(0x80, "active", "bootable; the conventional boot flag"),
    ],
};

pub static MBR_TYPES: EnumTable = EnumTable {
    name: "MBR partition type",
    entries: &[
        EnumEntry::num(0x00, "empty", "unused slot; the rest of the entry should be zero"),
        EnumEntry::num(0x01, "FAT12", "FAT12, CHS addressing"),
        EnumEntry::num(0x04, "FAT16 <32M", "FAT16 with fewer than 65536 sectors, CHS"),
        EnumEntry::num(0x05, "extended CHS", "extended partition, CHS addressing"),
        EnumEntry::num(0x06, "FAT16", "FAT16B, CHS addressing"),
        EnumEntry::num(0x07, "NTFS / exFAT / HPFS", "ambiguous: NTFS, exFAT, HPFS or QNX"),
        EnumEntry::num(0x0B, "FAT32 CHS", "FAT32 with CHS addressing"),
        EnumEntry::num(0x0C, "FAT32 LBA", "FAT32 with LBA addressing; the usual modern value"),
        EnumEntry::num(0x0E, "FAT16 LBA", "FAT16B with LBA addressing"),
        EnumEntry::num(0x0F, "extended LBA", "extended partition, LBA addressing"),
        EnumEntry::num(0x11, "hidden FAT12", "FAT12, hidden from DOS"),
        EnumEntry::num(0x12, "OEM / diagnostics", "vendor recovery or diagnostic partition"),
        EnumEntry::num(0x14, "hidden FAT16 <32M", "hidden FAT16, CHS"),
        EnumEntry::num(0x16, "hidden FAT16", "hidden FAT16B"),
        EnumEntry::num(0x17, "hidden NTFS/exFAT", "hidden NTFS, exFAT or HPFS"),
        EnumEntry::num(0x1B, "hidden FAT32", "hidden FAT32, CHS"),
        EnumEntry::num(0x1C, "hidden FAT32 LBA", "hidden FAT32, LBA"),
        EnumEntry::num(0x1E, "hidden FAT16 LBA", "hidden FAT16B, LBA"),
        EnumEntry::num(0x27, "Windows RE", "Windows recovery environment"),
        EnumEntry::num(0x39, "Plan 9", "Plan 9 from Bell Labs"),
        EnumEntry::num(0x3C, "PartitionMagic", "PartitionMagic recovery"),
        EnumEntry::num(0x42, "Windows LDM", "Windows dynamic disk / logical disk manager"),
        EnumEntry::num(0x63, "GNU HURD / SysV", "HURD, or a System V variant"),
        EnumEntry::num(0x80, "Minix", "old Minix"),
        EnumEntry::num(0x81, "Minix / old Linux", "Minix 1.4b+, or pre-1.0 Linux"),
        EnumEntry::num(0x82, "Linux swap", "Linux swap, or Solaris x86"),
        EnumEntry::num(0x83, "Linux", "any Linux filesystem: ext2/3/4, XFS, btrfs, F2FS"),
        EnumEntry::num(0x84, "hibernation", "OS/2 hidden C:, or Intel hibernation"),
        EnumEntry::num(0x85, "Linux extended", "Linux extended partition"),
        EnumEntry::num(0x86, "NTFS volume set", "legacy NTFS volume set"),
        EnumEntry::num(0x87, "NTFS volume set", "legacy NTFS volume set"),
        EnumEntry::num(0x88, "Linux plaintext", "Linux plaintext partition table"),
        EnumEntry::num(0x8E, "Linux LVM", "Linux logical volume manager"),
        EnumEntry::num(0xA0, "laptop hibernation", "vendor hibernation partition"),
        EnumEntry::num(0xA5, "FreeBSD", "FreeBSD slice"),
        EnumEntry::num(0xA6, "OpenBSD", "OpenBSD slice"),
        EnumEntry::num(0xA8, "Apple UFS", "Apple UFS"),
        EnumEntry::num(0xA9, "NetBSD", "NetBSD slice"),
        EnumEntry::num(0xAB, "Apple boot", "Apple boot partition"),
        EnumEntry::num(0xAF, "Apple HFS/HFS+", "Apple HFS or HFS+"),
        EnumEntry::num(0xB7, "BSDI", "BSDI filesystem"),
        EnumEntry::num(0xBE, "Solaris boot", "Solaris 8 boot partition"),
        EnumEntry::num(0xBF, "Solaris", "Solaris x86"),
        EnumEntry::num(0xEB, "BeOS BFS", "BeOS / Haiku BFS"),
        EnumEntry::num(0xEE, "GPT protective", "the whole disk is GPT; this MBR is a decoy"),
        EnumEntry::num(0xEF, "EFI System (MBR)", "EFI System Partition declared in an MBR"),
        EnumEntry::num(0xF2, "DOS secondary", "DOS 3.3+ secondary partition"),
        EnumEntry::num(0xFB, "VMware VMFS", "VMware filesystem"),
        EnumEntry::num(0xFC, "VMware swap", "VMware swap"),
        EnumEntry::num(0xFD, "Linux RAID", "Linux RAID autodetect"),
        EnumEntry::num(0xFE, "LANstep / IBM", "LANstep, or IBM IML"),
        EnumEntry::num(0xFF, "XENIX bad block", "XENIX bad block table"),
    ],
};

/// Type bytes that mean "this entry points at a chain of EBRs, not a filesystem".
pub const EXTENDED_TYPES: &[u64] = &[0x05, 0x0F, 0x85];

pub fn is_extended(type_byte: u64) -> bool {
    EXTENDED_TYPES.contains(&type_byte)
}

/// The protective entry a GPT disk puts in its MBR.
pub const TYPE_GPT_PROTECTIVE: u64 = 0xEE;

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::Value;

    #[test]
    fn the_types_we_actually_meet_are_named() {
        for (b, want) in [(0x0Cu64, "FAT32 LBA"), (0x07, "NTFS / exFAT / HPFS"), (0xEE, "GPT protective"), (0x83, "Linux")] {
            assert_eq!(MBR_TYPES.lookup(&Value::Uint(b)).unwrap().label, want);
        }
    }

    #[test]
    fn extended_types_are_recognised() {
        assert!(is_extended(0x05));
        assert!(is_extended(0x0F));
        assert!(is_extended(0x85));
        assert!(!is_extended(0x83));
    }

    #[test]
    fn the_table_has_no_duplicate_values() {
        let mut v: Vec<u64> = MBR_TYPES.entries.iter().map(|e| e.value).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "duplicate type byte in MBR_TYPES");
    }
}
