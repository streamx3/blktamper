//! (compiled only with the `fat` feature)
#![cfg(feature = "fat")]

//! FAT32 against real images made by `mkfs.vfat` and populated with `mtools`.
//!
//! Every number asserted here was read out of the image with an independent tool
//! before it was written down — `fsck.vfat -nv` for the geometry, `mdir` for the live
//! directory listing, `xxd` for the raw records, and a short Python transcription of
//! the fatgen §7.2 checksum for the long-filename sums. Asserting our own parser's
//! output against itself would prove nothing.
//!
//! `fsck.vfat -nv` on the partition reports, verbatim:
//!
//! ```text
//! 512 bytes per logical sector / 512 bytes per cluster / 32 reserved sectors
//! First FAT starts at byte 16384 (sector 32)
//! 2 FATs, 32 bit entries / 508416 bytes per FAT (= 993 sectors)
//! Root directory start at cluster 2 / Data area starts at byte 1033216 (sector 2018)
//! 127006 data clusters / 129024 sectors total / 6 files, 493/127006 clusters
//! ```

mod common;

use blktamper_core::{BlockSource, Children, FormatProbe, Node, Status};
use blktamper_formats::fat::{self, FatKind, FatProbe};
use common::*;

/// The FAT32 volume in `mbr-fat32.img` starts at LBA 2048.
const AT: u64 = 1 << 20;

/// `fsck.vfat`: "Data area starts at byte 1033216", relative to the volume.
const DATA_START: u64 = AT + 1_033_216;
/// `fsck.vfat`: "First FAT starts at byte 16384".
const FAT0: u64 = AT + 16_384;

fn kids(n: &Node, src: &dyn BlockSource) -> Vec<Node> {
    fat::expand(n, src)
}

/// Find a child by label prefix among a node's (possibly lazy) children.
fn child(n: &Node, src: &dyn BlockSource, prefix: &str) -> Node {
    kids(n, src)
        .into_iter()
        .find(|k| k.label.starts_with(prefix))
        .unwrap_or_else(|| panic!("no child starting with {prefix:?} under {:?}", n.label))
}

fn root_dir(root: &Node, src: &dyn BlockSource) -> Node {
    child(root, src, "root directory")
}

#[test]
fn reads_the_boot_sector_mkfs_vfat_wrote() {
    with_fixture("mbr-fat32.img", |src| {
        assert!(FatProbe.probe(&*src, AT) >= 80, "a clean FAT32 volume must be identified");
        let root = FatProbe.open(src.clone(), AT).root();
        assert_tree_invariants(&root);
        assert_eq!(root.label, "FAT32 volume");

        let boot = root.find_child("boot sector").expect("boot sector");
        let bpb = boot.find_child("FAT BPB").expect("BPB");
        // Every one of these is a line of `fsck.vfat -nv` output.
        assert_eq!(u64_at(bpb, &["bytes_per_sector"]), Some(512));
        assert_eq!(u64_at(bpb, &["sectors_per_cluster"]), Some(1));
        assert_eq!(u64_at(bpb, &["reserved_sectors"]), Some(32));
        assert_eq!(u64_at(bpb, &["num_fats"]), Some(2));
        assert_eq!(u64_at(bpb, &["media"]), Some(0xF8));
        assert_eq!(u64_at(bpb, &["hidden_sectors"]), Some(0));
        assert_eq!(u64_at(bpb, &["total_sectors_32"]), Some(129_024));
        // FAT32 puts its size in the 32-bit field and leaves both 16-bit ones zero.
        assert_eq!(u64_at(bpb, &["fat_size_16"]), Some(0));
        assert_eq!(u64_at(bpb, &["total_sectors_16"]), Some(0));
        assert_eq!(u64_at(bpb, &["root_entries"]), Some(0));

        let ebpb = boot.find_child("FAT32 EBPB").expect("EBPB");
        assert_eq!(u64_at(ebpb, &["fat_size_32"]), Some(993));
        assert_eq!(u64_at(ebpb, &["root_cluster"]), Some(2));
        assert_eq!(u64_at(ebpb, &["fs_info"]), Some(1));
        assert_eq!(u64_at(ebpb, &["backup_boot_sector"]), Some(6));
        assert_eq!(u64_at(ebpb, &["boot_signature"]), Some(0x29));
        assert_eq!(u64_at(ebpb, &["fs_version"]), Some(0));
        // `mkfs.vfat -i 1234ABCD`, and `mdir` shows it back as "1234-ABCD".
        assert_eq!(u64_at(ebpb, &["volume_id"]), Some(0x1234_ABCD));
        assert_eq!(text_at(ebpb, &["volume_label"]).as_deref(), Some("BLKTAMPER"));
        assert_eq!(text_at(ebpb, &["fs_type"]).as_deref(), Some("FAT32"));

        // The three pointers out of the EBPB resolve to real byte offsets: two
        // sector numbers measured from the volume start, and one cluster number
        // measured from the data region.
        let follow = |field: &str| -> (u64, Option<u64>) {
            let n = ebpb.find_child(field).unwrap();
            let l = n.links.first().unwrap_or_else(|| panic!("{field} must be followable"));
            (l.raw, l.resolved)
        };
        assert_eq!(follow("fs_info"), (1, Some(AT + 512)));
        assert_eq!(follow("backup_boot_sector"), (6, Some(AT + 6 * 512)));
        assert_eq!(follow("root_cluster"), (2, Some(DATA_START)));

        // 55 AA, and nothing in the boot sector is wrong.
        assert_eq!(boot.deep_status(), Status::Ok, "a clean boot sector must report clean");
    });
}

#[test]
fn derives_the_geometry_fsck_vfat_reports() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let g = root.find_child("geometry (computed)").expect("geometry");

        assert_eq!(text_at(g, &["fat type"]).as_deref(), Some("FAT32"));
        // "127006 data clusters"
        assert_eq!(u64_at(g, &["cluster count"]), Some(127_006));
        assert_eq!(u64_at(g, &["data sectors"]), Some(127_006));
        assert_eq!(u64_at(g, &["fat size (sectors)"]), Some(993));
        assert_eq!(u64_at(g, &["total sectors"]), Some(129_024));
        assert_eq!(u64_at(g, &["root dir sectors"]), Some(0), "FAT32 has no fixed root");
        assert_eq!(u64_at(g, &["bytes per cluster"]), Some(512));
        // "First FAT starts at byte 16384" and "Data area starts at byte 1033216",
        // both relative to the volume, which begins at 1 MiB on this image.
        assert_eq!(u64_at(g, &["fat #0 offset"]), Some(FAT0));
        assert_eq!(u64_at(g, &["cluster 2 offset"]), Some(DATA_START));

        // And the same numbers reached without building a tree.
        let geom = fat::FatReader::new(src, AT).geometry();
        assert_eq!(geom.kind, FatKind::Fat32);
        assert_eq!(geom.cluster_count, 127_006);
        assert_eq!(geom.data_start, DATA_START);
        assert_eq!(geom.fat_start, FAT0);
        // FAT #1 sits one whole table further on: 993 * 512 = 508416 bytes.
        assert_eq!(geom.fat_offset(1), Some(FAT0 + 508_416));
        assert_eq!(geom.cluster_to_byte(2), Some(DATA_START));
    });
}

#[test]
fn reads_the_fsinfo_hints_and_they_match_what_fsck_counted() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let fsi = root.find_child("FAT32 FSInfo @sector 1").expect("FSInfo");
        assert_eq!(fsi.extent.first().unwrap().start_byte(), AT + 512);

        // "RRaA" ... "rrAa" ... 00 00 55 AA, straight out of xxd.
        assert_eq!(u64_at(fsi, &["lead_sig"]), Some(0x4161_5252));
        assert_eq!(u64_at(fsi, &["struct_sig"]), Some(0x6141_7272));
        assert_eq!(u64_at(fsi, &["trail_sig"]), Some(0xAA55_0000));

        // fsck.vfat counted "493/127006 clusters" in use; the hint agrees exactly.
        assert_eq!(u64_at(fsi, &["free_count"]), Some(126_513));
        assert_eq!(127_006 - 126_513, 493);
        assert_eq!(u64_at(fsi, &["next_free"]), Some(593));
        assert_eq!(fsi.deep_status(), Status::Ok, "a consistent FSInfo raises nothing");
    });
}

#[test]
fn the_two_allocation_tables_are_identical() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let area = child(&root, &*src, "FAT area");
        let mirror = child(&area, &*src, "mirror check");
        // Nothing is read until somebody asks: each table is half a megabyte.
        assert!(matches!(mirror.children, Children::Lazy(_)));

        let cmp = &kids(&mirror, &*src)[0];
        assert_eq!(cmp.label, "FAT #0 vs FAT #1");
        // `cmp` on the two 508416-byte ranges reports no difference.
        let d = cmp.derived.as_ref().expect("a mirror verdict");
        assert!(d.matches, "the fixture's FATs are byte-identical");
        assert!(d.how.contains("508416"), "must say it compared the whole table: {}", d.how);
        assert!(cmp.diags.iter().any(|x| x.message.contains("agree")));

        // Both copies are pointed at, so the hex pane can highlight either.
        let spans = cmp.extent.spans();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start_byte(), FAT0);
        assert_eq!(spans[1].start_byte(), FAT0 + 508_416);
    });
}

#[test]
fn the_backup_boot_sector_is_the_primary_again() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let backup = root.find_child("backup boot sector @sector 6").expect("backup");
        // backup_boot_sector = 6, so six sectors past the volume start.
        assert_eq!(backup.extent.first().unwrap().start_byte(), AT + 6 * 512);
        assert!(backup.diags.iter().any(|d| d.message.contains("identical to the primary")));
        // It must not be measured from its own offset and then reported as
        // overrunning the device.
        assert_eq!(backup.deep_status(), Status::Info);
        let ebpb = backup.find_child("FAT32 EBPB").unwrap();
        assert_eq!(u64_at(ebpb, &["volume_id"]), Some(0x1234_ABCD));
    });
}

#[test]
fn lists_the_root_directory_mdir_shows() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let dir = root_dir(&root, &*src);
        assert_eq!(dir.extent.first().unwrap().start_byte(), DATA_START);
        let entries = kids(&dir, &*src);
        let labels: Vec<String> = entries.iter().map(|k| k.label.to_string()).collect();

        // `mdir -i mbr-fat32.img@@1M ::/` prints DCIM, A-LONG~1 (long name
        // "a-long-directory-name") and README.TXT, 29 bytes.
        assert!(labels.contains(&"DCIM/".to_string()), "{labels:?}");
        assert!(labels.contains(&"a-long-directory-name/".to_string()), "{labels:?}");
        assert!(labels.contains(&"README.TXT".to_string()), "{labels:?}");
        // mdir also prints 'Volume in drive : is BLKTAMPER'.
        assert!(labels.contains(&"BLKTAMPER (volume label)".to_string()), "{labels:?}");

        let readme = child(&dir, &*src, "README.TXT");
        assert_eq!(u64_at(&readme, &["file_size"]), Some(29));
        assert_eq!(u64_at(&readme, &["first_cluster"]), Some(494));
        assert_eq!(u64_at(&readme, &["attr"]), Some(0x20));
        // 2026-09-16 10:38 per mdir: DOS date 0x5D30 is 1980+46, month 9, day 16.
        assert_eq!(u64_at(&readme, &["write_date"]), Some(0x5D30));

        // The cluster number is split across two fields eleven bytes apart; the
        // computed node owns both ranges and resolves to where the text really is.
        let fc = readme.find_child("first_cluster").unwrap();
        assert_eq!(fc.extent.spans().len(), 2);
        let link = fc.links.first().expect("a followable cluster");
        // `grep -abo "hello from blktamper fixture"` finds it at 2333696.
        assert_eq!(link.resolved, Some(2_333_696));
        assert_eq!(link.resolved, Some(DATA_START + (494 - 2) * 512));
    });
}

#[test]
fn assembles_long_filename_runs_and_checks_their_checksum() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let dcim = child(&root_dir(&root, &*src), &*src, "DCIM/");
        let contents = child(&dcim, &*src, "contents");
        let long = child(&contents, &*src, "a-very-long-file-name-for-lfn.jpeg");

        // mdir shows: A-VERY~1 JPE 50000 ... a-very-long-file-name-for-lfn.jpeg
        let members = long.children.resolved().expect("the run is resolved");
        assert_eq!(members.len(), 4, "three fragments plus the 8.3 entry");
        assert_eq!(members[0].label, "LFN 3/3 \"lfn.jpeg\"");
        assert_eq!(members[1].label, "LFN 2/3 \"ile-name-for-\"");
        assert_eq!(members[2].label, "LFN 1/3 \"a-very-long-f\"");
        assert_eq!(members[3].label, "A-VERY~1.JPE");
        assert_eq!(u64_at(&members[3], &["file_size"]), Some(50_000));
        assert_eq!(u64_at(&members[3], &["first_cluster"]), Some(396));

        // The run is four records that are not adjacent to anything else, so the
        // group owns four separate spans: the 8.3 entry first in logical order.
        let spans = long.extent.spans();
        assert_eq!(spans.len(), 4);
        assert_eq!(spans[0].start_byte(), spans[1].start_byte() + 3 * 32);

        // The stored checksum is 0xC4; "A-VERY~1JPE" put through the fatgen §7.2
        // rotate-right-and-add comes to 0xC4 as well.
        for m in &members[..3] {
            let sum = m.find_child("checksum").expect("checksum field");
            assert_eq!(sum.value.as_u64(), Some(0xC4));
            let d = sum.derived.as_ref().expect("a computed comparison");
            assert!(d.matches, "the run belongs to this 8.3 entry");
            assert_eq!(d.value.as_u64(), Some(0xC4));
        }
        assert_eq!(long.deep_status(), Status::Ok, "a healthy long name raises nothing");

        // The short entry's chain: 50000 bytes in 512-byte clusters is 98 of them.
        let chain = child(&members[3], &*src, "cluster chain");
        let links = kids(&chain, &*src);
        assert!(links[0].label.starts_with("chain: 98 clusters"), "{}", links[0].label);
        assert!(links[0].diags.iter().any(|d| d.message.contains("ended cleanly")));
    });
}

#[test]
fn surfaces_the_deleted_secret_txt_that_mdir_will_not_show() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let dir = root_dir(&root, &*src);

        // `mdir` lists three files. The fixture deleted a fourth, SECRET.TXT, and
        // the 0xE5 that replaced its 'S' is the only byte the delete rewrote.
        let del = child(&dir, &*src, "?ECRET.TXT");
        assert_eq!(del.label, "?ECRET.TXT (deleted)");
        assert_eq!(del.status, Status::Info, "shown and marked, never hidden");
        assert!(
            del.diags.iter().any(|d| d.message.contains("0xE5")),
            "must say the first character is destroyed: {:?}",
            del.diags
        );

        // Everything else about the record survived: same size and timestamps as
        // README.TXT, which the fixture copied it from.
        assert_eq!(u64_at(&del, &["file_size"]), Some(29));
        assert_eq!(u64_at(&del, &["first_cluster"]), Some(495));
        assert_eq!(u64_at(&del, &["attr"]), Some(0x20));

        // And its data is still on the disk: `grep -abo "hello from blktamper
        // fixture" mbr-fat32.img` reports 2333696 (README) and 2334208 — the
        // second of which is exactly where this entry points.
        let fc = del.find_child("first_cluster").unwrap();
        assert_eq!(fc.links[0].resolved, Some(2_334_208));
        assert_eq!(fc.links[0].resolved, Some(DATA_START + (495 - 2) * 512));

        // The chain, however, was released: FAT[495] reads 0.
        assert!(
            fc.diags.iter().any(|d| d.message.contains("reads free")),
            "must say the chain was released: {:?}",
            fc.diags
        );
    });
}

#[test]
fn surfaces_the_deleted_payload_and_recovers_its_first_character() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let long_dir = child(&root_dir(&root, &*src), &*src, "a-long-directory-name/");
        let contents = child(&child(&long_dir, &*src, "A-LONG~1"), &*src, "contents");

        // The second deleted file. Its long-filename fragments survived the delete
        // with only their order bytes overwritten, so the whole name is still here
        // even though the 8.3 entry lost its 'd'.
        let del = child(&contents, &*src, "deleted-payload.bin");
        assert_eq!(del.label, "deleted-payload.bin (deleted)");
        assert_eq!(del.status, Status::Info);

        let members = del.children.resolved().expect("run resolved");
        assert_eq!(members.len(), 3, "two fragments plus the 8.3 entry");
        assert_eq!(members[0].label, "LFN ?/2 \"ad.bin\"");
        assert_eq!(members[1].label, "LFN ?/2 \"deleted-paylo\"");
        assert_eq!(members[2].label, "?ELETE~1.BIN (8.3)");
        assert_eq!(u64_at(&members[2], &["file_size"]), Some(50_000));
        assert_eq!(u64_at(&members[2], &["first_cluster"]), Some(496));

        // The fragments store checksum 0x95. "DELETE~1BIN" checksums to 0x95 and
        // "\xE5ELETE~1BIN" does not — so the destroyed character is recoverable,
        // and 'D' is the only byte in 0x20..0xFF that produces 0x95.
        let sum = members[0].find_child("checksum").unwrap();
        assert_eq!(sum.value.as_u64(), Some(0x95));
        assert!(!sum.derived.as_ref().unwrap().matches, "0xE5 cannot checksum to 0x95");
        assert!(
            del.diags.iter().any(|d| d.message.contains("was 'D'")),
            "must recover the destroyed character: {:?}",
            del.diags
        );
        assert!(
            del.diags.iter().any(|d| d.message.contains("0x95")),
            "must name the checksum it recovered it from: {:?}",
            del.diags
        );
    });
}

#[test]
fn shows_what_lies_past_the_end_of_directory_marker() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let entries = kids(&root_dir(&root, &*src), &*src);

        // The 0x00 record after ?ECRET.TXT tells a driver to stop. We say so and
        // keep listing, because residue past it is the whole question.
        let end = entries
            .iter()
            .find(|k| k.label.starts_with("end of directory"))
            .expect("the terminator is a node of its own");
        assert!(end.diags.iter().any(|d| d.message.contains("used to contain")));
        // `xxd -s 0x1FC400 -l 512` shows the root cluster's 16 records: the volume
        // label, DCIM, two LFN fragments, A-LONG~1, README.TXT and the deleted
        // ?ECRET.TXT — seven in use — then the 0x00 terminator at 0x1FC4E0 and eight
        // records after it that are genuinely zero. The terminator has a node of its
        // own, so it must not be counted a second time here.
        assert_eq!(end.extent.first().unwrap().start_byte(), AT + 1_033_216 + 7 * 32);
        assert!(
            entries.iter().any(|k| k.label == "8 unused entries (all zero)"),
            "{:?}",
            entries.iter().map(|k| k.label.to_string()).collect::<Vec<_>>()
        );
    });
}

#[test]
fn follows_a_real_files_cluster_chain_to_its_end() {
    with_fixture("mbr-fat32.img", |src| {
        let root = FatProbe.open(src.clone(), AT).root();
        let dcim = child(&root_dir(&root, &*src), &*src, "DCIM/");
        let img = child(&child(&dcim, &*src, "contents"), &*src, "IMG_0001.JPG");
        assert_eq!(u64_at(&img, &["file_size"]), Some(200_000));
        assert_eq!(u64_at(&img, &["first_cluster"]), Some(5));

        let chain = kids(&child(&img, &*src, "cluster chain"), &*src);
        // 200000 bytes in 512-byte clusters is 391 of them, and xxd shows FAT[5]=6,
        // FAT[394]=0x18B, FAT[395]=0x0FFFFFFF.
        assert!(chain[0].label.starts_with("chain: 391 clusters"), "{}", chain[0].label);
        assert_eq!(200_000u64.div_ceil(512), 391);
        assert_eq!(chain[1].label, "[0] cluster 5");
        assert_eq!(chain[1].extent.first().unwrap().start_byte(), DATA_START + 3 * 512);
        assert_eq!(chain[391].label, "[390] cluster 395");
    });
}

#[test]
fn reads_a_fat32_inside_a_gpt_partition_too() {
    with_fixture("gpt-fat32.img", |src| {
        assert!(FatProbe.probe(&*src, AT) >= 80);
        let root = FatProbe.open(src.clone(), AT).root();
        assert_tree_invariants(&root);

        let ebpb = root.find_child("boot sector").unwrap().find_child("FAT32 EBPB").unwrap();
        assert_eq!(text_at(ebpb, &["volume_label"]).as_deref(), Some("GPTDATA"));
        assert_eq!(u64_at(ebpb, &["fat_size_32"]), Some(992));

        // `fsck.vfat -nv` on this partition: 126944 data clusters, 128960 sectors
        // total, 992 sectors per FAT, data area at byte 1032192.
        let g = root.find_child("geometry (computed)").unwrap();
        assert_eq!(u64_at(g, &["cluster count"]), Some(126_944));
        assert_eq!(u64_at(g, &["total sectors"]), Some(128_960));
        assert_eq!(u64_at(g, &["cluster 2 offset"]), Some(AT + 1_032_192));
        assert_eq!(text_at(g, &["fat type"]).as_deref(), Some("FAT32"));

        // Freshly formatted: the root holds only the volume label mkfs.vfat wrote.
        let entries = kids(&root_dir(&root, &*src), &*src);
        assert!(
            entries.iter().any(|k| k.label == "GPTDATA (volume label)"),
            "{:?}",
            entries.iter().map(|k| k.label.to_string()).collect::<Vec<_>>()
        );
    });
}

#[test]
fn is_not_claimed_where_it_is_not() {
    with_fixture("mbr-fat32.img", |src| {
        // Sector 0 is the MBR, not a volume. A jump instruction is missing there and
        // the BPB fields are bootstrap code.
        assert_eq!(FatProbe.probe(&*src, 0), 0, "an MBR must not be read as FAT");
    });
    with_fixture("exfat.img", |src| {
        // The single most honest thing this probe does: exFAT's boot sector is the
        // same shape and must be refused outright rather than scored low.
        assert_eq!(FatProbe.probe(&*src, 0), 0, "exFAT must not be claimed as FAT");
    });
    for name in ["garbage.img", "zeros.img"] {
        with_fixture(name, |src| {
            assert_eq!(FatProbe.probe(&*src, 0), 0, "{name} must not be claimed as FAT");
            // Forcing the interpretation must still produce a labelled tree.
            let root = FatProbe.open(src.clone(), 0).root();
            assert_tree_invariants(&root);
            assert!(root.find_child("boot sector").is_some());
            for k in root.children.resolved().unwrap() {
                let _ = kids(k, &*src);
            }
        });
    }
}

// Asserts about the registry as a whole, so it needs the MBR module compiled in.
#[cfg(feature = "mbr")]
#[test]
fn the_registry_picks_fat_at_the_partition_and_mbr_at_sector_zero() {
    with_fixture("mbr-fat32.img", |src| {
        let reg = blktamper_formats::registry();
        assert_eq!(reg.best(&*src, AT).expect("something at 1 MiB").0, fat::ID);
        assert_ne!(reg.best(&*src, 0).expect("something at sector 0").0, fat::ID);
    });
}
