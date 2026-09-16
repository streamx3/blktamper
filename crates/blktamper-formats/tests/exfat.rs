//! (compiled only with the `exfat` feature)
#![cfg(feature = "exfat")]

//! exFAT against real images made by `mkfs.exfat` (exfatprogs 1.2.2).
//!
//! Every number asserted here was read off the image with an independent tool
//! before it was ever compared with ours — `xxd` for the raw bytes, `dump.exfat`
//! for the boot sector's own account of itself, `fsck.exfat -n` for whether the
//! volume is internally consistent, and a short Python transcription of the
//! specification's checksum pseudo-code for the two checksums. Asserting values
//! our own parser produced would prove only that it is self-consistent.

mod common;

use blktamper_core::{Children, FormatProbe, Node, Status};
use blktamper_formats::exfat::{self, ExfatProbe};
use common::*;

/// Byte offset of the exFAT volume inside `mbr-exfat.img`: sfdisk put partition 1
/// at LBA 2048 and the volume was `dd`'d in there.
const MBR_EXFAT_AT: u64 = 2048 * 512;

fn boot_sector(root: &Node) -> &Node {
    find_deep(root, "main boot sector").expect("the main boot sector must always be present")
}

#[test]
fn reads_a_real_mkfs_exfat_volume() {
    with_fixture("exfat.img", |src| {
        assert!(ExfatProbe.probe(&*src, 0) >= 80, "a pristine volume must score confidently");
        let root = ExfatProbe.open(src, 0).root();
        assert_tree_invariants(&root);

        // Every value below is what `dump.exfat` reports for this image, and what
        // `xxd -l 512` shows at the matching offset.
        let b = boot_sector(&root);
        assert_eq!(text_at(b, &["fs_name"]).as_deref(), Some("EXFAT"));
        assert_eq!(u64_at(b, &["partition_offset"]), Some(0));
        assert_eq!(u64_at(b, &["volume_length"]), Some(131_072));
        assert_eq!(u64_at(b, &["fat_offset"]), Some(2048));
        assert_eq!(u64_at(b, &["fat_length"]), Some(128));
        assert_eq!(u64_at(b, &["cluster_heap_offset"]), Some(4096));
        assert_eq!(u64_at(b, &["cluster_count"]), Some(15_872));
        assert_eq!(u64_at(b, &["first_cluster_of_root"]), Some(5));
        assert_eq!(u64_at(b, &["volume_serial_number"]), Some(0x7FE9_D4D7));
        assert_eq!(u64_at(b, &["fs_revision"]), Some(0x0100));
        assert_eq!(u64_at(b, &["volume_flags"]), Some(0));
        assert_eq!(u64_at(b, &["bytes_per_sector_shift"]), Some(9));
        assert_eq!(u64_at(b, &["sectors_per_cluster_shift"]), Some(3));
        assert_eq!(u64_at(b, &["number_of_fats"]), Some(1));
        assert_eq!(u64_at(b, &["drive_select"]), Some(0x80));
        assert_eq!(u64_at(b, &["percent_in_use"]), Some(0));
        assert_eq!(u64_at(b, &["boot_signature"]), Some(0xAA55));

        // mkfs.exfat leaves the 53 bytes where a FAT BPB would be at zero, which is
        // what stops a FAT driver mounting this.
        let mbz = b.find_child("must_be_zero").unwrap();
        assert_eq!(mbz.raw.len(), 53);
        assert!(mbz.raw.iter().all(|&x| x == 0));

        // All eight extended boot sectors carry the same trailing signature.
        let ext = find_deep(&root, "extended boot sectors").expect("sectors 1..=8");
        let kids = ext.children.resolved().unwrap();
        assert_eq!(kids.len(), 8);
        for (i, k) in kids.iter().enumerate() {
            assert_eq!(
                u64_at(k, &["ext_boot_signature"]),
                Some(0xAA55_0000),
                "extended boot sector {i}"
            );
        }
    });
}

#[test]
fn the_geometry_is_derived_from_the_shifts_and_shown() {
    with_fixture("exfat.img", |src| {
        let root = ExfatProbe.open(src, 0).root();
        let g = root.find_child("geometry (computed)").expect("computed geometry");
        assert_eq!(u64_at(g, &["bytes_per_sector"]), Some(512)); // 1 << 9
        assert_eq!(u64_at(g, &["sectors_per_cluster"]), Some(8)); // 1 << 3
        assert_eq!(u64_at(g, &["cluster_size"]), Some(4096));
        assert_eq!(u64_at(g, &["volume_size"]), Some(131_072 * 512));
        // cluster_heap_offset 4096 x 512 bytes
        assert_eq!(u64_at(g, &["heap_offset"]), Some(0x20_0000));
        assert_eq!(u64_at(g, &["fat_0_offset"]), Some(0x10_0000));
        // root at cluster 5: heap + (5 - 2) x 4096. xxd shows the 0x83 entry there.
        assert_eq!(u64_at(g, &["root_directory_offset"]), Some(0x20_3000));
        assert_eq!(u64_at(g, &["last_cluster"]), Some(15_873));
    });
}

#[test]
fn the_boot_region_checksum_is_computed_and_matches() {
    with_fixture("exfat.img", |src| {
        let root = ExfatProbe.open(src, 0).root();
        // 0x02226F37: computed independently in Python over sectors 0..=10,
        // skipping byte indices 106, 107 and 112 of sector 0 — and that is exactly
        // what `xxd -s 5632` shows stored in sector 11.
        let ck = find_deep(&root, "boot_checksum").expect("the checksum node");
        assert_eq!(ck.value.as_u64(), Some(0x0222_6F37));
        let d = ck.derived.as_ref().expect("a computed value to compare against");
        assert_eq!(d.value.as_u64(), Some(0x0222_6F37));
        assert!(d.matches, "a pristine volume's boot checksum must verify");

        // The value is repeated for every 4 bytes of the 512-byte sector.
        let reps = find_deep(&root, "repetitions").expect("the repetition node");
        assert_eq!(reps.value.as_u64(), Some(128));
        assert!(reps.diags.iter().any(|x| x.message.contains("all 128 copies")));
    });
}

#[test]
fn the_backup_boot_region_is_byte_identical_on_a_fresh_volume() {
    with_fixture("exfat.img", |src| {
        let root = ExfatProbe.open(src, 0).root();
        let diff = root.find_child("main vs backup boot region").expect("the diff node");
        assert!(
            diff.diags.iter().any(|d| d.message.contains("byte-identical")),
            "cmp of the two 6144-byte regions says they are equal: {:?}",
            diff.diags
        );
        assert!(!diff.status.is_anomaly());

        // and the backup's own checksum sector verifies too
        let backup = find_deep(&root, "backup boot region").expect("the backup region");
        let ck = find_deep(backup, "boot_checksum").unwrap();
        assert_eq!(ck.value.as_u64(), Some(0x0222_6F37));
        assert!(ck.derived.as_ref().unwrap().matches);
        assert_eq!(ck.extent.first().unwrap().start_byte(), 23 * 512);
    });
}

#[test]
fn the_root_directory_holds_the_records_mkfs_wrote() {
    with_fixture("exfat.img", |src| {
        let root = ExfatProbe.open(src, 0).root();
        let dir = root.find_child("root directory").expect("root directory");
        assert_eq!(dir.extent.first().unwrap().start_byte(), 0x20_3000);
        let kids = dir.children.resolved().unwrap();

        // `xxd -s 2109440` shows, in order: 83 (label), 20, 81 (bitmap), 82
        // (up-case), then the 0x00 end-of-directory marker.
        assert_eq!(u64_at(&kids[0], &["entry_type"]), Some(0x83));
        assert_eq!(u64_at(&kids[0], &["character_count"]), Some(11));
        assert_eq!(text_at(&kids[0], &["volume_label"]).as_deref(), Some("BLKTAMPER-X"));
        assert!(kids[0].label.contains("BLKTAMPER-X"), "{}", kids[0].label);

        assert_eq!(u64_at(&kids[2], &["entry_type"]), Some(0x81));
        assert_eq!(u64_at(&kids[2], &["first_cluster"]), Some(2));
        assert_eq!(u64_at(&kids[2], &["data_length"]), Some(1984)); // 15872 / 8

        assert_eq!(u64_at(&kids[3], &["entry_type"]), Some(0x82));
        assert_eq!(u64_at(&kids[3], &["first_cluster"]), Some(3));
        assert_eq!(u64_at(&kids[3], &["data_length"]), Some(5836));
        assert_eq!(u64_at(&kids[3], &["table_checksum"]), Some(0xE619_D30D));

        assert_eq!(u64_at(&kids[4], &["entry_type"]), Some(0x00));
        assert!(kids[4].label.contains("end of directory"));
    });
}

#[test]
fn mkfs_exfat_leaves_a_deleted_volume_guid_entry_in_the_root() {
    // The single deleted record a freshly formatted volume contains, and the one
    // `dump.exfat` reports as "Bitmap entry type: 0x20" because it labels root
    // entries by position rather than by type. Reading the type byte says what it
    // really is: a volume GUID entry with InUse cleared.
    with_fixture("exfat.img", |src| {
        let root = ExfatProbe.open(src, 0).root();
        let dir = root.find_child("root directory").expect("root directory");
        let e = &dir.children.resolved().unwrap()[1];

        assert_eq!(u64_at(e, &["entry_type"]), Some(0x20));
        assert_eq!(e.label.as_ref(), "deleted volume GUID entry");
        assert_eq!(e.extent.first().unwrap().start_byte(), 0x20_3020);
        assert!(
            e.diags.iter().any(|d| d.message.contains("InUse (bit 7) is clear")),
            "{:?}",
            e.diags
        );
        // Nothing survives in this one — and saying so is as important as saying
        // when something does.
        assert!(e.diags.iter().any(|d| d.message.contains("nothing survives in it")));
        assert!(
            !e.deep_status().is_anomaly(),
            "a record mkfs deliberately left not-in-use is a finding, not damage"
        );
        assert!(dir.diags.iter().any(|d| d.message.contains("marked not-in-use")));
    });
}

#[test]
fn the_allocation_bitmap_is_located_and_counted() {
    with_fixture("exfat.img", |src| {
        let root = ExfatProbe.open(src, 0).root();
        let bm = root.find_child("allocation bitmap").expect("bitmap region");
        // cluster 2 -> heap + 0
        assert_eq!(bm.extent.first().unwrap().start_byte(), 0x20_0000);

        // `xxd -s 2097152 -l 1` is 0x0F: clusters 2, 3, 4 and 5 — the bitmap, both
        // clusters of the up-case table, and the root directory. Nothing else on a
        // freshly formatted volume.
        assert_eq!(u64_at(bm, &["allocated_clusters"]), Some(4));
        assert_eq!(u64_at(bm, &["free_clusters"]), Some(15_868));
        assert_eq!(u64_at(bm, &["allocated_bytes"]), Some(4 * 4096));

        let x = bm.find_child("bitmap vs FAT").expect("the FAT cross-check");
        assert_eq!(u64_at(x, &["clusters_compared"]), Some(15_872));
        assert!(
            x.diags.iter().any(|d| d.message.contains("agree over the first")),
            "{:?}",
            x.diags
        );
    });
}

#[test]
fn the_up_case_table_checksum_matches_the_table_on_disk() {
    with_fixture("exfat.img", |src| {
        let root = ExfatProbe.open(src, 0).root();
        let uc = root.find_child("up-case table").expect("up-case table region");
        // cluster 3 -> heap + 4096
        assert_eq!(uc.extent.first().unwrap().start_byte(), 0x20_1000);
        assert_eq!(u64_at(uc, &["table_bytes"]), Some(5836));
        // 0xE619D30D, computed in Python over the 5836 bytes at that offset.
        assert!(
            uc.diags.iter().any(|d| d.message.contains("matches the checksum")),
            "{:?}",
            uc.diags
        );
        // The table spans clusters 3 and 4 — 5836 bytes does not fit in one 4096-
        // byte cluster — so the region is two clusters long and contiguous.
        assert_eq!(uc.extent.len_bytes(), 8192);

        // Decoding it into 65536 rows must not happen while the tree is built.
        let mappings = uc.find_child("mappings").expect("mappings node");
        assert!(mappings.children.resolved().is_none(), "the table must stay compressed");
    });
}

#[test]
fn the_fat_matches_what_xxd_shows_and_expands_lazily() {
    with_fixture("exfat.img", |src| {
        let root = ExfatProbe.open(src.clone(), 0).root();
        let fat = root.find_child("FAT").expect("the FAT region");
        assert_eq!(fat.extent.first().unwrap().start_byte(), 0x10_0000);

        // `xxd -s 1048576 -l 24`: F8FFFFFF FFFFFFFF FFFFFFFF 04000000 FFFFFFFF
        // FFFFFFFF — the media descriptor, the reserved entry, then clusters 2..=5.
        assert_eq!(u64_at(fat, &["entry 0 (media type)"]), Some(0xFFFF_FFF8));
        assert_eq!(u64_at(fat, &["entry 1 (reserved)"]), Some(0xFFFF_FFFF));

        let entries = fat.find_child("entries (clusters 2..)").expect("the entry array");
        assert!(entries.children.resolved().is_none(), "a 7 MB FAT must not be built eagerly");
        assert_eq!(entries.children.len_hint(), Some(15_872));

        let Children::Lazy(e) = &entries.children else { panic!("expected a lazy expander") };
        let kids = e.expand(&*src);
        assert_eq!(kids.len(), 15_872);
        // Cluster 3 chains to 4: the up-case table is 5836 bytes and does not fit
        // in one 4096-byte cluster. Everything else here is a one-cluster object.
        assert!(kids[0].label.starts_with("[2] end of chain"), "{}", kids[0].label);
        assert!(kids[1].label.starts_with("[3] -> 4"), "{}", kids[1].label);
        assert!(kids[2].label.starts_with("[4] end of chain"), "{}", kids[2].label);
        assert!(kids[3].label.starts_with("[5] end of chain"), "{}", kids[3].label);
        assert!(kids[4].label.starts_with("[6] free"), "{}", kids[4].label);
    });
}

#[test]
fn an_exfat_inside_a_partition_reports_partition_offset_honestly() {
    // sfdisk put the partition at LBA 2048, but mkfs.exfat ran on a standalone
    // file before it was copied in, so the boot sector's partition_offset is 0.
    // The specification defines 0 as "no meaningful value" — reporting it as "this
    // volume starts at sector 0" would be the wrong reading of the same bytes.
    with_fixture("mbr-exfat.img", |src| {
        assert!(ExfatProbe.probe(&*src, MBR_EXFAT_AT) >= 80);
        assert_eq!(ExfatProbe.probe(&*src, 0), 0, "there is no exFAT at sector 0 of this image");

        let root = ExfatProbe.open(src, MBR_EXFAT_AT).root();
        assert_tree_invariants(&root);
        let b = boot_sector(&root);

        let po = b.find_child("partition_offset").unwrap();
        assert_eq!(po.value.as_u64(), Some(0));
        assert!(
            po.diags.iter().any(|d| d.message.contains("opened at LBA 2048")),
            "{:?}",
            po.diags
        );
        assert!(!po.status.is_anomaly(), "a zero partition_offset is legal, not an error");

        // dump.exfat on the extracted partition: 194560 sectors, FAT length 192,
        // 23808 clusters, serial 0x6aabd4d7.
        assert_eq!(u64_at(b, &["volume_length"]), Some(194_560));
        assert_eq!(u64_at(b, &["fat_length"]), Some(192));
        assert_eq!(u64_at(b, &["cluster_count"]), Some(23_808));
        assert_eq!(u64_at(b, &["volume_serial_number"]), Some(0x6AAB_D4D7));

        // Everything is offset by the 1 MiB the partition starts at.
        let g = root.find_child("geometry (computed)").unwrap();
        assert_eq!(u64_at(g, &["heap_offset"]), Some(MBR_EXFAT_AT + 0x20_0000));
        assert_eq!(u64_at(g, &["root_directory_offset"]), Some(MBR_EXFAT_AT + 0x20_3000));

        // 23808 clusters, four of them in use; the bitmap is 23808 / 8 bytes.
        let bm = root.find_child("allocation bitmap").unwrap();
        assert_eq!(u64_at(bm, &["allocated_clusters"]), Some(4));
        assert_eq!(u64_at(bm, &["free_clusters"]), Some(23_804));
        let dir = root.find_child("root directory").unwrap();
        assert_eq!(u64_at(&dir.children.resolved().unwrap()[2], &["data_length"]), Some(2976));
        assert_eq!(
            text_at(&dir.children.resolved().unwrap()[0], &["volume_label"]).as_deref(),
            Some("BLKTAMPER-X")
        );
    });
}

#[test]
fn a_freshly_formatted_volume_reports_no_anomaly() {
    for (name, at) in [("exfat.img", 0u64), ("mbr-exfat.img", MBR_EXFAT_AT)] {
        with_fixture(name, |src| {
            let root = ExfatProbe.open(src, at).root();
            assert!(
                !root.deep_status().is_anomaly(),
                "{name}: fsck.exfat -n calls this volume clean, so neither may we call it \
                 damaged — got {:?}",
                root.deep_status()
            );
            assert!(
                root.deep_status() >= Status::Info,
                "{name}: but the deleted volume GUID entry is worth saying out loud"
            );
        });
    }
}

#[test]
fn nothing_else_on_these_disks_is_claimed_as_exfat() {
    // The honest half of the probe. A FAT32 boot sector and a GPT disk both look
    // like a boot sector at a glance; only the eight bytes at offset 3 decide.
    for (name, at) in [
        ("garbage.img", 0u64),
        ("zeros.img", 0),
        ("mbr-fat32.img", 0),
        ("mbr-fat32.img", 2048 * 512),
        ("gpt-basic.img", 0),
        ("gpt-fat32.img", 2048 * 512),
        ("mbr-extended.img", 0),
    ] {
        with_fixture(name, |src| {
            assert_eq!(
                ExfatProbe.probe(&*src, at),
                0,
                "{name} at {at:#x} must not be claimed as exFAT"
            );
            // Forcing the interpretation must still produce a full, labelled tree.
            let root = ExfatProbe.open(src, at).root();
            assert_tree_invariants(&root);
            assert!(find_deep(&root, "main boot sector").is_some());
        });
    }
}

#[test]
fn the_registry_picks_exfat_over_the_55aa_at_sector_zero() {
    // An exFAT boot sector ends in 55 AA, so the MBR probe sees its own signature
    // there. Scoring, rather than deciding, is what keeps that from mattering.
    with_fixture("exfat.img", |src| {
        let reg = blktamper_formats::registry();
        let candidates = reg.candidates(&*src, 0);
        assert_eq!(candidates[0].0, exfat::ID, "got {candidates:?}");
        assert!(candidates[0].1 >= 80);
        if let Some((_, mbr_score)) = candidates.iter().find(|(id, _)| id.0 == "mbr") {
            assert!(
                *mbr_score < candidates[0].1,
                "the MBR probe may see 55 AA, but it must not win: {candidates:?}"
            );
        }
    });
}

#[test]
fn an_unreadable_region_is_never_rendered_as_zeros() {
    // How a dying stick behaves: the boot region reads, the cluster heap does not.
    // R-2.7 says those two states must never be confused.
    let path = fixture_dir().join("exfat.img");
    let Ok(data) = std::fs::read(&path) else {
        eprintln!("skipping: {} not found", path.display());
        return;
    };
    let src: std::sync::Arc<dyn blktamper_core::BlockSource> =
        std::sync::Arc::new(blktamper_core::source::FailingSource {
            inner: blktamper_core::MemSource::new(data),
            fail_from: 0x20_0000,
        });
    let root = ExfatProbe.open(src, 0).root();
    let mut unreadable = 0;
    root.walk(&mut |n| {
        if n.status == Status::Unreadable {
            unreadable += 1;
        }
    });
    assert!(unreadable > 0, "an I/O error must be its own state");
    // and the boot region, which did read, is still complete
    assert_eq!(u64_at(boot_sector(&root), &["cluster_count"]), Some(15_872));
}
