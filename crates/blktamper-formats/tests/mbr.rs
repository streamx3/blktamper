//! (compiled only with the `mbr` feature)
#![cfg(feature = "mbr")]

//! MBR against real images made by `sfdisk`.

mod common;

use blktamper_core::{FormatProbe, Status};
use blktamper_formats::mbr::{self, MbrProbe};
use common::*;

#[test]
fn reads_a_real_sfdisk_table() {
    with_fixture("mbr-fat32.img", |src| {
        assert!(MbrProbe.probe(&*src, 0) >= 80);
        let root = MbrProbe.open(src, 0).root();
        assert_tree_invariants(&root);

        let entries = root.find_child("entries").expect("entry array");
        let kids = entries.children.resolved().unwrap();
        assert_eq!(kids.len(), 4);

        // sfdisk wrote: start=2048, size=129024, type=c, bootable
        let e0 = &kids[0];
        assert_eq!(u64_at(e0, &["lba_first"]), Some(2048));
        assert_eq!(u64_at(e0, &["num_sectors"]), Some(129_024));
        assert_eq!(u64_at(e0, &["part_type"]), Some(0x0C));
        assert_eq!(u64_at(e0, &["status"]), Some(0x80));
        assert!(e0.label.contains("FAT32 LBA"));

        // and the disk id we asked for
        assert_eq!(u64_at(&root, &["disk_signature"]), Some(0xDEAD_BEEF));

        // slots 1..3 are genuinely empty
        for k in &kids[1..] {
            assert_eq!(k.label.as_ref(), format!("[{}] --", kids.iter().position(|x| std::ptr::eq(x, k)).unwrap()));
        }
        assert_eq!(root.deep_status(), Status::Ok, "a clean table must report clean");
    });
}

#[test]
fn the_partition_entry_links_to_its_volume_header() {
    with_fixture("mbr-fat32.img", |src| {
        let root = MbrProbe.open(src, 0).root();
        let e0 = &root.find_child("entries").unwrap().children.resolved().unwrap()[0];
        let lba = e0.find_child("lba_first").unwrap();
        let link = lba.links.first().expect("lba_first must be followable");
        assert_eq!(link.raw, 2048);
        assert_eq!(link.resolved, Some(1_048_576));
    });
}

#[test]
fn follows_an_extended_chain() {
    with_fixture("mbr-extended.img", |src| {
        let root = MbrProbe.open(src, 0).root();
        assert_tree_invariants(&root);
        let entries = root.find_child("entries").unwrap();
        let kids = entries.children.resolved().unwrap();

        // slot 1 is the extended container sfdisk created
        let ext = kids.iter().find(|k| u64_at(k, &["part_type"]) == Some(0x05)).expect("extended");
        let logicals = ext.find_child("logical partitions").expect("EBR chain walked");
        let ebrs = logicals.children.resolved().unwrap();
        assert_eq!(ebrs.len(), 2, "sfdisk wrote two logical partitions");

        // The first EBR sits at the extended partition's start.
        assert!(ebrs[0].label.contains("LBA 10240"));
        let e0 = find_deep(&ebrs[0], "logical 1").expect("logical partition entry");
        // relative LBA 2048 from EBR at 10240 -> absolute 12288, which is what
        // sfdisk was told to create.
        assert_eq!(u64_at(e0, &["lba_first"]), Some(2048));
        assert!(e0.diags.iter().any(|d| d.message.contains("absolute LBA 12288")));
    });
}

#[test]
fn recognises_a_protective_mbr_on_a_gpt_disk() {
    with_fixture("gpt-basic.img", |src| {
        assert!(MbrProbe.probe(&*src, 0) > 0, "a protective MBR is still an MBR");
        let root = MbrProbe.open(src, 0).root();
        assert!(
            root.diags.iter().any(|d| d.message.contains("protective MBR")),
            "must say the real table is elsewhere"
        );
    });
}

#[test]
fn garbage_and_zeros_never_panic_and_never_pretend() {
    for name in ["garbage.img", "zeros.img"] {
        with_fixture(name, |src| {
            let score = MbrProbe.probe(&*src, 0);
            // Random data will not have 55 AA; zeros certainly do not.
            assert_eq!(score, 0, "{name} must not be claimed as an MBR");
            // Forcing the interpretation must still produce a labelled tree.
            let root = MbrProbe.open(src, 0).root();
            assert_tree_invariants(&root);
            assert!(root.find_child("entries").is_some());
        });
    }
}

#[test]
fn the_registry_picks_mbr_for_a_partitioned_disk() {
    with_fixture("mbr-fat32.img", |src| {
        let reg = blktamper_formats::registry();
        let best = reg.best(&*src, 0).expect("something must match sector 0");
        assert_eq!(best.0, mbr::ID);
    });
}
