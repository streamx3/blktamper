//! (compiled only with the `gpt` feature)
#![cfg(feature = "gpt")]

//! GPT against real images made by `sgdisk`.
//!
//! Every number asserted below came from something that is not this parser:
//! `sgdisk -p` and `sgdisk -i N` for the partition table, `xxd` for the raw header
//! bytes, and an independent bit-by-bit CRC-32 in this file for the two checksums.
//! Asserting values our own reader produced would only prove it is self-consistent
//! (R-9.1).
//!
//! Constants are only hardcoded where `tests/fixtures/make-fixtures.sh` pins them.
//! It passes `-U` and `-u 1:` for `gpt-basic.img` and nothing for `gpt-fat32.img`,
//! so every other GUID — and therefore both CRCs, which cover them — is fresh on
//! each regeneration and is checked by recomputation instead.

mod common;

use blktamper_core::{BlockSource, Children, FormatProbe, Node, Status, Value};
use blktamper_formats::gpt::{self, diff_headers, guids, GptProbe};
use common::*;
use std::sync::Arc;

/// Expand a lazily-built entry array.
fn entries(root: &Node, src: &Arc<dyn BlockSource>) -> Vec<Node> {
    let arr = root.find_child("partition entries").expect("entry array");
    match &arr.children {
        Children::Lazy(e) => e.expand(&**src),
        // On an image whose entries_lba points nowhere there is nothing to expand,
        // and the node has to say so rather than render an empty array.
        Children::None => {
            assert!(!arr.diags.is_empty(), "an array with no children must explain itself");
            Vec::new()
        }
        other => panic!("the entry array must be lazy, found {other:?}"),
    }
}

/// CRC-32/ISO-HDLC, written out bit by bit.
///
/// Deliberately not `blktamper_core`'s table-driven one: a checksum test that calls
/// the implementation it is testing proves only that it is deterministic. This one
/// is checked against the standard "123456789" vector below before it is trusted.
fn crc32_reference(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn read_at(src: &Arc<dyn BlockSource>, off: u64, len: usize) -> Vec<u8> {
    let (v, outcome) = src.read_vec(off, len);
    assert!(outcome.is_ok(), "fixture read at {off:#x} failed: {outcome:?}");
    v
}

fn guid_of(n: &Node, field: &str) -> String {
    match n.find_child(field).map(|c| &c.value) {
        Some(Value::Guid(g)) => blktamper_core::value::format_guid_mixed_endian(g),
        other => panic!("{field} is not a GUID: {other:?}"),
    }
}

#[test]
fn reads_a_real_sgdisk_table() {
    with_fixture("gpt-basic.img", |src| {
        assert!(GptProbe.probe(&*src, 0) >= 80, "a well-formed GPT must score strongly");
        let root = GptProbe.open(src.clone(), 0).root();
        assert_tree_invariants(&root);

        let h = root.find_child("primary header").expect("primary header");

        // `sgdisk -p gpt-basic.img`:
        //   Disk identifier (GUID): 89ABCDEF-0123-4567-89AB-CDEF01234567
        //   Partition table holds up to 128 entries
        //   Main partition table begins at sector 2
        //   First usable sector is 34, last usable sector is 131038
        assert_eq!(guid_of(h, "disk_guid"), "89abcdef-0123-4567-89ab-cdef01234567");
        assert_eq!(u64_at(h, &["num_entries"]), Some(128));
        assert_eq!(u64_at(h, &["entry_size"]), Some(128));
        assert_eq!(u64_at(h, &["entries_lba"]), Some(2));
        assert_eq!(u64_at(h, &["first_usable_lba"]), Some(34));
        assert_eq!(u64_at(h, &["last_usable_lba"]), Some(131_038));

        // `xxd -s 512 -l 32 gpt-basic.img` -> 4546 4920 5041 5254 0000 0100 5c00 0000
        assert_eq!(text_at(h, &["signature"]).as_deref(), Some("EFI PART"));
        assert_eq!(u64_at(h, &["revision"]), Some(0x0001_0000));
        assert_eq!(u64_at(h, &["header_size"]), Some(92));
        assert_eq!(u64_at(h, &["my_lba"]), Some(1));
        assert_eq!(u64_at(h, &["alternate_lba"]), Some(131_071));

        assert!(!root.deep_status().is_anomaly(), "a clean table must report clean");
    });
}

#[test]
fn the_reference_crc32_is_the_standard_one() {
    // Before the next test is allowed to believe anything, the yardstick it uses
    // has to match the published CRC-32/ISO-HDLC check value.
    assert_eq!(crc32_reference(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32_reference(b""), 0x0000_0000);
}

#[test]
fn both_crcs_are_recomputed_over_the_right_ranges() {
    with_fixture("gpt-basic.img", |src| {
        let root = GptProbe.open(src.clone(), 0).root();
        let h = root.find_child("primary header").unwrap();

        // The header CRC covers header_size bytes — 92, which `xxd -s 524 -l 4`
        // shows as 5c 00 00 00 — with its own four bytes taken as zero, and NOT
        // the whole 512-byte block. Recomputed here from the fixture's own bytes
        // with an independent implementation.
        let mut hdr = read_at(&src, 512, 92);
        let stored_header_crc = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
        hdr[16..20].fill(0);
        let want_header_crc = crc32_reference(&hdr);
        assert_eq!(
            stored_header_crc, want_header_crc,
            "sgdisk wrote this image, so its stored CRC is the external oracle"
        );

        let hc = h.find_child("header_crc32").unwrap().derived.clone().expect("header CRC");
        assert_eq!(hc.value, Value::Uint(want_header_crc as u64));
        assert_eq!(u64_at(h, &["header_crc32"]), Some(stored_header_crc as u64));
        assert!(hc.matches);
        assert!(hc.how.contains("92 bytes"), "must cover header_size, not the block: {}", hc.how);
        // 512 bytes would be the classic wrong answer, and it is a different number.
        assert_ne!(want_header_crc, crc32_reference(&read_at(&src, 512, 512)));

        // The entry array CRC covers num_entries * entry_size = 128 * 128 = 16384
        // bytes at entries_lba 2, not the 16 KiB it happens to round up to, and not
        // the gap up to first_usable_lba 34 (which is 16384 bytes here, but only by
        // coincidence of the numbers).
        let array = read_at(&src, 2 * 512, 128 * 128);
        let want_array_crc = crc32_reference(&array);
        let ec = h.find_child("entries_crc32").unwrap().derived.clone().expect("entries CRC");
        assert_eq!(ec.value, Value::Uint(want_array_crc as u64));
        assert_eq!(u64_at(h, &["entries_crc32"]), Some(want_array_crc as u64));
        assert!(ec.matches);
        assert!(ec.how.contains("16384 bytes"), "128 x 128 = 16384: {}", ec.how);
    });
}

#[test]
fn the_backup_header_is_read_and_differs_only_where_it_must() {
    with_fixture("gpt-basic.img", |src| {
        let root = GptProbe.open(src, 0).root();
        let p = root.find_child("primary header").unwrap();
        let b = root.find_child("backup header").unwrap();

        // `xxd -s 0x3FFFE00 -l 96` on the last LBA: my_lba 131071, alternate_lba 1,
        // entries_lba 131039 = last_usable_lba + 1.
        assert_eq!(u64_at(b, &["my_lba"]), Some(131_071));
        assert_eq!(u64_at(b, &["alternate_lba"]), Some(1));
        assert_eq!(u64_at(b, &["entries_lba"]), Some(131_039));
        assert!(b.find_child("header_crc32").unwrap().derived.as_ref().unwrap().matches);
        // The backup's CRC necessarily differs from the primary's: it covers those
        // three fields, and all three are supposed to be different.
        assert_ne!(u64_at(b, &["header_crc32"]), u64_at(p, &["header_crc32"]));

        // Those four are exactly the fields that are supposed to differ.
        assert!(diff_headers(p, b).is_empty(), "{:?}", diff_headers(p, b));
        assert_eq!(gpt::MIRRORED_FIELDS, &["my_lba", "alternate_lba", "entries_lba", "header_crc32"]);

        let cmp = root.find_child("primary vs backup").unwrap();
        assert!(cmp.diags.iter().any(|d| d.message.contains("agree on every field")));
        assert!(cmp.diags.iter().any(|d| d.message.contains("byte-identical")));
        assert!(!cmp.deep_status().is_anomaly());
    });
}

#[test]
fn reads_the_three_partitions_sgdisk_created() {
    with_fixture("gpt-basic.img", |src| {
        let root = GptProbe.open(src.clone(), 0).root();
        let kids = entries(&root, &src);
        assert_eq!(kids.len(), 128, "every declared slot gets a node");

        // `sgdisk -i 1`: C12A7328-F81F-11D2-BA4B-00A0C93EC93B (EFI system partition),
        // unique 11111111-2222-3333-4444-555555555555, sectors 2048..34815, 'EFI System'
        assert_eq!(guid_of(&kids[0], "type_guid"), "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
        assert_eq!(guid_of(&kids[0], "unique_guid"), "11111111-2222-3333-4444-555555555555");
        assert_eq!(u64_at(&kids[0], &["first_lba"]), Some(2048));
        assert_eq!(u64_at(&kids[0], &["last_lba"]), Some(34_815));
        assert_eq!(text_at(&kids[0], &["name"]).as_deref(), Some("EFI System"));
        assert_eq!(u64_at(&kids[0], &["attributes"]), Some(0));
        assert!(kids[0].label.contains("EFI System"));

        // `sgdisk -i 2`: 0FC63DAF-8483-4772-8E79-3D69D8477DE4 (Linux filesystem),
        // sectors 34816..67583. Its unique GUID is not asserted: make-fixtures.sh
        // pins only partition 1's, so 2 and 3 get a fresh one every regeneration.
        assert_eq!(guid_of(&kids[1], "type_guid"), "0fc63daf-8483-4772-8e79-3d69d8477de4");
        assert_eq!(u64_at(&kids[1], &["first_lba"]), Some(34_816));
        assert_eq!(u64_at(&kids[1], &["last_lba"]), Some(67_583));
        assert_eq!(text_at(&kids[1], &["name"]).as_deref(), Some("Linux filesystem"));

        // `sgdisk -i 3`: CA7D7CCB-63ED-4C53-861C-1742536059CC (Linux LUKS),
        // sectors 67584..131038.
        // sgdisk prints the name as 'Linux LUKS \xe2\x98\x85' and that escaped form
        // is literally what is on the disk: `xxd -s 1336` shows the ASCII "\x85"
        // as four UTF-16 units, not one star.
        assert_eq!(guid_of(&kids[2], "type_guid"), "ca7d7ccb-63ed-4c53-861c-1742536059cc");
        assert_eq!(u64_at(&kids[2], &["first_lba"]), Some(67_584));
        assert_eq!(u64_at(&kids[2], &["last_lba"]), Some(131_038));
        assert_eq!(text_at(&kids[2], &["name"]).as_deref(), Some("Linux LUKS \\xe2\\x98\\x85"));

        assert_eq!(gpt::guids::type_label(&guids::LINUX_LUKS), Some("Linux LUKS"));
        for k in &kids[..3] {
            assert!(!k.deep_status().is_anomaly(), "{}: {:?}", k.label, k.diags);
        }
    });
}

#[test]
fn unused_slots_are_shown_rather_than_skipped() {
    with_fixture("gpt-basic.img", |src| {
        let root = GptProbe.open(src.clone(), 0).root();
        let kids = entries(&root, &src);
        // sgdisk zeroes the slots it does not use, so 125 of them are genuinely
        // blank — and every one still has a labelled node with its own offset.
        for (i, k) in kids.iter().enumerate().skip(3) {
            assert_eq!(k.label.as_ref(), format!("[{i}] --"));
            assert_eq!(k.raw.len(), 128);
            assert!(k.is_empty_for_filter(), "a zeroed slot is empty for the filter");
            assert!(k.diags.is_empty(), "a genuinely blank slot has nothing to report");
        }
        assert_eq!(kids[3].extent.min_byte(), Some(2 * 512 + 3 * 128));
    });
}

#[test]
fn every_attribute_bit_gets_its_own_node() {
    with_fixture("gpt-basic.img", |src| {
        let root = GptProbe.open(src.clone(), 0).root();
        let kids = entries(&root, &src);
        let attrs = kids[0].find_child("attributes").expect("attributes");
        // `sgdisk -i 1` prints "Attribute flags: 0000000000000000".
        assert_eq!(attrs.value, Value::Uint(0));
        let bits = attrs.children.resolved().expect("bits");
        assert_eq!(bits.len(), 64);
        assert!(bits.iter().all(|b| b.value == Value::Bool(false)));
        assert!(bits.iter().any(|b| b.label.contains("legacy_bios_bootable")));
        assert!(bits.iter().any(|b| b.label.contains("no_automount")));
        assert_eq!(attrs.status, Status::Ok);
    });
}

#[test]
fn links_resolve_to_the_bytes_they_name() {
    with_fixture("gpt-basic.img", |src| {
        let root = GptProbe.open(src.clone(), 0).root();
        let h = root.find_child("primary header").unwrap();

        // alternate_lba 131071 * 512 = 67_108_352 = 0x3FFFE00, which is where
        // `xxd -s 0x3FFFE00 -l 8` finds the second "EFI PART".
        let alt = h.find_child("alternate_lba").unwrap().links.first().expect("backup link");
        assert_eq!(alt.raw, 131_071);
        assert_eq!(alt.resolved, Some(0x3FF_FE00));

        let arr = h.find_child("entries_lba").unwrap().links.first().expect("array link");
        assert_eq!(arr.resolved, Some(1024));

        // Partition 1 starts at LBA 2048 -> 1 MiB, which `sgdisk -i 1` prints as
        // "First sector: 2048 (at 1024.0 KiB)".
        let kids = entries(&root, &src);
        let first = kids[0].find_child("first_lba").unwrap().links.first().expect("volume link");
        assert_eq!(first.raw, 2048);
        assert_eq!(first.resolved, Some(1_048_576));
    });
}

#[test]
fn a_corrupted_header_crc_shows_stored_against_computed_and_hides_nothing() {
    with_fixture("gpt-badcrc.img", |src| {
        // The fixture has DE AD BE EF written over the four CRC bytes at file
        // offset 528 (LBA 1 + 0x10); everything else is byte-identical to
        // gpt-basic.img.
        assert!(GptProbe.probe(&*src, 0) >= 80, "a broken CRC does not make it stop being a GPT");
        let root = GptProbe.open(src.clone(), 0).root();
        assert_tree_invariants(&root);

        let h = root.find_child("primary header").unwrap();
        let crc = h.find_child("header_crc32").unwrap();
        assert_eq!(crc.value, Value::Uint(0xEFBE_ADDE), "stored: little-endian DE AD BE EF");
        let d = crc.derived.clone().expect("a computed value");
        assert!(!d.matches);
        // gpt-badcrc.img is a byte copy of gpt-basic.img with only those four bytes
        // changed, so the CRC we compute here must equal the one sgdisk stored in
        // the uncorrupted image.
        let mut hdr = read_at(&src, 512, 92);
        hdr[16..20].fill(0);
        assert_eq!(d.value, Value::Uint(crc32_reference(&hdr) as u64));
        assert_eq!(crc.status, Status::Bad);
        assert!(crc.diags.iter().any(|x| x.message.contains("stored") && x.message.contains("computed")));

        // Nothing was refused: every other field still reads exactly as in the
        // uncorrupted image, and the entry array is intact.
        assert_eq!(guid_of(h, "disk_guid"), "89abcdef-0123-4567-89ab-cdef01234567");
        assert_eq!(u64_at(h, &["last_usable_lba"]), Some(131_038));
        assert_eq!(u64_at(h, &["my_lba"]), Some(1));
        assert!(h.find_child("entries_crc32").unwrap().derived.as_ref().unwrap().matches);
        let kids = entries(&root, &src);
        assert_eq!(text_at(&kids[0], &["name"]).as_deref(), Some("EFI System"));

        // The backup's own CRC is untouched, which is the recovery path.
        let b = root.find_child("backup header").unwrap();
        assert!(b.find_child("header_crc32").unwrap().derived.as_ref().unwrap().matches);
        // And the two headers still agree on everything that must match: only the
        // checksum of one of them was damaged.
        assert!(diff_headers(h, b).is_empty());
    });
}

#[test]
fn notes_the_protective_mbr() {
    with_fixture("gpt-basic.img", |src| {
        // `xxd -s 0x1be -l 16` -> 00 00 02 00 ee 28 20 08 01 00 00 00 ff ff 01 00:
        // one 0xEE entry, start LBA 1, 0x1FFFF = 131071 sectors on a 131072-sector
        // image.
        let root = GptProbe.open(src, 0).root();
        let d = root
            .diags
            .iter()
            .find(|d| d.message.contains("protective MBR"))
            .expect("the GPT must say whether LBA 0 protects it");
        assert!(d.message.contains("well formed"), "{}", d.message);
        assert!(d.message.contains("131071"));
        assert_eq!(d.status, Status::Info);
    });
}

#[test]
fn reads_the_single_partition_of_the_fat32_image() {
    with_fixture("gpt-fat32.img", |src| {
        let root = GptProbe.open(src.clone(), 0).root();
        assert_tree_invariants(&root);
        let h = root.find_child("primary header").unwrap();

        // `sgdisk -p gpt-fat32.img` prints a disk GUID, but make-fixtures.sh passes
        // no -U here, so it is a fresh random one on every regeneration. What is
        // stable is that it is a real GUID and that both CRCs verify.
        assert_ne!(guid_of(h, "disk_guid"), "00000000-0000-0000-0000-000000000000");
        let array = read_at(&src, 2 * 512, 128 * 128);
        assert_eq!(u64_at(h, &["entries_crc32"]), Some(crc32_reference(&array) as u64));
        assert!(h.find_child("entries_crc32").unwrap().derived.as_ref().unwrap().matches);
        assert!(h.find_child("header_crc32").unwrap().derived.as_ref().unwrap().matches);

        // `sgdisk -i 1`: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 (Microsoft basic data),
        // sectors 2048..131038, name 'DATA'.
        let kids = entries(&root, &src);
        assert_eq!(guid_of(&kids[0], "type_guid"), "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7");
        assert_eq!(u64_at(&kids[0], &["first_lba"]), Some(2048));
        assert_eq!(u64_at(&kids[0], &["last_lba"]), Some(131_038));
        assert_eq!(text_at(&kids[0], &["name"]).as_deref(), Some("DATA"));
        assert!(kids[0].label.contains("Microsoft basic data"));
        assert_eq!(guids::type_label(&guids::MS_BASIC_DATA), Some("Microsoft basic data"));
        assert_eq!(kids[1].label.as_ref(), "[1] --");
        assert!(!root.deep_status().is_anomaly());
    });
}

#[test]
fn garbage_and_zeros_never_panic_and_never_pretend() {
    for name in ["garbage.img", "zeros.img"] {
        with_fixture(name, |src| {
            assert_eq!(GptProbe.probe(&*src, 0), 0, "{name} must not be claimed as a GPT");
            // Forcing the interpretation must still produce a labelled tree.
            let root = GptProbe.open(src.clone(), 0).root();
            assert_tree_invariants(&root);
            let h = root.find_child("primary header").expect("a header node either way");
            assert_eq!(h.children.resolved().map(|c| c.len()), Some(15), "14 fields plus the tail");
            assert!(root.deep_status().is_anomaly(), "no signature must read as a finding");
            let _ = entries(&root, &src);
        });
    }
}

#[test]
fn an_mbr_disk_is_not_claimed_as_a_gpt() {
    with_fixture("mbr-fat32.img", |src| {
        // LBA 1 of a FAT32-in-MBR disk is filesystem data, not "EFI PART".
        assert_eq!(GptProbe.probe(&*src, 0), 0);
    });
}

// Asserts about the registry as a whole, so it needs the MBR module compiled in.
#[cfg(feature = "mbr")]
#[test]
fn the_registry_prefers_gpt_over_the_protective_mbr() {
    with_fixture("gpt-basic.img", |src| {
        let reg = blktamper_formats::registry();
        let candidates = reg.candidates(&*src, 0);
        // Both match at sector 0 — a protective MBR really is an MBR — and the GPT
        // has to win, because the MBR is the decoy.
        assert!(candidates.iter().any(|(id, _)| *id == blktamper_formats::mbr::ID));
        let best = reg.best(&*src, 0).expect("something must match");
        assert_eq!(best.0, gpt::ID);
        assert!(best.1 >= 80, "score was {}", best.1);
    });
}
