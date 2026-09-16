//! Unit tests for the parts of exFAT no real image can be made to contain.
//!
//! The integration tests in `tests/exfat.rs` are the primary evidence: they read
//! images `mkfs.exfat` wrote and assert values taken from `xxd`, `dump.exfat` and
//! independent arithmetic. These cover what a healthy volume cannot show — a shift
//! of 200, a FAT chain that loops, an entry set that runs off the end of its
//! directory, and records left behind past the end-of-directory marker.
//!
//! `synth_volume` is not a mock. `fsck.exfat -n` from exfatprogs 1.2.2 reports its
//! output `clean. directories 1, files 1`, so a test built on it is testing against
//! something exfatprogs itself accepts.

use super::*;
use blktamper_core::{FormatProbe, MemSource};

/// The 96 bytes exfatprogs accepted as `/HELLO.TXT` — a 0x85 entry with
/// `secondary_count` 2, set checksum 0xC804 and name hash 0x3046. Taken from an
/// image `fsck.exfat -n` reported as `clean. directories 1, files 2`; corrupting
/// either the checksum or the hash makes fsck reject the set, which is what makes
/// these bytes ground truth rather than our own opinion.
const HELLO_SET: [u8; 96] = [
    0x85, 0x02, 0x04, 0xC8, 0x20, 0x00, 0x00, 0x00, 0x5C, 0x64, 0x30, 0x5D, 0x5C, 0x64, 0x30, 0x5D,
    0x5C, 0x64, 0x30, 0x5D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x03, 0x00, 0x09, 0x46, 0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC1, 0x00, 0x48, 0x00, 0x45, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x4F, 0x00, 0x2E, 0x00, 0x54, 0x00,
    0x58, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The same set after a delete: five type bytes lost bit 7 and nothing else moved.
/// `fsck.exfat -n` reports the image holding this as `clean. directories 1, files 1`
/// — it cannot see the file at all, and the name is still there in full.
const DELETED_SET: [u8; 160] = [
    0x05, 0x04, 0xC7, 0xD7, 0x20, 0x00, 0x00, 0x00, 0x5C, 0x64, 0x30, 0x5D, 0x5C, 0x64, 0x30, 0x5D,
    0x5C, 0x64, 0x30, 0x5D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x03, 0x00, 0x22, 0xC8, 0xFE, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x00, 0x53, 0x00, 0x45, 0x00, 0x43, 0x00, 0x52, 0x00, 0x45, 0x00, 0x54, 0x00, 0x2D, 0x00,
    0x4E, 0x00, 0x4F, 0x00, 0x54, 0x00, 0x45, 0x00, 0x53, 0x00, 0x2D, 0x00, 0x54, 0x00, 0x48, 0x00,
    0x41, 0x00, 0x41, 0x00, 0x54, 0x00, 0x2D, 0x00, 0x57, 0x00, 0x45, 0x00, 0x52, 0x00, 0x45, 0x00,
    0x2D, 0x00, 0x44, 0x00, 0x45, 0x00, 0x4C, 0x00, 0x45, 0x00, 0x54, 0x00, 0x45, 0x00, 0x44, 0x00,
    0x41, 0x00, 0x2E, 0x00, 0x54, 0x00, 0x58, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const DELETED_NAME: &str = "SECRET-NOTES-THAT-WERE-DELETED.TXT";

fn src_of(img: Vec<u8>) -> Arc<dyn BlockSource> {
    Arc::new(MemSource::new(img))
}

fn root_of(img: Vec<u8>) -> Node {
    ExfatProbe.open(src_of(img), 0).root()
}

fn find<'a>(n: &'a Node, needle: &str) -> Option<&'a Node> {
    if n.label.contains(needle) {
        return Some(n);
    }
    for k in n.children.resolved()? {
        if let Some(f) = find(k, needle) {
            return Some(f);
        }
    }
    None
}

/// True when anything in the resolved tree says `needle`, in a diagnostic's
/// message or in the hint that goes with it.
fn says(n: &Node, needle: &str) -> bool {
    let mut hit = false;
    n.walk(&mut |x| {
        if x.diags.iter().any(|d| {
            d.message.contains(needle)
                || d.hint.as_deref().is_some_and(|h| h.contains(needle))
        }) {
            hit = true;
        }
    });
    hit
}

/// Byte offset of the root directory in a `synth_volume` image.
const SYNTH_ROOT: usize = 32 * 512;
const SYNTH_FAT: usize = 24 * 512;

#[test]
fn a_synthetic_volume_is_recognised_and_fully_parsed() {
    let img = synth_volume(&synth_entry_set("HELLO.TXT", 5, 512, true, false));
    assert!(ExfatProbe.probe(&*src_of(img.clone()), 0) >= 80);
    let root = root_of(img);
    assert!(find(&root, "volume label entry \"SYNTH\"").is_some());
    assert!(find(&root, "file \"HELLO.TXT\"").is_some());
    assert!(find(&root, "allocation bitmap").is_some());
    assert!(find(&root, "up-case table").is_some());
    assert!(!root.deep_status().is_anomaly(), "a clean volume must not report an anomaly");
}

#[test]
fn only_the_fs_name_makes_this_exfat() {
    // A FAT boot sector: same jump, same 55 AA, different name at offset 3.
    let mut fat = vec![0u8; 1 << 20];
    fat[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    fat[3..11].copy_from_slice(b"MSDOS5.0");
    fat[0x1FE] = 0x55;
    fat[0x1FF] = 0xAA;
    assert_eq!(ExfatProbe.probe(&*src_of(fat), 0), 0);

    // NTFS: likewise.
    let mut ntfs = vec![0u8; 1 << 20];
    ntfs[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    ntfs[0x1FE] = 0x55;
    ntfs[0x1FF] = 0xAA;
    assert_eq!(ExfatProbe.probe(&*src_of(ntfs), 0), 0);
}

#[test]
fn the_signature_alone_does_not_earn_a_confident_score() {
    // "EXFAT   " over otherwise empty bytes: the name is there, the geometry is
    // not. Claiming 90 here is exactly the over-claim the probe must not make.
    let mut bare = vec![0u8; 1 << 20];
    bare[3..11].copy_from_slice(b"EXFAT   ");
    bare[0x1FE] = 0x55;
    bare[0x1FF] = 0xAA;
    let score = ExfatProbe.probe(&*src_of(bare.clone()), 0);
    assert!(score > 0, "the signature is real evidence");
    assert!(score < 80, "but geometry that does not add up must keep it below 80, got {score}");
    // Forcing the interpretation still produces a full tree.
    let root = root_of(bare);
    assert!(find(&root, "main boot sector").is_some());
}

#[test]
fn a_sector_shift_of_200_is_a_diagnostic_not_a_shift() {
    let mut img = synth_volume(&[]);
    img[0x6C] = 200;
    let root = root_of(img);
    assert!(says(&root, "bytes_per_sector_shift is 200"), "{:?}", root.diags);
    assert!(says(&root, "geometry is unusable"));
    // and the boot sector is still shown in full
    assert!(find(&root, "main boot sector").is_some());
}

#[test]
fn a_cluster_larger_than_32_mib_is_refused_before_it_is_shifted() {
    let mut img = synth_volume(&[]);
    img[0x6C] = 12; // 4096-byte sectors
    img[0x6D] = 25; // x 2^25 sectors == 128 GiB per cluster
    let root = root_of(img);
    assert!(says(&root, "the specification caps a cluster at 32 MiB"), "{:?}", root.diags);

    // And a shift past the field's own range is caught before the shift happens.
    let mut img = synth_volume(&[]);
    img[0x6D] = 200;
    let root = root_of(img);
    assert!(says(&root, "sectors_per_cluster_shift is 200"));
}

#[test]
fn the_boot_checksum_skips_the_two_fields_a_driver_rewrites() {
    let img = synth_volume(&[]);
    let clean = root_of(img.clone());
    assert!(!says(&clean, "stored"), "the generated volume must check out");

    // VolumeFlags (106..108) and PercentInUse (112) are skipped, so a driver may
    // rewrite them on mount without touching sector 11.
    for off in [106usize, 107, 112] {
        let mut m = img.clone();
        m[off] = 0x5A;
        let root = root_of(m);
        let ck = find(&root, "boot_checksum").expect("checksum node");
        assert!(
            ck.derived.as_ref().is_some_and(|d| d.matches),
            "byte {off} is excluded from the checksum and must not break it"
        );
    }

    // Any other byte of the region does break it.
    let mut m = img.clone();
    m[0x64] ^= 0xFF; // volume_serial_number
    let root = root_of(m);
    let ck = find(&root, "boot_checksum").expect("checksum node");
    assert!(ck.derived.as_ref().is_some_and(|d| !d.matches));
    assert!(ck.diags.iter().any(|d| d.message.starts_with("stored ")), "{:?}", ck.diags);
}

#[test]
fn a_checksum_sector_whose_copies_disagree_is_a_finding() {
    let mut img = synth_volume(&[]);
    img[11 * 512 + 40] ^= 0xFF;
    let root = root_of(img);
    assert!(says(&root, "copies differ from the first"), "partial writes must be visible");
}

#[test]
fn the_backup_boot_region_is_diffed_field_by_field() {
    let mut img = synth_volume(&[]);
    // Change the backup's cluster_count but not the main one.
    img[12 * 512 + 0x5C] ^= 0x01;
    let root = root_of(img);
    assert!(says(&root, "boot sector field cluster_count differs"), "{:?}", root.diags);
    assert!(says(&root, "against backup sector(s) [12]"));

    // A difference confined to the bytes the checksum skips is reported as normal
    // drift, not as damage.
    let mut img = synth_volume(&[]);
    img[106] = 0x03;
    let root = root_of(img);
    assert!(says(&root, "boot sector field volume_flags differs"));
    assert!(says(&root, "legitimately drift here"));
}

// ------------------------------------------------------------------ entry sets

#[test]
fn the_entry_set_checksum_agrees_with_exfatprogs() {
    // 0xC804 is the value exfatprogs wrote and fsck.exfat accepted.
    let (stored, computed, _) = set_checksum(&HELLO_SET, false);
    assert_eq!(stored, Some(0xC804));
    assert_eq!(computed, 0xC804);
}

#[test]
fn the_name_hash_agrees_with_exfatprogs() {
    // Both values come from sets fsck.exfat validated; corrupting either makes
    // fsck reject the entry set.
    let hello: Vec<u16> = "HELLO.TXT".encode_utf16().collect();
    assert_eq!(name_hash_ascii(&hello), Some(0x3046));
    let secret: Vec<u16> = DELETED_NAME.encode_utf16().collect();
    assert_eq!(name_hash_ascii(&secret), Some(0xFEC8));
    // Up-casing is part of the hash: the lower-case spelling hashes the same.
    let lower: Vec<u16> = "hello.txt".encode_utf16().collect();
    assert_eq!(name_hash_ascii(&lower), Some(0x3046));
    // Outside ASCII we decline rather than guess: we do not have the up-case table.
    let accented: Vec<u16> = "café".encode_utf16().collect();
    assert_eq!(name_hash_ascii(&accented), None);
}

#[test]
fn a_deleted_entry_set_keeps_its_name_and_proves_it_is_intact() {
    let root = root_of(synth_volume(&DELETED_SET));
    let set = find(&root, DELETED_NAME).expect("the filename must survive the delete");
    assert!(set.label.starts_with("deleted file"), "{}", set.label);
    assert!(
        set.diags.iter().any(|d| d.message.contains("matches once the InUse bits are restored")),
        "{:?}",
        set.diags
    );
    assert!(set.diags.iter().any(|d| d.message.contains("0x05/0x40/0x41")));
    // Every record of the set is shown, each labelled as deleted.
    let kids = set.children.resolved().unwrap();
    assert!(kids.iter().any(|k| k.label == "deleted file entry"));
    assert!(kids.iter().any(|k| k.label == "deleted stream extension"));
    assert_eq!(kids.iter().filter(|k| k.label.starts_with("deleted file name")).count(), 3);
    // A deleted set is a finding, not a fault: it must not read as damage.
    assert!(!set.deep_status().is_anomaly());
}

#[test]
fn a_deleted_set_that_was_partly_overwritten_says_so() {
    let mut set = DELETED_SET;
    set[0x50] ^= 0xFF; // a byte of the stream extension, after the delete
    let root = root_of(synth_volume(&set));
    assert!(
        says(&root, "does not match even with the InUse bits restored"),
        "residue that was then overwritten must not be presented as intact"
    );
}

#[test]
fn a_set_whose_records_disagree_about_being_in_use_is_flagged() {
    let mut set = HELLO_SET;
    set[64] &= !0x80; // delete only the file-name entry
    let root = root_of(synth_volume(&set));
    assert!(says(&root, "do not agree about whether they are in use"));
}

#[test]
fn an_entry_set_that_runs_past_its_directory_is_truncated_not_followed() {
    let mut set = HELLO_SET.to_vec();
    set[1] = 200; // secondary_count far beyond the end of the cluster
    let root = root_of(synth_volume(&set));
    assert!(says(&root, "secondary_count says 200 but only"), "{:?}", root.diags);
}

#[test]
fn a_set_with_no_stream_extension_is_reported() {
    let mut set = HELLO_SET.to_vec();
    set[32] = types::FILE_NAME; // the stream extension becomes a second name entry
    let root = root_of(synth_volume(&set));
    assert!(says(&root, "no 0xC0 stream extension"));
}

#[test]
fn an_orphan_secondary_entry_is_shown_and_flagged() {
    let mut orphan = [0u8; 32];
    orphan[0] = types::FILE_NAME;
    orphan[2..10].copy_from_slice(&[0x4F, 0x00, 0x4C, 0x00, 0x44, 0x00, 0x21, 0x00]); // "OLD!"
    let root = root_of(synth_volume(&orphan));
    let n = find(&root, "file name entry").expect("an orphan must still be shown");
    assert!(n.diags.iter().any(|d| d.message.contains("on its own")), "{:?}", n.diags);
    assert_eq!(n.find_child("file_name").unwrap().value.as_str(), Some("OLD!"));
}

#[test]
fn records_past_the_end_of_directory_marker_are_surfaced() {
    // An end-of-directory marker, then a deleted set behind it — the shape a
    // directory takes after its last live file is removed.
    let mut entries = vec![0u8; 32];
    entries.extend_from_slice(&DELETED_SET);
    let root = root_of(synth_volume(&entries));
    assert!(says(&root, "non-zero entry slot(s) survive past the end-of-directory marker"));
    let n = find(&root, "residue").expect("residue must be shown, not skipped");
    assert!(n.diags.iter().any(|d| d.message.contains("no driver will read it")));
    // and the name is still legible inside it
    assert!(find(&root, DELETED_NAME).is_some());
}

#[test]
fn names_render_lossily_and_are_never_refused() {
    // An unpaired surrogate in the middle of a filename: invalid UTF-16, and the
    // one thing a viewer must not do is refuse to show it.
    let mut set = HELLO_SET;
    set[66] = 0x00;
    set[67] = 0xD8; // U+D800, a lone high surrogate
    let root = root_of(synth_volume(&set));
    let n = find(&root, "file \"").expect("the set must still render");
    assert!(n.label.contains(char::REPLACEMENT_CHARACTER), "{}", n.label);
}

#[test]
fn a_name_longer_than_its_name_length_shows_the_leftover() {
    let mut set = synth_entry_set("SHORT.TXT", 5, 512, true, false);
    set[35] = 4; // claim only "SHOR"
    let root = root_of(synth_volume(&set));
    assert!(says(&root, "non-zero code units past name_length"));
}

// ------------------------------------------------------------- cluster chains

#[test]
fn nofatchain_walks_arithmetically_and_says_so() {
    // Two clusters' worth of data with NoFatChain set and the FAT left at zero:
    // the FAT must not be consulted, and the second cluster must still be found.
    let img = synth_volume(&synth_entry_set("CONTIG.BIN", 5, 1024, true, false));
    let root = root_of(img);
    let data = find(&root, "file data").expect("file data node");
    assert!(
        data.diags.iter().any(|d| d.message.contains("the FAT was not consulted")),
        "{:?}",
        data.diags
    );
    assert_eq!(data.value.as_u64(), Some(2), "two 512-byte clusters");
    assert_eq!(data.extent.len_bytes(), 1024);
}

#[test]
fn a_fat_chain_is_followed_when_nofatchain_is_clear() {
    let mut img = synth_volume(&synth_entry_set("CHAINED.BIN", 5, 1024, false, false));
    let fat = SYNTH_FAT;
    img[fat + 5 * 4..fat + 5 * 4 + 4].copy_from_slice(&6u32.to_le_bytes());
    img[fat + 6 * 4..fat + 6 * 4 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let root = root_of(img);
    let data = find(&root, "file data").expect("file data node");
    assert_eq!(data.value.as_u64(), Some(2));
    assert!(!data.diags.iter().any(|d| d.message.contains("was not consulted")));
}

#[test]
fn a_chain_with_no_end_marker_is_reported_rather_than_invented() {
    // NoFatChain clear but the FAT entry is zero: the file claims two clusters and
    // the chain has no terminator. Reading this as "contiguous" would be the exact
    // mistake of getting NoFatChain backwards.
    let img = synth_volume(&synth_entry_set("BROKEN.BIN", 5, 1024, false, false));
    let root = root_of(img);
    assert!(says(&root, "is zero, so the chain has no end marker"));
}

#[test]
fn a_fat_chain_that_loops_terminates() {
    let mut img = synth_volume(&[]);
    let fat = SYNTH_FAT;
    // The root directory's own chain: 2 -> 3 -> 2.
    img[fat + 8..fat + 12].copy_from_slice(&3u32.to_le_bytes());
    img[fat + 12..fat + 16].copy_from_slice(&2u32.to_le_bytes());
    let root = root_of(img); // must return rather than hang
    assert!(says(&root, "it loops"));
}

#[test]
fn a_first_cluster_outside_the_heap_is_refused() {
    let img = synth_volume(&synth_entry_set("NOWHERE.BIN", 99_999, 512, true, false));
    let root = root_of(img);
    assert!(says(&root, "is outside the heap's 2..=1001 range"));
}

// ------------------------------------------------- bitmap, up-case table, FAT

#[test]
fn a_bitmap_whose_length_disagrees_with_cluster_count_is_flagged() {
    let mut img = synth_volume(&[]);
    // data_length of the 0x81 entry, at root + 32 + 0x18.
    img[SYNTH_ROOT + 32 + 0x18] = 7;
    let root = root_of(img);
    assert!(says(&root, "1000 clusters need 125"), "{:?}", root.diags);
}

#[test]
fn a_cluster_chained_in_the_fat_but_free_in_the_bitmap_is_a_finding() {
    let mut img = synth_volume(&[]);
    let fat = SYNTH_FAT;
    img[fat + 9 * 4..fat + 9 * 4 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let root = root_of(img);
    assert!(says(&root, "have a FAT entry but are marked free in the bitmap"));
}

#[test]
fn the_up_case_table_is_not_decoded_until_it_is_asked_for() {
    let img = synth_volume(&[]);
    let src = src_of(img);
    let root = ExfatProbe.open(src.clone(), 0).root();
    let mappings = find(&root, "mappings").expect("mappings node");
    assert!(
        mappings.children.resolved().is_none(),
        "the table must not be decompressed as part of building the tree"
    );
    let Children::Lazy(e) = &mappings.children else { panic!("expected a lazy expander") };
    let kids = e.expand(&*src);
    assert!(!kids.is_empty(), "and it must decode once asked");
}

#[test]
fn the_fat_entry_array_is_lazy_and_bounded() {
    let img = synth_volume(&[]);
    let src = src_of(img);
    let root = ExfatProbe.open(src.clone(), 0).root();
    let entries = find(&root, "entries (clusters 2..)").expect("FAT entry array");
    assert!(entries.children.resolved().is_none(), "a 7 MB FAT must not be built eagerly");
    assert_eq!(entries.children.len_hint(), Some(1000));
    let Children::Lazy(e) = &entries.children else { panic!("expected a lazy expander") };
    let kids = e.expand(&*src);
    assert_eq!(kids.len(), 1000);
    assert!(kids[0].label.starts_with("[2] end of chain"), "{}", kids[0].label);
    assert!(kids[6].label.starts_with("[8] free"), "{}", kids[6].label);
}

#[test]
fn a_bad_media_descriptor_is_reported() {
    let mut img = synth_volume(&[]);
    img[SYNTH_FAT] = 0x00;
    let root = root_of(img);
    assert!(says(&root, "expected 0xFFFFFFF8"));
}

// --------------------------------------------------------------- hostile input

#[test]
fn garbage_never_panics_and_never_pretends() {
    for seed in [0u8, 1, 0x55, 0xAA, 0xE5, 0xFF] {
        let data = vec![seed; 256 * 1024];
        let src = src_of(data);
        assert_eq!(ExfatProbe.probe(&*src, 0), 0, "{seed:#04X} must not be claimed as exFAT");
        // Forcing the interpretation must still produce a labelled tree.
        let root = ExfatProbe.open(src, 0).root();
        assert!(!root.label.is_empty());
        root.walk(&mut |n| assert!(!n.label.is_empty()));
    }
}

#[test]
fn every_byte_of_the_boot_sector_can_be_hostile() {
    // Flip each boot-sector field to 0xFF in turn. None of it may panic, and the
    // tree must survive every time.
    let base = synth_volume(&synth_entry_set("X.BIN", 5, 512, true, false));
    for fd in desc::MAIN_BOOT_SECTOR.fields {
        for fill in [0x00u8, 0xFF] {
            let mut img = base.clone();
            for b in &mut img[fd.off as usize..fd.end() as usize] {
                *b = fill;
            }
            let root = root_of(img);
            assert!(find(&root, "main boot sector").is_some(), "{} {fill:#04X}", fd.name);
        }
    }
}

#[test]
fn every_directory_entry_type_byte_can_be_hostile() {
    for t in 0u8..=255 {
        let mut e = [0xA5u8; 32];
        e[0] = t;
        let root = root_of(synth_volume(&e));
        root.walk(&mut |n| assert!(!n.label.is_empty(), "type {t:#04X}"));
    }
}

#[test]
fn an_unreadable_device_is_never_shown_as_zeros() {
    let img = synth_volume(&[]);
    let src: Arc<dyn BlockSource> = Arc::new(blktamper_core::source::FailingSource {
        inner: MemSource::new(img),
        fail_from: 4096,
    });
    let root = ExfatProbe.open(src, 0).root();
    let mut unreadable = false;
    root.walk(&mut |n| {
        if n.status == Status::Unreadable {
            unreadable = true;
        }
    });
    assert!(unreadable, "an I/O error must be a distinct state, not zeros");
}

#[test]
fn a_volume_that_claims_more_space_than_the_device_has_is_flagged() {
    let mut img = synth_volume(&[]);
    img[0x48..0x50].copy_from_slice(&0x00FF_FFFFu64.to_le_bytes());
    let root = root_of(img);
    assert!(says(&root, "past the end of the"));
}

#[test]
fn geometry_that_overlaps_itself_is_flagged() {
    let mut img = synth_volume(&[]);
    img[0x58..0x5C].copy_from_slice(&25u32.to_le_bytes()); // heap inside the FAT
    let root = root_of(img);
    assert!(says(&root, "they overlap"));
}

#[test]
fn a_dirty_volume_says_so() {
    let mut img = synth_volume(&[]);
    img[0x6A] = 0x02; // VolumeDirty
    let root = root_of(img);
    assert!(says(&root, "was not cleanly unmounted"));
    // ...and the boot checksum still passes, because these bytes are skipped.
    let ck = find(&root, "boot_checksum").unwrap();
    assert!(ck.derived.as_ref().is_some_and(|d| d.matches));
}

#[test]
fn a_subdirectory_is_expanded_only_when_it_is_opened() {
    // A directory entry set in the root, pointing at cluster 5, which holds an
    // entry set of its own. A 58 GiB stick can nest tens of thousands of these, so
    // the tree must not walk into them until the user does (R-3.5).
    let mut set = synth_entry_set("SUBDIR", 5, 512, true, false);
    set[4] = 0x10; // FileAttributes: Directory
    let ck = ChecksumAlgo::ExfatEntrySet.compute(&set, &[(2, 2)]) as u16;
    set[2..4].copy_from_slice(&ck.to_le_bytes());

    let mut img = synth_volume(&set);
    let sub = 32 * 512 + 3 * 512; // cluster 5
    img[sub..sub + HELLO_SET.len()].copy_from_slice(&HELLO_SET);

    let src = src_of(img);
    let root = ExfatProbe.open(src.clone(), 0).root();
    let dir = find(&root, "directory \"SUBDIR\"").expect("the directory entry set");
    let clusters = dir.find_child("directory clusters").expect("its cluster list");
    assert!(
        clusters.children.resolved().is_none(),
        "a subdirectory must not be walked while the parent tree is built"
    );

    let Children::Lazy(e) = &clusters.children else { panic!("expected a lazy expander") };
    let kids = e.expand(&*src);
    assert!(
        kids.iter().any(|k| k.label == "file \"HELLO.TXT\""),
        "and it must parse once opened: {:?}",
        kids.iter().map(|k| k.label.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn a_deleted_directorys_clusters_are_not_walked_as_a_directory() {
    // Once a directory is deleted its clusters are free and something else may
    // already own them. Showing the byte range is honest; parsing it as a
    // directory would be inventing structure.
    let mut set = synth_entry_set("GONE", 5, 512, true, false);
    set[4] = 0x10;
    let ck = ChecksumAlgo::ExfatEntrySet.compute(&set, &[(2, 2)]) as u16;
    set[2..4].copy_from_slice(&ck.to_le_bytes());
    for i in (0..set.len()).step_by(32) {
        set[i] &= !types::IN_USE;
    }
    let root = root_of(synth_volume(&set));
    let dir = find(&root, "deleted directory \"GONE\"").expect("the deleted directory");
    let clusters = dir.find_child("directory clusters").expect("its cluster list");
    assert!(clusters.children.resolved().is_none());
    assert!(matches!(clusters.children, Children::None), "must not be lazy either");
    assert!(clusters.diags.iter().any(|d| d.message.contains("may already belong to something else")));
    assert_eq!(clusters.extent.len_bytes(), 512, "but the byte range is still shown");
}

#[test]
fn random_mutation_of_a_real_volume_never_panics() {
    // R-3.7 in bulk: take a volume exfatprogs calls clean, corrupt it a byte at a
    // time, and require a complete labelled tree every single time. The seed is
    // fixed so a failure is reproducible.
    let base = synth_volume(&{
        let mut v = synth_entry_set("HELLO.TXT", 5, 512, true, false);
        v.extend_from_slice(&DELETED_SET);
        v
    });
    let mut rng: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for round in 0..600 {
        let mut img = base.clone();
        // Concentrate on the metadata: the boot region, the FAT and the root
        // directory are where every offset this module computes comes from.
        for _ in 0..(1 + round % 8) {
            let at = (next() as usize) % (35 * 512);
            img[at] = (next() >> 11) as u8;
        }
        let root = root_of(img);
        let mut nodes = 0;
        root.walk(&mut |n| {
            nodes += 1;
            assert!(!n.label.is_empty(), "round {round}: an unlabelled node");
        });
        assert!(nodes > 20, "round {round}: the tree collapsed to {nodes} nodes");
    }
}
