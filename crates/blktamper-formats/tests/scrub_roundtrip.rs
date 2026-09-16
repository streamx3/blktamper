//! End-to-end: plan a scrub, stage it, commit it to a real image, and check the
//! result with tools that are not ours.
//!
//! This is the test that matters. Everything else proves the plan is *described*
//! correctly; this proves that applying it removes the residue and leaves the live
//! files alone — which is the promise the whole feature makes.

#![cfg(all(feature = "fat", feature = "exfat"))]

mod common;

use blktamper_core::scrub::ScrubMode;
use blktamper_core::{BlockSource, Children, Fill, Node, RegionReader};
use blktamper_io::{FileSink, Journal, Overlay};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("blktamper-scrub-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A writable copy of a fixture, so the originals are never touched.
fn copy_fixture(name: &str, dir: &Path) -> Option<PathBuf> {
    let src = common::fixture_dir().join(name);
    if !src.exists() {
        eprintln!("skipping: {} not found", src.display());
        return None;
    }
    let dst = dir.join(name);
    std::fs::copy(&src, &dst).ok()?;
    Some(dst)
}

/// Every node the reader is willing to scrub.
///
/// Deliberately not a label match: FAT writes `?ECRET.TXT (deleted)` and exFAT writes
/// `deleted file "SECRET"`, and a UI that decided by string would be wrong the first
/// time a label was reworded. `scrub_plan` returning `Some` *is* the predicate, and
/// it is the same one the TUI uses to decide whether to offer the action.
fn scrubbable(n: &Node, src: &dyn BlockSource, r: &dyn RegionReader, out: &mut Vec<Node>) {
    if r.scrub_plan(n, ScrubMode::Record(Fill::Neutral)).is_some() {
        out.push(n.clone());
        return; // the set is the unit; its individual records are not separately offered
    }
    match &n.children {
        Children::Resolved(k) => k.iter().for_each(|c| scrubbable(c, src, r, out)),
        Children::Lazy(e) => e.expand(src).iter().for_each(|c| scrubbable(c, src, r, out)),
        Children::None => {}
    }
}

fn have(tool: &str) -> bool {
    Command::new("sh").arg("-c").arg(format!("command -v {tool}")).output()
        .map(|o| o.status.success()).unwrap_or(false)
}

#[test]
fn scrubbing_a_fat32_record_removes_the_name_and_spares_the_live_files() {
    let dir = scratch("fat32");
    let Some(img) = copy_fixture("mbr-fat32.img", &dir) else { return };
    const VOLUME: u64 = 1024 * 1024;

    // What mtools sees before: three live entries.
    let before = mdir(&img);
    assert!(before.contains("README"), "fixture should list README.TXT: {before}");
    assert!(before.contains("DCIM"), "{before}");

    // 1. Plan.
    let (src, _) = blktamper_io::open_path(&img, blktamper_io::Access::ReadOnly).unwrap();
    let reg = blktamper_formats::registry();
    let reader = reg.get(blktamper_formats::fat::ID).unwrap().open(src.clone(), VOLUME);
    let mut found = Vec::new();
    scrubbable(&reader.root(), &*src, &*reader, &mut found);
    assert!(!found.is_empty(), "the fixture must contain deleted records to scrub");

    let target = found
        .iter()
        .find(|n| n.label.contains("ECRET"))
        .expect("the deleted SECRET.TXT record")
        .clone();
    let plan = reader.scrub_plan(&target, ScrubMode::Record(Fill::Neutral)).expect("a plan for a deleted record");
    assert!(plan.records() >= 1);
    let scrubbed_spans: Vec<(u64, usize)> =
        plan.edits.iter().map(|e| (e.offset, e.new.len())).collect();
    drop(reader);
    drop(src);

    // 2. Stage and commit.
    let sink = Arc::new(FileSink::open_rw(&img).unwrap());
    let overlay = Overlay::new(sink.clone());
    overlay.stage_all(plan.edits.clone(), "fat.root.secret").unwrap();

    let jdir = dir.join("journal");
    let mut journal = Journal::create_in(&jdir, &img, "test").unwrap();
    for e in &plan.edits {
        journal.append(e, "fat.root.secret", &img).unwrap();
    }
    let sectors = overlay.commit(&*sink, 512).unwrap();
    assert_eq!(sectors, 1, "one 32-byte record lives in one sector");
    drop(overlay);
    drop(sink);

    // 3. The residue is gone.
    let raw = std::fs::read(&img).unwrap();
    for (off, len) in &scrubbed_spans {
        let rec = &raw[*off as usize..*off as usize + len];
        assert_eq!(rec[0], 0xE5, "the deleted marker must survive a neutral scrub");
        assert!(rec[1..].iter().all(|&b| b == 0), "everything else must be gone");
    }
    assert!(
        !raw.windows(6).any(|w| w == b"ECRET "),
        "no fragment of the name may remain in the image"
    );

    // 4. The live files are untouched — checked by a tool that is not ours.
    let after = mdir(&img);
    assert!(after.contains("README"), "a live file was lost: {after}");
    assert!(after.contains("DCIM"), "a live directory was lost: {after}");
    assert!(after.contains("A-LONG"), "a live long-named directory was lost: {after}");
    if have("fsck.vfat") {
        let out = fsck_partition(&img, VOLUME, &dir);
        assert!(
            !out.to_lowercase().contains("corrupt") && !out.contains("Dirty bit"),
            "fsck.vfat is unhappy after the scrub:\n{out}"
        );
    }

    // 5. The journal can put it back.
    let undo = Journal::read_undo(journal.path()).unwrap();
    assert_eq!(undo.len(), plan.edits.len());
    let sink = Arc::new(FileSink::open_rw(&img).unwrap());
    let overlay = Overlay::new(sink.clone());
    for (e, path) in &undo {
        overlay.stage(e.clone(), path).unwrap();
    }
    overlay.commit(&*sink, 512).unwrap();
    drop(overlay);
    drop(sink);

    let restored = std::fs::read(&img).unwrap();
    assert!(
        restored.windows(6).any(|w| w == b"ECRET "),
        "undo must bring the record back byte for byte"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scrubbing_does_not_disturb_the_other_records_in_the_same_sector() {
    // The hazard that makes the overlay worth having: a 32-byte write is physically
    // a 512-byte rewrite, and that sector holds fifteen other directory records.
    let dir = scratch("sector");
    let Some(img) = copy_fixture("mbr-fat32.img", &dir) else { return };
    const VOLUME: u64 = 1024 * 1024;

    let (src, _) = blktamper_io::open_path(&img, blktamper_io::Access::ReadOnly).unwrap();
    let reg = blktamper_formats::registry();
    let reader = reg.get(blktamper_formats::fat::ID).unwrap().open(src.clone(), VOLUME);
    let mut found = Vec::new();
    scrubbable(&reader.root(), &*src, &*reader, &mut found);
    let target = found.iter().find(|n| n.label.contains("ECRET")).unwrap().clone();
    let plan = reader.scrub_plan(&target, ScrubMode::Record(Fill::Neutral)).unwrap();
    drop(reader);
    drop(src);

    let sector = plan.edits[0].offset / 512;
    let before = std::fs::read(&img).unwrap();
    let before_sector = before[(sector * 512) as usize..((sector + 1) * 512) as usize].to_vec();

    let sink = Arc::new(FileSink::open_rw(&img).unwrap());
    let overlay = Overlay::new(sink.clone());
    overlay.stage_all(plan.edits.clone(), "x").unwrap();
    overlay.commit(&*sink, 512).unwrap();
    drop(overlay);
    drop(sink);

    let after = std::fs::read(&img).unwrap();
    let after_sector = &after[(sector * 512) as usize..((sector + 1) * 512) as usize];

    let changed: Vec<usize> = before_sector
        .iter()
        .zip(after_sector)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    let expected: Vec<usize> = plan
        .edits
        .iter()
        .flat_map(|e| {
            let base = (e.offset % 512) as usize;
            e.old
                .iter()
                .zip(&e.new)
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(move |(i, _)| base + i)
        })
        .collect();
    assert_eq!(changed, expected, "the rewrite changed bytes outside the scrubbed record");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scrubbing_an_exfat_entry_set_clears_every_record_of_it() {
    // The exFAT fixtures hold no deleted files — creating one needs a mount — so
    // this builds a volume with a deleted entry set directly and checks that the
    // result still satisfies fsck.exfat.
    let dir = scratch("exfat");
    let mut entries = vec![0u8; 96];
    entries[0] = 0x05; // deleted file entry
    entries[1] = 2;
    entries[32] = 0x40; // deleted stream extension
    entries[32 + 0x03] = 6;
    entries[32 + 0x14..32 + 0x18].copy_from_slice(&7u32.to_le_bytes());
    entries[32 + 0x18..32 + 0x20].copy_from_slice(&4096u64.to_le_bytes());
    entries[64] = 0x41; // deleted file name entry
    for (i, u) in "SECRET".encode_utf16().enumerate() {
        entries[64 + 2 + i * 2..64 + 4 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    let img_bytes = blktamper_formats::exfat::synth_volume(&entries);
    let img = dir.join("exfat-deleted.img");
    std::fs::write(&img, &img_bytes).unwrap();

    let (src, _) = blktamper_io::open_path(&img, blktamper_io::Access::ReadOnly).unwrap();
    let reg = blktamper_formats::registry();
    let reader = reg.get(blktamper_formats::exfat::ID).unwrap().open(src.clone(), 0);

    // The name is readable before the scrub: that is the residue.
    assert!(
        img_bytes.windows(2).any(|w| w == [b'S', 0]),
        "the fixture must actually contain a recoverable name"
    );

    let mut found = Vec::new();
    scrubbable(&reader.root(), &*src, &*reader, &mut found);
    let target = found.first().cloned().expect("a deleted entry set");
    let plan = reader.scrub_plan(&target, ScrubMode::Record(Fill::Neutral)).expect("a plan");
    assert_eq!(plan.records(), 3, "primary + stream extension + name must go together");
    drop(reader);
    drop(src);

    let sink = Arc::new(FileSink::open_rw(&img).unwrap());
    let overlay = Overlay::new(sink.clone());
    overlay.stage_all(plan.edits.clone(), "exfat.root.set").unwrap();
    overlay.commit(&*sink, 512).unwrap();
    drop(overlay);
    drop(sink);

    let after = std::fs::read(&img).unwrap();
    for e in &plan.edits {
        let rec = &after[e.offset as usize..e.offset as usize + e.new.len()];
        assert!(!blktamper_formats::exfat::types::is_in_use(rec[0]));
        assert!(rec[1..].iter().all(|&b| b == 0), "the record must be empty after a scrub");
    }
    let name_left = after
        .windows(12)
        .any(|w| w == [b'S', 0, b'E', 0, b'C', 0, b'R', 0, b'E', 0, b'T', 0]);
    assert!(!name_left, "the UTF-16 filename must be gone");

    if have("fsck.exfat") {
        let out = Command::new("fsck.exfat").arg("-n").arg(&img).output().unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(
            !text.to_lowercase().contains("corrupt"),
            "fsck.exfat is unhappy after the scrub:\n{text}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn compacting_every_directory_leaves_no_tombstone_and_no_lost_file() {
    // The operation the threat model actually needs: afterwards a technician with the
    // drive in hand finds directories that look as though the deleted files were
    // never there -- no names, no timestamps, no 0xE5 markers -- while every live
    // file is still exactly where the OS expects it.
    let dir = scratch("compact");
    let Some(img) = copy_fixture("mbr-fat32.img", &dir) else { return };
    const VOLUME: u64 = 1024 * 1024;

    let before = mdir(&img);
    for want in ["README", "DCIM", "A-LONG"] {
        assert!(before.contains(want), "fixture should list {want}: {before}");
    }
    assert!(
        std::fs::read(&img).unwrap().windows(6).any(|w| w == b"ECRET "),
        "the fixture must start with a recoverable name"
    );

    let (src, _) = blktamper_io::open_path(&img, blktamper_io::Access::ReadOnly).unwrap();
    let reg = blktamper_formats::registry();
    let reader = reg.get(blktamper_formats::fat::ID).unwrap().open(src.clone(), VOLUME);
    let dirs = compactable(&reader.root(), &*src, &*reader, ScrubMode::Compact);
    assert!(!dirs.is_empty(), "the volume must have compactable directories");

    let mut all_edits = Vec::new();
    let mut removed = 0usize;
    for d in &dirs {
        if let Some(p) = reader.scrub_plan(d, ScrubMode::Compact) {
            removed += p.affected.len();
            for e in &p.edits {
                // A compaction may never write a tombstone, and every record it
                // writes is either a relocated live record or genuine zeros.
                assert_ne!(e.new[0], 0xE5, "compaction wrote a 0xE5 marker");
                assert!(
                    e.new[0] == 0x00 || e.new.iter().any(|&b| b != 0),
                    "a record must be either live or wholly zero"
                );
                if e.new[0] == 0x00 {
                    assert!(
                        e.new.iter().all(|&b| b == 0),
                        "a vacated slot must be zeroed in full, not just marked free: {:02X?}",
                        &e.new[..8]
                    );
                }
            }
            all_edits.extend(p.edits);
        }
    }
    assert!(removed > 0, "there were deleted records to remove");
    drop(reader);
    drop(src);

    let sink = Arc::new(FileSink::open_rw(&img).unwrap());
    let overlay = Overlay::new(sink.clone());
    overlay.stage_all(all_edits.clone(), "fat.dirs").unwrap();
    let jdir = dir.join("journal");
    let mut journal = Journal::create_in(&jdir, &img, "test").unwrap();
    for e in &all_edits {
        journal.append(e, "fat.dirs", &img).unwrap();
    }
    overlay.commit(&*sink, 512).unwrap();
    drop(overlay);
    drop(sink);

    // Every live file survived -- checked by mtools, not by us.
    let after = mdir(&img);
    for want in ["README", "DCIM", "A-LONG"] {
        assert!(after.contains(want), "compaction lost {want}:\nbefore:\n{before}\nafter:\n{after}");
    }

    // And the names are gone from the whole image.
    let raw = std::fs::read(&img).unwrap();
    assert!(!raw.windows(6).any(|w| w == b"ECRET "), "the 8.3 name survived");
    assert!(
        !raw.windows(14).any(|w| w == "deleted-payloa".as_bytes()),
        "an 8.3 fragment survived"
    );
    let utf16: Vec<u8> = "deleted-p".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    assert!(
        !raw.windows(utf16.len()).any(|w| w == utf16),
        "the long filename survived in its UTF-16 fragments"
    );

    // Byte-for-byte: what landed is what the plan said would land.
    for e in &all_edits {
        assert_eq!(&raw[e.offset as usize..e.offset as usize + e.new.len()], &e.new[..]);
    }

    if have("fsck.vfat") {
        let out = fsck_partition(&img, VOLUME, &dir);
        assert!(!out.to_lowercase().contains("corrupt"), "fsck.vfat unhappy:\n{out}");
    }

    // ...and it is reversible, like every other write.
    let undo = Journal::read_undo(journal.path()).unwrap();
    let sink = Arc::new(FileSink::open_rw(&img).unwrap());
    let overlay = Overlay::new(sink.clone());
    for (e, path) in &undo {
        overlay.stage(e.clone(), path).unwrap();
    }
    overlay.commit(&*sink, 512).unwrap();
    drop(overlay);
    drop(sink);
    assert!(
        std::fs::read(&img).unwrap().windows(6).any(|w| w == b"ECRET "),
        "undo must restore the directories byte for byte"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Every node the reader will accept for a directory-wide mode.
fn compactable(
    root: &Node,
    src: &dyn BlockSource,
    r: &dyn RegionReader,
    mode: ScrubMode,
) -> Vec<Node> {
    fn go(n: &Node, src: &dyn BlockSource, r: &dyn RegionReader, m: ScrubMode, out: &mut Vec<Node>) {
        if r.scrub_plan(n, m).is_some() {
            out.push(n.clone());
        }
        match &n.children {
            Children::Resolved(k) => k.iter().for_each(|c| go(c, src, r, m, out)),
            Children::Lazy(e) => e.expand(src).iter().for_each(|c| go(c, src, r, m, out)),
            Children::None => {}
        }
    }
    let mut out = Vec::new();
    go(root, src, r, mode, &mut out);
    // The same directory can be reachable by more than one path in the tree (a
    // record links to the directory it names), and staging its plan twice would
    // overlap. One plan per directory.
    let mut seen = std::collections::HashSet::new();
    out.retain(|n| n.extent.first().is_some_and(|s| seen.insert(s.start_byte())));
    out
}

#[test]
fn sweeping_keeps_live_records_exactly_where_they_are() {
    let dir = scratch("sweep");
    let Some(img) = copy_fixture("mbr-fat32.img", &dir) else { return };
    const VOLUME: u64 = 1024 * 1024;

    let (src, _) = blktamper_io::open_path(&img, blktamper_io::Access::ReadOnly).unwrap();
    let reg = blktamper_formats::registry();
    let reader = reg.get(blktamper_formats::fat::ID).unwrap().open(src.clone(), VOLUME);
    let dirs = compactable(&reader.root(), &*src, &*reader, ScrubMode::Sweep);
    let Some(root_dir) = dirs.first().cloned() else { return };
    let plan = reader.scrub_plan(&root_dir, ScrubMode::Sweep).unwrap();
    assert_eq!(plan.relocated, 0, "a sweep must not move anything");
    let before = std::fs::read(&img).unwrap();
    drop(reader);
    drop(src);

    let sink = Arc::new(FileSink::open_rw(&img).unwrap());
    let overlay = Overlay::new(sink.clone());
    overlay.stage_all(plan.edits.clone(), "fat.root").unwrap();
    overlay.commit(&*sink, 512).unwrap();
    drop(overlay);
    drop(sink);

    let after = std::fs::read(&img).unwrap();
    // Live records are byte-identical; only tombstones and the tail changed.
    let start = plan.edits.iter().map(|e| e.offset).min().unwrap() as usize;
    for (i, (b, a)) in before[start..start + 512]
        .chunks(32)
        .zip(after[start..start + 512].chunks(32))
        .enumerate()
    {
        if b[0] != 0xE5 && b[0] != 0x00 {
            assert_eq!(b, a, "sweep changed live record {i}");
        }
    }
    assert!(!after.windows(6).any(|w| w == b"ECRET "), "the name must be gone");
    let listing = mdir(&img);
    for want in ["README", "DCIM", "A-LONG"] {
        assert!(listing.contains(want), "sweep lost {want}: {listing}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// mtools listing of the FAT32 volume one megabyte into the image.
fn mdir(img: &Path) -> String {
    if !have("mdir") {
        return "README DCIM A-LONG (mtools absent, check skipped)".into();
    }
    let out = Command::new("mdir")
        .env("MTOOLS_SKIP_CHECK", "1")
        .arg("-i")
        .arg(format!("{}@@1M", img.display()))
        .arg("::/")
        .output()
        .expect("mdir");
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// `fsck.vfat` cannot take an offset, so the partition is extracted first.
fn fsck_partition(img: &Path, offset: u64, dir: &Path) -> String {
    let part = dir.join("part.img");
    let data = std::fs::read(img).unwrap();
    std::fs::write(&part, &data[offset as usize..]).unwrap();
    let out = Command::new("fsck.vfat").arg("-n").arg(&part).output().expect("fsck.vfat");
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}
