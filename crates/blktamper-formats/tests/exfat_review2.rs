//! (compiled only with the `exfat` feature)
#![cfg(feature = "exfat")]

//! Second independent adversarial pass (review scratch, round 2).
//!
//! Deliberately targets what `exfat_adversarial.rs` does not: FAT-chained
//! recursion, meta records pointing at hostile clusters, huge declared lengths,
//! entry sets that overrun the last slot, invalid UTF-16 names, and probe
//! over-claiming on non-exFAT images.

use blktamper_core::{BlockSource, Children, FormatProbe, MemSource, Node, RenderCtx};
use blktamper_formats::exfat::{synth_entry_set, synth_volume, ExfatProbe};
use std::sync::Arc;

const BPS: usize = 512;
const HEAP_OFF: usize = 32;
const FAT_OFF: usize = 24;

fn cluster(n: usize) -> usize {
    HEAP_OFF * BPS + (n - 2) * BPS
}

fn fat_set(img: &mut [u8], c: usize, v: u32) {
    let o = FAT_OFF * BPS + c * 4;
    img[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn walk(node: &Node, src: &dyn BlockSource, depth: u32, seen: &mut usize, labels: &mut Vec<String>) {
    *seen += 1;
    if *seen > 300_000 || depth > 40 {
        return;
    }
    labels.push(node.label.to_string());
    let ctx = RenderCtx::default();
    let _ = blktamper_core::render::render_value(node, &ctx);
    let _ = blktamper_core::render::render_raw(node, 48);
    match &node.children {
        Children::None => {}
        Children::Resolved(k) => k.iter().for_each(|c| walk(c, src, depth + 1, seen, labels)),
        Children::Lazy(e) => {
            e.expand(src).iter().for_each(|c| walk(c, src, depth + 1, seen, labels))
        }
    }
}

fn drive(img: Vec<u8>) -> (Vec<String>, usize) {
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(img));
    let _ = ExfatProbe.probe(&*src, 0);
    let root = ExfatProbe.open(src.clone(), 0).root();
    let mut seen = 0;
    let mut labels = Vec::new();
    walk(&root, &*src, 0, &mut seen, &mut labels);
    (labels, seen)
}

fn dir_set(name: &str, first_cluster: u32, length: u64, no_fat_chain: bool) -> Vec<u8> {
    let mut s = synth_entry_set(name, first_cluster, length, no_fat_chain, false);
    s[4..6].copy_from_slice(&0x0010u16.to_le_bytes());
    s[2..4].copy_from_slice(&[0, 0]);
    let spec = &blktamper_formats::exfat::desc::ENTRY_SET_CHECKSUM;
    let ck = spec.algo.compute(&s, spec.exclude) as u16;
    s[2..4].copy_from_slice(&ck.to_le_bytes());
    s
}

/// A FAT-chained directory whose chain loops back on itself, and two directories
/// that point at each other. Neither may hang or overflow the stack.
#[test]
fn fat_chained_recursion() {
    // Self-loop via the FAT: cluster 6 -> 6.
    let mut img = synth_volume(&dir_set("SELF", 6, 4 * BPS as u64, false));
    fat_set(&mut img, 6, 6);
    let dir = dir_set("SELF", 6, 4 * BPS as u64, false);
    img[cluster(6)..cluster(6) + dir.len()].copy_from_slice(&dir);
    let (labels, seen) = drive(img);
    assert!(seen < 300_000, "self-looping FAT directory expanded {seen} nodes");
    assert!(labels.iter().any(|l| l.contains("SELF")));

    // Mutual recursion: A in cluster 6 contains B in cluster 7, B contains A.
    let mut img = synth_volume(&dir_set("DIR-A", 6, BPS as u64, true));
    let b = dir_set("DIR-B", 7, BPS as u64, true);
    img[cluster(6)..cluster(6) + b.len()].copy_from_slice(&b);
    let a = dir_set("DIR-A", 6, BPS as u64, true);
    img[cluster(7)..cluster(7) + a.len()].copy_from_slice(&a);
    let (_, seen) = drive(img);
    assert!(seen < 300_000, "mutually recursive directories expanded {seen} nodes");
}

/// The root's bitmap and up-case records point at hostile clusters with absurd
/// declared lengths.
#[test]
fn hostile_meta_records() {
    for (fc, len) in [
        (0u32, 0u64),
        (1, u64::MAX),
        (2, u64::MAX),
        (999, u64::MAX),
        (1001, 1 << 40),
        (u32::MAX, u64::MAX),
        (1000, 0),
    ] {
        let mut img = synth_volume(&[]);
        let root = cluster(2);
        // bitmap entry is the second record, up-case the third.
        img[root + 32 + 0x14..root + 32 + 0x18].copy_from_slice(&fc.to_le_bytes());
        img[root + 32 + 0x18..root + 32 + 0x20].copy_from_slice(&len.to_le_bytes());
        img[root + 64 + 0x14..root + 64 + 0x18].copy_from_slice(&fc.to_le_bytes());
        img[root + 64 + 0x18..root + 64 + 0x20].copy_from_slice(&len.to_le_bytes());
        let (_, seen) = drive(img);
        assert!(seen > 0 && seen < 300_000, "meta {fc}/{len} produced {seen} nodes");
    }
}

/// An entry set declaring 18 secondaries in the last slot of the directory, and a
/// stream extension with every length field maxed.
#[test]
fn entry_set_overruns_and_absurd_lengths() {
    let mut img = synth_volume(&[]);
    let root = cluster(2);
    // Last 32-byte slot of the root cluster.
    let last = root + BPS - 32;
    img[last] = 0x85;
    img[last + 1] = 18;
    let (_, seen) = drive(img);
    assert!(seen > 0, "overrunning set produced nothing");

    for len in [u64::MAX, 1 << 62, 0] {
        let mut set = synth_entry_set("HUGE.BIN", 6, len, true, false);
        set[40..48].copy_from_slice(&len.to_le_bytes());
        set[56..64].copy_from_slice(&len.to_le_bytes());
        let img = synth_volume(&set);
        let (_, seen) = drive(img);
        assert!(seen < 300_000, "data_length {len} produced {seen} nodes");
    }
    // Same, FAT-chained rather than contiguous.
    for len in [u64::MAX, 1 << 62] {
        let mut set = synth_entry_set("HUGE.BIN", 6, len, false, false);
        set[56..64].copy_from_slice(&len.to_le_bytes());
        let img = synth_volume(&set);
        let (_, seen) = drive(img);
        assert!(seen < 300_000, "chained data_length {len} produced {seen} nodes");
    }
}

/// Names made of unpaired surrogates, NULs and 0xFFFF.
#[test]
fn hostile_names() {
    for filler in [0xD800u16, 0xDC00, 0xFFFF, 0x0000, 0x000A] {
        let mut set = synth_entry_set("X", 6, 1, true, false);
        // 0xC1 record starts at 64; overwrite all 15 units and claim 15 of them.
        for i in 0..15 {
            set[66 + i * 2..68 + i * 2].copy_from_slice(&filler.to_le_bytes());
        }
        set[35] = 15;
        let img = synth_volume(&set);
        let (_, seen) = drive(img);
        assert!(seen > 0, "filler {filler:#06X} produced nothing");
    }
}

/// A 32 MiB cluster declared on a tiny device, and a cluster_count that would make
/// the heap enormous.
#[test]
fn huge_clusters_on_a_small_device() {
    for (bps, spc) in [(9u8, 16u8), (12, 13), (12, 25), (9, 25), (11, 14)] {
        let mut img = synth_volume(&[]);
        img[0x6C] = bps;
        img[0x6D] = spc;
        let (_, seen) = drive(img);
        assert!(seen > 0 && seen < 300_000, "bps {bps} spc {spc} -> {seen} nodes");
    }
}

/// The probe must not claim anything for images that are not exFAT.
#[test]
fn probe_does_not_over_claim() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/gen");
    for name in ["mbr-fat32.img", "gpt-basic.img", "garbage.img", "zeros.img", "mbr-extended.img"] {
        let p = dir.join(name);
        if !p.exists() {
            continue;
        }
        let data = std::fs::read(&p).unwrap();
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
        for at in [0u64, 512, 1024, 2048 * 512] {
            assert_eq!(ExfatProbe.probe(&*src, at), 0, "{name} at {at}");
        }
    }
    // The signature alone must not be enough for a confident score.
    let mut img = vec![0u8; 1 << 20];
    img[3..11].copy_from_slice(b"EXFAT   ");
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(img));
    let s = ExfatProbe.probe(&*src, 0);
    assert!(s > 0 && s < 80, "signature-only image scored {s}");
}

/// Real fixtures must score high, and the bare volume must be recognised at 0.
#[test]
fn probe_claims_the_real_thing() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/gen");
    for (name, at) in [("exfat.img", 0u64), ("mbr-exfat.img", 2048 * 512)] {
        let p = dir.join(name);
        if !p.exists() {
            continue;
        }
        let data = std::fs::read(&p).unwrap();
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
        assert!(ExfatProbe.probe(&*src, at) >= 90, "{name} scored too low");
    }
}

/// Every byte of the root directory cluster set to the same value, for all 256
/// values, with the FAT pointing every cluster at the next.
#[test]
fn uniform_root_directory() {
    for b in 0u16..=255 {
        let mut img = synth_volume(&[]);
        let r = cluster(2);
        for x in img[r..r + BPS].iter_mut() {
            *x = b as u8;
        }
        for c in 0..64usize {
            fat_set(&mut img, c, (c as u32 + 1) % 1002);
        }
        let (_, seen) = drive(img);
        assert!(seen > 0 && seen < 300_000, "byte {b:#04X} produced {seen} nodes");
    }
}

/// The up-case table decode, checked against an independent Python transcription
/// of the compression format: mkfs.exfat's 5836-byte table is 4 identity runs and
/// 874 explicit mappings, covering all 65536 code units.
#[test]
fn upcase_decode_matches_an_independent_decode() {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/gen/exfat.img");
    if !p.exists() {
        return;
    }
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(std::fs::read(&p).unwrap()));
    let root = ExfatProbe.open(src.clone(), 0).root();
    let mut seen = 0;
    let mut labels = Vec::new();
    walk(&root, &*src, 0, &mut seen, &mut labels);
    let maps = labels.iter().filter(|l| l.contains(" -> U+")).count();
    let runs = labels.iter().filter(|l| l.ends_with("identity")).count();
    assert_eq!(runs, 4, "identity runs");
    assert_eq!(maps, 874, "explicit mappings");
    assert!(labels.iter().any(|l| l == "U+0061 -> U+0041"), "a->A missing");
    assert!(labels.iter().any(|l| l == "U+FF5A -> U+FF3A"), "fullwidth z missing");
}

/// A sparse 16 TiB device whose boot sector declares the largest legal geometry.
/// Nothing may try to materialise the heap, the FAT or the bitmap.
#[test]
fn a_declared_sixteen_terabyte_volume_stays_bounded() {
    #[derive(Debug)]
    struct Sparse {
        boot: Vec<u8>,
    }
    impl BlockSource for Sparse {
        fn len(&self) -> u64 {
            1 << 44
        }
        fn name(&self) -> &str {
            "sparse"
        }
        fn logical_sector_size(&self) -> u32 {
            512
        }
        fn read_at(&self, at: u64, buf: &mut [u8]) -> blktamper_core::ReadOutcome {
            buf.fill(0);
            if at < self.boot.len() as u64 {
                let s = at as usize;
                let n = buf.len().min(self.boot.len() - s);
                buf[..n].copy_from_slice(&self.boot[s..s + n]);
            }
            blktamper_core::ReadOutcome::Ok
        }
    }

    let mut boot = vec![0u8; 512];
    boot[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    boot[3..11].copy_from_slice(b"EXFAT   ");
    boot[0x48..0x50].copy_from_slice(&(1u64 << 35).to_le_bytes()); // volume_length
    boot[0x50..0x54].copy_from_slice(&2048u32.to_le_bytes()); // fat_offset
    boot[0x54..0x58].copy_from_slice(&u32::MAX.to_le_bytes()); // fat_length
    boot[0x58..0x5C].copy_from_slice(&(1u32 << 30).to_le_bytes()); // heap offset
    boot[0x5C..0x60].copy_from_slice(&0xFFFF_FFF5u32.to_le_bytes()); // cluster_count
    boot[0x60..0x64].copy_from_slice(&2u32.to_le_bytes()); // root cluster
    boot[0x68..0x6A].copy_from_slice(&0x0100u16.to_le_bytes());
    boot[0x6C] = 12; // 4096-byte sectors
    boot[0x6D] = 13; // 32 MiB clusters
    boot[0x6E] = 2;
    boot[0x1FE] = 0x55;
    boot[0x1FF] = 0xAA;

    let src: Arc<dyn BlockSource> = Arc::new(Sparse { boot });
    let _ = ExfatProbe.probe(&*src, 0);
    let root = ExfatProbe.open(src.clone(), 0).root();
    let mut seen = 0;
    let mut labels = Vec::new();
    let t = std::time::Instant::now();
    walk(&root, &*src, 0, &mut seen, &mut labels);
    assert!(seen < 300_000, "{seen} nodes");
    assert!(t.elapsed().as_secs() < 60, "took {:?}", t.elapsed());
}
