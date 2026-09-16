//! (compiled only with the `exfat` feature)
#![cfg(feature = "exfat")]

//! Independent adversarial harness (review scratch). Drives probe + open + full
//! recursive lazy expansion + rendering over hostile inputs.

use blktamper_core::{
    BlockSource, Children, FormatProbe, MemSource, Node, RenderCtx,
};
use blktamper_formats::exfat::ExfatProbe;
use std::sync::Arc;

fn deep(node: &Node, src: &dyn BlockSource, depth: u32, seen: &mut usize) {
    *seen += 1;
    if *seen > 400_000 || depth > 24 {
        return;
    }
    let ctx = RenderCtx::default();
    let _ = blktamper_core::render::render_value(node, &ctx);
    let _ = blktamper_core::render::render_raw(node, 64);
    match &node.children {
        Children::None => {}
        Children::Resolved(kids) => {
            for k in kids {
                deep(k, src, depth + 1, seen);
            }
        }
        Children::Lazy(e) => {
            for k in e.expand(src) {
                deep(&k, src, depth + 1, seen);
            }
        }
    }
}

fn hammer(img: Vec<u8>, what: &str) {
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(img));
    let _ = ExfatProbe.probe(&*src, 0);
    let root = ExfatProbe.open(src.clone(), 0).root();
    let mut seen = 0usize;
    deep(&root, &*src, 0, &mut seen);
    assert!(seen > 0, "{what}");
}

fn base() -> Vec<u8> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/gen/exfat.img");
    std::fs::read(p).expect("fixture")
}

#[test]
fn zeros_garbage_and_ff() {
    hammer(vec![0u8; 1 << 20], "zeros");
    hammer(vec![0xFFu8; 1 << 20], "all ff");
    let mut g = vec![0u8; 1 << 20];
    let mut s: u64 = 0x1234_5678_9ABC_DEF0;
    for b in g.iter_mut() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }
    hammer(g, "garbage");
    hammer(Vec::new(), "empty");
    hammer(vec![0u8; 3], "3 bytes");
    hammer(vec![0u8; 511], "511 bytes");
}

/// EXFAT magic followed by every possible pair of shift bytes, plus hostile
/// counts/offsets in the other fields.
#[test]
fn every_shift_pair_with_hostile_geometry() {
    for bps in 0u8..=255 {
        for spc in [0u8, 1, 3, 7, 25, 26, 63, 64, 200, 255] {
            let mut img = vec![0u8; 4 << 20];
            img[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
            img[3..11].copy_from_slice(b"EXFAT   ");
            img[0x6C] = bps;
            img[0x6D] = spc;
            img[0x6E] = 0xFF; // number_of_fats
            img[0x70] = 0xFF; // percent_in_use
            img[0x1FE] = 0x55;
            img[0x1FF] = 0xAA;
            for (off, val) in [
                (0x40usize, u64::MAX),
                (0x48, u64::MAX),
            ] {
                img[off..off + 8].copy_from_slice(&val.to_le_bytes());
            }
            for off in [0x50usize, 0x54, 0x58, 0x5C, 0x60] {
                img[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            hammer(img, "hostile geometry");
        }
    }
}

/// Plausible geometry, hostile pointers: every field that points somewhere gets a
/// value just inside and just outside the heap.
#[test]
fn hostile_pointers_on_plausible_geometry() {
    let orig = base();
    let sizes: [u32; 6] = [0, 1, 2, 5, 15871, u32::MAX];
    for &root in &sizes {
        for &cc in &sizes {
            for &fatlen in &[0u32, 1, 128, u32::MAX] {
                let mut img = orig[..8 << 20].to_vec();
                img[0x5C..0x60].copy_from_slice(&cc.to_le_bytes());
                img[0x60..0x64].copy_from_slice(&root.to_le_bytes());
                img[0x54..0x58].copy_from_slice(&fatlen.to_le_bytes());
                hammer(img, "hostile pointers");
            }
        }
    }
}

/// The root directory itself is hostile: every entry type, self-referential FAT,
/// secondary counts that overrun, name lengths of 255.
#[test]
fn hostile_root_directory() {
    let orig = base();
    // root cluster 5 -> offset (4096 + 3*8) * 512
    let root_off = (4096usize + 3 * 8) * 512;
    let fat_off = 2048usize * 512;
    for t in 0u16..=255 {
        let mut img = orig[..8 << 20].to_vec();
        for slot in 0..8 {
            let o = root_off + slot * 32;
            img[o] = t as u8;
            img[o + 1] = 0xFF; // secondary_count / flags
            for b in img[o + 2..o + 32].iter_mut() {
                *b = 0xFF;
            }
            img[o + 3] = 0xFF; // name_length
        }
        // FAT: make cluster 5 point at itself, cluster 2/3 too
        for c in 0..8usize {
            img[fat_off + c * 4..fat_off + c * 4 + 4].copy_from_slice(&(c as u32).to_le_bytes());
        }
        hammer(img, "hostile root");
    }
}

/// Bit-flip fuzz across the whole boot region and root directory.
#[test]
fn seeded_mutation_fuzz() {
    let orig = base();
    let trimmed = &orig[..8 << 20];
    let mut s: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let mut rnd = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let hot: &[(usize, usize)] = &[
        (0, 512),
        (11 * 512, 512),
        (12 * 512, 512),
        (2048 * 512, 4096),
        ((4096 + 3 * 8) * 512, 512),
        (4096 * 512, 2048),
    ];
    for round in 0..3000 {
        let mut img = trimmed.to_vec();
        let n = 1 + (rnd() % 24) as usize;
        for _ in 0..n {
            let (b, l) = hot[(rnd() % hot.len() as u64) as usize];
            let off = b + (rnd() % l as u64) as usize;
            img[off] = (rnd() >> 11) as u8;
        }
        hammer(img, &format!("mutation round {round}"));
    }
}

/// A source that fails every read past the first sector.
#[test]
fn failing_source() {
    #[derive(Debug)]
    struct Flaky(Vec<u8>);
    impl BlockSource for Flaky {
        fn len(&self) -> u64 {
            1 << 40
        }
        fn name(&self) -> &str {
            "flaky"
        }
        fn logical_sector_size(&self) -> u32 {
            512
        }
        fn read_at(&self, at: u64, buf: &mut [u8]) -> blktamper_core::ReadOutcome {
            if at >= 512 {
                return blktamper_core::ReadOutcome::Unreadable;
            }
            let end = (at as usize + buf.len()).min(self.0.len());
            let n = end.saturating_sub(at as usize);
            buf[..n].copy_from_slice(&self.0[at as usize..at as usize + n]);
            if n < buf.len() {
                blktamper_core::ReadOutcome::Short { filled: n }
            } else {
                blktamper_core::ReadOutcome::Ok
            }
        }
    }
    let src: Arc<dyn BlockSource> = Arc::new(Flaky(base()[..512].to_vec()));
    let root = ExfatProbe.open(src.clone(), 0).root();
    let mut seen = 0;
    deep(&root, &*src, 0, &mut seen);
}

/// A directory that contains itself, and a volume opened at an offset near the top
/// of the address space.
#[test]
fn self_referential_directory_and_extreme_base() {
    let orig = base();
    let root_off = (4096usize + 3 * 8) * 512;
    let mut img = orig[..8 << 20].to_vec();
    // Overwrite the root's first entry set with a directory pointing at cluster 5
    // (the root itself), NoFatChain set so it is followed arithmetically.
    let set: &mut [u8] = &mut img[root_off..root_off + 96];
    set.fill(0);
    set[0] = 0x85;
    set[1] = 2;
    set[4] = 0x10; // directory
    set[32] = 0xC0;
    set[33] = 0x03; // AllocationPossible | NoFatChain
    set[35] = 4; // name_length
    set[32 + 0x14..32 + 0x18].copy_from_slice(&5u32.to_le_bytes());
    set[32 + 0x18..32 + 0x20].copy_from_slice(&4096u64.to_le_bytes());
    set[64] = 0xC1;
    for (i, c) in "LOOP".encode_utf16().enumerate() {
        set[66 + i * 2..68 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    hammer(img, "self-referential directory");

    // Opened at an offset that makes every derived address overflow.
    for at in [u64::MAX - 512, u64::MAX - 1, u64::MAX, 1 << 63] {
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(orig[..1 << 20].to_vec()));
        let _ = ExfatProbe.probe(&*src, at);
        let root = ExfatProbe.open(src.clone(), at).root();
        let mut seen = 0;
        deep(&root, &*src, 0, &mut seen);
    }
}

/// 4096-byte sectors declared on a 512-byte device.
#[test]
fn sector_shift_twelve_on_a_small_device() {
    let orig = base();
    for shift in 9u8..=12 {
        for spcs in 0u8..=13 {
            let mut img = orig[..2 << 20].to_vec();
            img[0x6C] = shift;
            img[0x6D] = spcs;
            hammer(img, "shift 12");
        }
    }
}

// ---------------------------------------------------------------- correctness

fn dir_set(name: &str, first_cluster: u32, length: u64, no_fat_chain: bool) -> Vec<u8> {
    let mut s = blktamper_formats::exfat::synth_entry_set(
        name,
        first_cluster,
        length,
        no_fat_chain,
        false,
    );
    s[4..6].copy_from_slice(&0x0010u16.to_le_bytes()); // Directory
    s[2..4].copy_from_slice(&[0, 0]);
    let spec = &blktamper_formats::exfat::desc::ENTRY_SET_CHECKSUM;
    let ck = spec.algo.compute(&s, spec.exclude) as u16;
    s[2..4].copy_from_slice(&ck.to_le_bytes());
    s
}

fn all_labels(node: &Node, src: &dyn BlockSource, out: &mut Vec<String>, depth: u32) {
    if depth > 12 {
        return;
    }
    out.push(node.label.to_string());
    match &node.children {
        Children::None => {}
        Children::Resolved(k) => {
            for c in k {
                all_labels(c, src, out, depth + 1);
            }
        }
        Children::Lazy(e) => {
            for c in e.expand(src) {
                all_labels(&c, src, out, depth + 1);
            }
        }
    }
}

/// A contiguous (NoFatChain) directory two clusters long must show the entries in
/// its *second* cluster too.
#[test]
fn a_contiguous_multicluster_directory_is_fully_walked() {
    const BPS: usize = 512;
    const HEAP_OFF: usize = 32;
    let cluster = |n: usize| HEAP_OFF * BPS + (n - 2) * BPS;

    // Root holds one directory entry set: cluster 6, 2 clusters, NoFatChain.
    let root_entries = dir_set("SUBDIR", 6, 2 * BPS as u64, true);
    let mut img = blktamper_formats::exfat::synth_volume(&root_entries);

    // Second cluster of the subdirectory (cluster 7) holds a file entry set.
    let inner = blktamper_formats::exfat::synth_entry_set("DEEP-FILE.TXT", 9, 10, true, false);
    let at = cluster(7);
    img[at..at + inner.len()].copy_from_slice(&inner);
    // Mark clusters 6 and 7 allocated in the bitmap (cluster 3, bit n-2).
    img[cluster(3)] |= 0b1100_0000;

    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(img));
    let root = ExfatProbe.open(src.clone(), 0).root();
    let mut labels = Vec::new();
    all_labels(&root, &*src, &mut labels, 0);
    assert!(
        labels.iter().any(|l| l.contains("SUBDIR")),
        "the subdirectory itself must be listed: {labels:#?}"
    );
    assert!(
        labels.iter().any(|l| l.contains("DEEP-FILE.TXT")),
        "an entry in the directory's SECOND cluster must be surfaced; got {labels:#?}"
    );
}

/// A directory whose chain crosses an unreadable cluster: the entries that *are*
/// readable must still be reported at their true offsets.
#[test]
fn an_unreadable_run_does_not_shift_later_entries() {
    const BPS: u64 = 512;
    const HEAP_OFF: u64 = 32;
    let cluster = |n: u64| (HEAP_OFF + n - 2) * BPS;

    // Root: one directory, first cluster 6, FAT-chained 6 -> 8.
    let root_entries = dir_set("SUBDIR", 6, 2 * BPS, false);
    let mut img = blktamper_formats::exfat::synth_volume(&root_entries);
    let fat = 24usize * BPS as usize;
    img[fat + 6 * 4..fat + 6 * 4 + 4].copy_from_slice(&8u32.to_le_bytes());
    img[fat + 8 * 4..fat + 8 * 4 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // The named file lives in cluster 8, the SECOND cluster of the chain.
    let inner = blktamper_formats::exfat::synth_entry_set("IN-CLUSTER-8.TXT", 9, 10, true, false);
    let at = cluster(8) as usize;
    img[at..at + inner.len()].copy_from_slice(&inner);

    #[derive(Debug)]
    struct Holed {
        data: Vec<u8>,
        hole: (u64, u64),
    }
    impl BlockSource for Holed {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn name(&self) -> &str {
            "holed"
        }
        fn logical_sector_size(&self) -> u32 {
            512
        }
        fn read_at(&self, at: u64, buf: &mut [u8]) -> blktamper_core::ReadOutcome {
            let end = at.saturating_add(buf.len() as u64);
            if at < self.hole.0 + self.hole.1 && end > self.hole.0 {
                return blktamper_core::ReadOutcome::Unreadable;
            }
            let s = at.min(self.data.len() as u64) as usize;
            let e = (s + buf.len()).min(self.data.len());
            let n = e - s;
            buf[..n].copy_from_slice(&self.data[s..e]);
            if n < buf.len() {
                blktamper_core::ReadOutcome::Short { filled: n }
            } else {
                blktamper_core::ReadOutcome::Ok
            }
        }
    }

    let hole = (cluster(6), BPS);
    let src: Arc<dyn BlockSource> = Arc::new(Holed { data: img, hole });
    let root = ExfatProbe.open(src.clone(), 0).root();

    // Find the node for the file that really lives in cluster 8 and check where the
    // tree says its bytes are.
    fn hunt(n: &Node, src: &dyn BlockSource, needle: &str, out: &mut Vec<u64>, d: u32) {
        if d > 12 {
            return;
        }
        if n.label.contains(needle) {
            if let Some(s) = n.extent.first() {
                out.push(s.start_byte());
            }
        }
        match &n.children {
            Children::None => {}
            Children::Resolved(k) => k.iter().for_each(|c| hunt(c, src, needle, out, d + 1)),
            Children::Lazy(e) => e.expand(src).iter().for_each(|c| hunt(c, src, needle, out, d + 1)),
        }
    }
    let mut offs = Vec::new();
    hunt(&root, &*src, "IN-CLUSTER-8.TXT", &mut offs, 0);
    for o in &offs {
        assert!(
            *o >= cluster(8) && *o < cluster(9),
            "an entry set physically in cluster 8 ({:#X}..{:#X}) was reported at {o:#X}",
            cluster(8),
            cluster(9)
        );
    }
}
