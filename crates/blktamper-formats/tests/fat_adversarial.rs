//! (compiled only with the `fat` feature)
#![cfg(feature = "fat")]

//! Adversarial review harness: hostile inputs must never panic and never over-claim.

use blktamper_core::{BlockSource, Children, FormatProbe, MemSource, Node};
use blktamper_formats::fat::{self, FatProbe};
use std::sync::Arc;

/// Force every lazy child, bounded, and touch every field of every node.
fn walk(n: &Node, src: &dyn BlockSource, depth: u32, budget: &mut u32) {
    if depth > 12 || *budget == 0 {
        return;
    }
    *budget -= 1;
    // touch everything a renderer would touch
    let _ = format!("{:?} {:?} {:?}", n.label, n.value, n.extent);
    let _ = n.deep_status();
    for d in &n.diags {
        let _ = &d.message;
    }
    let kids: Vec<Node> = match &n.children {
        Children::Lazy(e) => e.expand(src),
        Children::Resolved(v) => v.clone(),
        Children::None => Vec::new(),
    };
    for k in &kids {
        walk(k, src, depth + 1, budget);
    }
}

fn hammer(name: &str, data: Vec<u8>) {
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
    for at in [0u64, 512, 1 << 20] {
        let score = FatProbe.probe(&*src, at);
        assert!(score <= 100, "{name}@{at}: score {score} out of range");
        let root = FatProbe.open(src.clone(), at).root();
        let mut budget = 20_000u32;
        walk(&root, &*src, 0, &mut budget);
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/gen/");
    std::fs::read(format!("{p}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn garbage_and_zeros_and_ones_never_panic() {
    hammer("garbage", fixture("garbage.img"));
    hammer("zeros", fixture("zeros.img"));
    hammer("ones", vec![0xFFu8; 1 << 20]);
    hammer("empty", Vec::new());
    hammer("short", vec![0xEB, 0x58, 0x90]);
}

/// A structurally valid FAT32 signature followed by every hostile field value we can
/// think of.
#[test]
fn hostile_bpb_fields_never_panic() {
    let base = fat::synth_fat32(100_000, 1, 800);
    // (offset, bytes) pokes, applied one at a time and also all together.
    let pokes: Vec<(usize, Vec<u8>)> = vec![
        (0x0B, vec![0x00, 0x00]),             // zero sector size
        (0x0B, vec![0xFF, 0xFF]),             // absurd sector size
        (0x0B, vec![0x00, 0x10]),             // 4096
        (0x0D, vec![0x00]),                   // zero sectors per cluster
        (0x0D, vec![0xFF]),                   // not a power of two
        (0x0D, vec![0x80]),                   // 128
        (0x0E, vec![0x00, 0x00]),             // zero reserved
        (0x0E, vec![0xFF, 0xFF]),             // 65535 reserved
        (0x10, vec![0x00]),                   // zero FATs
        (0x10, vec![0xFF]),                   // 255 FATs
        (0x11, vec![0xFF, 0xFF]),             // 65535 root entries
        (0x13, vec![0xFF, 0xFF]),             // total_sectors_16 max
        (0x16, vec![0xFF, 0xFF]),             // fat_size_16 max
        (0x20, vec![0xFF, 0xFF, 0xFF, 0xFF]), // total_sectors_32 max
        (0x24, vec![0xFF, 0xFF, 0xFF, 0xFF]), // fat_size_32 max
        (0x28, vec![0xFF, 0xFF]),             // ext_flags
        (0x2C, vec![0xFF, 0xFF, 0xFF, 0xFF]), // root cluster max
        (0x2C, vec![0x00, 0x00, 0x00, 0x00]), // root cluster 0
        (0x2C, vec![0x01, 0x00, 0x00, 0x00]), // root cluster 1
        (0x30, vec![0xFF, 0xFF]),             // fsinfo sector
        (0x32, vec![0xFF, 0xFF]),             // backup sector
        (0x15, vec![0x00]),                   // media
    ];
    for (off, bytes) in &pokes {
        let mut img = base.clone();
        img[*off..*off + bytes.len()].copy_from_slice(bytes);
        hammer(&format!("poke@{off:#x}"), img);
    }
    let mut all = base.clone();
    for (off, bytes) in &pokes {
        all[*off..*off + bytes.len()].copy_from_slice(bytes);
    }
    hammer("all-pokes", all);
}

/// A self-referential directory: a subdirectory whose first cluster is the root's.
#[test]
fn self_referential_directories_terminate() {
    let mut img = fat::synth_fat32(100_000, 1, 800);
    let (g, _) = blktamper_formats::fat::Geom::derive(&img, 0);
    let root = g.data_start as usize;
    // "SELF" is a directory pointing at cluster 2 — itself.
    fat::synth_entry(&mut img, root, b"SELF       ", 0x10, 2, 0);
    // "DOTDOT" points at cluster 2 too, with a differing name.
    fat::synth_entry(&mut img, root + 32, b"LOOP       ", 0x10, 2, 0);
    hammer("self-referential", img);
}

/// A cluster chain that points back into itself and one that runs off the volume.
#[test]
fn hostile_chains_terminate() {
    let mut img = fat::synth_fat32(100_000, 1, 800);
    let (g, _) = blktamper_formats::fat::Geom::derive(&img, 0);
    let fat0 = g.fat_start as usize;
    // every entry points at the next one, forever
    for c in 2..2000u32 {
        let o = fat0 + c as usize * 4;
        img[o..o + 4].copy_from_slice(&(c + 1).to_le_bytes());
    }
    let root = g.data_start as usize;
    fat::synth_entry(&mut img, root, b"CHAIN   BIN", 0x20, 2, 0xFFFF_FFFF);
    hammer("long-chain", img);
}

/// A FAT12 and a FAT16 boot sector exactly as `mkfs.vfat -F 12` / `-F 16` wrote
/// them, transcribed byte for byte from `xxd` of images whose geometry `fsck.vfat
/// -nv` printed independently. There is no FAT12/16 image under tests/fixtures, so
/// this is the only thing standing between the FAT12/16 code paths and a silent
/// regression.
///
/// The point is twofold: the derived geometry must equal what fsck reported, and a
/// volume mkfs.vfat itself produced must raise nothing. Offset 0x24 is the FAT12/16
/// EBPB, not `fat_size_32`, and reading it as a FAT size used to put a Warn on
/// `fat_size_16` of every healthy small volume.
fn small_volume(boot_head: &[u8], total_sectors: usize) -> Vec<u8> {
    let mut boot = vec![0u8; 512];
    boot[..boot_head.len()].copy_from_slice(boot_head);
    boot[0x1FE] = 0x55;
    boot[0x1FF] = 0xAA;
    let mut img = boot;
    img.resize(total_sectors * 512, 0);
    img
}

#[test]
fn a_clean_fat12_volume_raises_nothing() {
    // `xxd -l 54 f12.img`, and `fsck.vfat -nv`: 4081 data clusters, first FAT at
    // byte 2048, root directory at byte 14336, data area at byte 30720.
    #[rustfmt::skip]
    let head: [u8; 54] = [
        0xEB, 0x3C, 0x90, b'm', b'k', b'f', b's', b'.', b'f', b'a', b't', 0x00,
        0x02, 0x04, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00, 0x40, 0xF8, 0x0C, 0x00,
        0x20, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x29, 0x11, 0x11, 0xAA, 0xAA,
        b'T', b'W', b'E', b'L', b'V', b'E', b' ', b' ', b' ', b' ', b' ',
    ];
    let mut img = small_volume(&head, 16_384);
    // FAT #0 and #1: media byte then end-of-chain, 12-bit packed.
    for fat in 0..2usize {
        let at = (4 + fat * 12) * 512;
        img[at..at + 4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
    }
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(img));

    let g = fat::FatReader::new(src.clone(), 0).geometry();
    assert_eq!(g.kind, blktamper_formats::fat::FatKind::Fat12);
    assert_eq!(g.cluster_count, 4081, "fsck.vfat: 4081 data clusters");
    assert_eq!(g.bytes_per_cluster, 2048);
    assert_eq!(g.fat_start, 2048, "fsck.vfat: First FAT starts at byte 2048");
    assert_eq!(g.root_dir_start, 14_336, "fsck.vfat: root directory at byte 14336");
    assert_eq!(g.data_start, 30_720, "fsck.vfat: data area starts at byte 30720");

    let root = FatProbe.open(src.clone(), 0).root();
    let boot = root.find_child("boot sector").expect("boot sector");
    let bpb = boot.find_child("FAT BPB").expect("BPB");
    for f in bpb.children.resolved().unwrap_or(&[]) {
        assert!(
            f.diags.is_empty(),
            "mkfs.vfat's own FAT12 BPB must raise nothing, but {} says {:?}",
            f.label,
            f.diags
        );
    }
    assert!(boot.find_child("FAT12/16 EBPB").is_some(), "FAT12 gets the 16-bit EBPB");
}

#[test]
fn a_clean_fat16_volume_raises_nothing() {
    // `xxd -l 54 f16.img`; fsck.vfat: 32695 data clusters, data area at byte 149504.
    #[rustfmt::skip]
    let head: [u8; 54] = [
        0xEB, 0x3C, 0x90, b'm', b'k', b'f', b's', b'.', b'f', b'a', b't', 0x00,
        0x02, 0x04, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0xF8, 0x80, 0x00,
        0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x80, 0x00, 0x29, 0x22, 0x22, 0xBB, 0xBB,
        b'S', b'I', b'X', b'T', b'E', b'E', b'N', b' ', b' ', b' ', b' ',
    ];
    let mut img = small_volume(&head, 131_072);
    for fat in 0..2usize {
        let at = (4 + fat * 128) * 512;
        img[at..at + 4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
    }
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(img));

    let g = fat::FatReader::new(src.clone(), 0).geometry();
    assert_eq!(g.kind, blktamper_formats::fat::FatKind::Fat16);
    assert_eq!(g.cluster_count, 32_695, "fsck.vfat: 32695 data clusters");
    assert_eq!(g.fat_start, 2048);
    assert_eq!(g.root_dir_start, 133_120, "fsck.vfat: root directory at byte 133120");
    assert_eq!(g.data_start, 149_504, "fsck.vfat: data area starts at byte 149504");

    let root = FatProbe.open(src.clone(), 0).root();
    let bpb = root
        .find_child("boot sector")
        .and_then(|b| b.find_child("FAT BPB"))
        .expect("BPB");
    for f in bpb.children.resolved().unwrap_or(&[]) {
        assert!(
            f.diags.is_empty(),
            "mkfs.vfat's own FAT16 BPB must raise nothing, but {} says {:?}",
            f.label,
            f.diags
        );
    }
}

/// The inverse: a non-zero `fat_size_16` on a volume the cluster count calls FAT32
/// really is an inconsistency, and must still be reported.
#[test]
fn a_fat32_volume_with_a_16_bit_fat_size_is_flagged() {
    let mut img = fat::synth_fat32(100_000, 1, 800);
    img[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(img));
    let root = FatProbe.open(src.clone(), 0).root();
    let bpb = root
        .find_child("boot sector")
        .and_then(|b| b.find_child("FAT BPB"))
        .expect("BPB");
    let f = bpb.find_child("fat_size_16").expect("fat_size_16");
    assert!(
        f.diags.iter().any(|d| d.message.contains("must come from fat_size_32")),
        "{:?}",
        f.diags
    );
}

/// Probe must not claim an exFAT or NTFS boot sector, nor a random block.
#[test]
fn probe_does_not_over_claim() {
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(fixture("exfat.img")));
    assert_eq!(FatProbe.probe(&*src, 0), 0, "exFAT must not be claimed as FAT");
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(fixture("mbr-exfat.img")));
    assert_eq!(FatProbe.probe(&*src, 1 << 20), 0, "exFAT in a partition must not be claimed");
    let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(fixture("garbage.img")));
    for at in [0u64, 512, 4096] {
        assert_eq!(FatProbe.probe(&*src, at), 0, "garbage must not be claimed");
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Random single-byte mutations of the real FAT32 fixture, in the five regions the
/// parser actually walks. Nothing here should ever panic, however corrupt.
#[test]
fn random_mutations_of_a_real_image_never_panic() {
    let base = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/gen/mbr-fat32.img"
    ))
    .unwrap();
    // Keep only the volume plus enough data region to hold the root and DCIM.
    const AT: usize = 1 << 20;
    let mut rng = Rng(0x2026_0916_DEAD_BEEF);
    let iters: u32 = std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(250);
    for _ in 0..iters {
        let mut img = base.clone();
        // Mutate the boot sector, FSInfo, the backup, the head of FAT#0 and the root
        // directory cluster — the regions the parser actually walks.
        let zones: [(usize, usize); 5] = [
            (AT, 512),
            (AT + 512, 512),
            (AT + 6 * 512, 512),
            (AT + 16_384, 4096),
            (2_081_792, 2048),
        ];
        let n = 1 + (rng.next() % 12) as usize;
        for _ in 0..n {
            let (z0, zl) = zones[(rng.next() % zones.len() as u64) as usize];
            let o = z0 + (rng.next() as usize % zl);
            img[o] = (rng.next() & 0xFF) as u8;
        }
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(img));
        let _ = FatProbe.probe(&*src, AT as u64);
        let root = FatProbe.open(src.clone(), AT as u64).root();
        let mut budget = 6_000u32;
        walk(&root, &*src, 0, &mut budget);
    }
}
