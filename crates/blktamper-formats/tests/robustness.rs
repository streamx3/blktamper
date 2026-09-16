//! Every format, against hostile input.
//!
//! The central invariant of this program is that parsing never fails and never
//! panics (R-3.1, R-3.7). That is not a nicety: every byte this tool reads is
//! potentially garbage, because looking at garbage is the job. A parser that
//! panics on a corrupt superblock is a parser that dies exactly when you need it.
//!
//! This runs against *every registered format* rather than being written per
//! module, so a format added later is covered the day it is registered.

use blktamper_core::{BlockSource, Children, MemSource, Node, Registry};
use std::sync::Arc;

/// Deterministic PRNG. No `rand` dependency, and the same bytes every run, so a
/// failure is reproducible from the seed printed in the assertion.
struct Rng(u64);

impl Rng {
    fn next_u8(&mut self) -> u8 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8
    }
    fn fill(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u8()).collect()
    }
}

/// Nodes materialised while walking, as a proxy for "did it try to allocate the
/// whole disk". A header claiming four billion entries must produce a diagnostic,
/// not a four-billion-element vector.
const NODE_BUDGET: usize = 500_000;

fn count_nodes(n: &Node, budget: &mut usize) {
    *budget = budget.saturating_sub(1);
    if *budget == 0 {
        return;
    }
    if let Children::Resolved(kids) = &n.children {
        for k in kids {
            count_nodes(k, budget);
        }
    }
}

/// Every probe scored, every reader opened, every tree walked — without panicking.
fn exercise(reg: &Registry, src: Arc<dyn BlockSource>, what: &str) {
    for p in reg.probes() {
        let score = p.probe(&*src, 0);
        assert!(score <= 100, "{}: probe returned {score} for {what}", p.id());

        // Forcing the interpretation is a supported user action (`:as`), so it must
        // survive being pointed at anything.
        let reader = p.open(src.clone(), 0);
        let root = reader.root();
        assert!(!root.label.is_empty(), "{}: unlabelled root for {what}", p.id());

        let mut budget = NODE_BUDGET;
        count_nodes(&root, &mut budget);
        assert!(budget > 0, "{}: produced more than {NODE_BUDGET} nodes for {what}", p.id());

        // And at a non-zero offset, which is how every partition is opened.
        if src.len() > 4096 {
            let _ = p.probe(&*src, 1024);
            let _ = p.open(src.clone(), 1024).root();
        }
    }
}

#[test]
fn no_format_panics_on_random_bytes() {
    let reg = blktamper_formats::registry();
    for seed in [1u64, 42, 0xDEAD_BEEF, 0x5555_AAAA, 12345] {
        let mut rng = Rng(seed);
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(rng.fill(256 * 1024)));
        exercise(&reg, src, &format!("random seed {seed}"));
    }
}

#[test]
fn no_format_panics_on_uniform_bytes() {
    let reg = blktamper_formats::registry();
    for fill in [0x00u8, 0xFF, 0x55, 0xAA, 0xE5] {
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(vec![fill; 128 * 1024]));
        exercise(&reg, src, &format!("uniform {fill:#04X}"));
    }
}

#[test]
fn no_format_panics_on_a_truncated_device() {
    let reg = blktamper_formats::registry();
    // Every size from "less than one sector" upwards: the classic place where a
    // reader indexes past the end of a buffer it assumed was full.
    for len in [0usize, 1, 16, 511, 512, 513, 1023, 1024, 4095, 4096, 8191] {
        let mut rng = Rng(len as u64 + 7);
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(rng.fill(len)));
        exercise(&reg, src, &format!("{len}-byte device"));
    }
}

#[test]
fn no_format_panics_when_its_own_magic_is_followed_by_garbage() {
    // The nastiest input: a valid signature, so the parser commits to the format,
    // followed by field values designed to overflow, divide by zero, or allocate.
    let magics: &[(&str, usize, &[u8])] = &[
        ("MBR 55AA", 0x1FE, &[0x55, 0xAA]),
        ("EFI PART", 512, b"EFI PART"),
        ("FAT jmp", 0, &[0xEB, 0x58, 0x90]),
        ("FAT32 label", 82, b"FAT32   "),
        ("EXFAT", 3, b"EXFAT   "),
        ("exFAT sig", 510, &[0x55, 0xAA]),
    ];
    let reg = blktamper_formats::registry();
    for (name, off, magic) in magics {
        for seed in [3u64, 99, 0xABCD] {
            let mut rng = Rng(seed);
            let mut data = rng.fill(512 * 1024);
            data[*off..*off + magic.len()].copy_from_slice(magic);
            let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
            exercise(&reg, src, &format!("{name} + garbage, seed {seed}"));
        }
    }
}

#[test]
fn no_format_panics_on_hostile_counts_and_shifts() {
    // Fields that get multiplied, shifted, or used as a loop bound, set to the
    // values that break naive code: zero, one, u32::MAX, and shift counts >= 64.
    let reg = blktamper_formats::registry();
    let poisons: [u8; 4] = [0xFF, 0x00, 0x80, 0x40];
    for poison in poisons {
        let mut data = vec![poison; 256 * 1024];
        // Give it every signature at once so every reader commits.
        data[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        data[3..11].copy_from_slice(b"EXFAT   ");
        data[0x1FE] = 0x55;
        data[0x1FF] = 0xAA;
        data[512..520].copy_from_slice(b"EFI PART");
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
        exercise(&reg, src, &format!("all-signatures, poison {poison:#04X}"));
    }
}

#[test]
fn no_format_panics_when_every_read_fails() {
    // A dying drive. The tree must still be produced, marked unreadable.
    #[derive(Debug)]
    struct AllBad(u64);
    impl BlockSource for AllBad {
        fn len(&self) -> u64 {
            self.0
        }
        fn read_at(&self, _: u64, _: &mut [u8]) -> blktamper_core::ReadOutcome {
            blktamper_core::ReadOutcome::Unreadable
        }
        fn name(&self) -> &str {
            "<all bad>"
        }
    }
    let reg = blktamper_formats::registry();
    let src: Arc<dyn BlockSource> = Arc::new(AllBad(64 * 1024 * 1024));
    exercise(&reg, src, "every read fails");
}

#[test]
fn probes_do_not_over_claim_a_sector() {
    // If two formats are both confident about the same sector, the "interpret as"
    // menu becomes a coin toss — with one designed-in exception: a GPT disk really
    // does carry a protective MBR in sector 0, and both readers are right about it.
    // Encoding the exception rather than loosening the rule is the point.
    let reg = blktamper_formats::registry();
    for name in ["mbr-fat32.img", "mbr-extended.img", "gpt-basic.img", "gpt-fat32.img", "exfat.img", "mbr-exfat.img"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/gen")
            .join(name);
        if !path.exists() {
            continue;
        }
        let Ok((src, _)) = blktamper_io::open_path(&path, blktamper_io::Access::ReadOnly) else {
            continue;
        };
        let confident: Vec<String> = reg
            .candidates(&*src, 0)
            .into_iter()
            .filter(|(_, s)| *s >= 80)
            .map(|(id, s)| format!("{id}={s}"))
            .collect();

        if confident.len() <= 1 {
            continue;
        }

        let ids: Vec<&str> = confident.iter().map(|c| c.split('=').next().unwrap()).collect();
        let mbr_and_gpt = ids.len() == 2 && ids.contains(&"mbr") && ids.contains(&"gpt");
        assert!(
            mbr_and_gpt,
            "{name}: {} formats are confident about sector 0: {confident:?}",
            confident.len()
        );

        // Allowed only if the MBR really is protective: exactly one entry, type 0xEE.
        let mut sector = [0u8; 512];
        src.read_at(0, &mut sector);
        let used: Vec<u8> = (0..4)
            .map(|i| sector[0x1BE + i * 16 + 4])
            .filter(|&t| t != 0)
            .collect();
        assert_eq!(
            used,
            vec![0xEE],
            "{name}: mbr and gpt both claim sector 0 but the MBR is not protective \
             (entry types {used:02X?}) - one of them is over-claiming"
        );
    }
}
