//! Checksum arithmetic against real images and independently-computed values.
//!
//! The expected values here were produced with Python's `zlib.crc32`, not with this
//! crate. A checksum test that checks our implementation against our implementation
//! proves nothing; these numbers come from somewhere else.

mod common;

use blktamper_core::ChecksumAlgo;
use common::*;

/// Read `len` bytes at `off` from a fixture.
fn bytes(name: &str, off: u64, len: usize) -> Option<Vec<u8>> {
    use blktamper_core::BlockSource;
    let src = fixture(name)?;
    let (v, _) = src.read_vec(off, len);
    (v.len() == len).then_some(v)
}

#[test]
fn gpt_header_crc32_matches_an_independent_implementation() {
    // zlib.crc32 over bytes 512..604 with 528..532 zeroed = 0x1D887C84
    let Some(hdr) = bytes("gpt-basic.img", 512, 92) else { return };
    assert_eq!(ChecksumAlgo::Crc32.compute(&hdr, &[(16, 4)]), 0x1D88_7C84);

    // and it is what the header itself claims
    let stored = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
    assert_eq!(stored, 0x1D88_7C84, "sgdisk and we must agree about a healthy header");
}

#[test]
fn gpt_entry_array_crc32_matches_an_independent_implementation() {
    // 128 entries x 128 bytes at LBA 2; zlib.crc32 = 0x89626BB9
    let Some(arr) = bytes("gpt-basic.img", 2 * 512, 128 * 128) else { return };
    assert_eq!(ChecksumAlgo::Crc32.compute(&arr, &[]), 0x8962_6BB9);
}

#[test]
fn the_corrupted_fixture_really_is_corrupted() {
    // The whole point of gpt-badcrc.img: the stored value is wrong and the
    // computed one is right, so a reader has something to disagree about.
    let Some(hdr) = bytes("gpt-badcrc.img", 512, 92) else { return };
    let stored = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
    let computed = ChecksumAlgo::Crc32.compute(&hdr, &[(16, 4)]);
    // The fixture script writes the bytes DE AD BE EF, which read back as a
    // little-endian u32 is 0xEFBEADDE. Worth spelling out: mixing those two up is
    // how a reader ends up reporting a mismatch that is really its own bug.
    assert_eq!(stored, 0xEFBE_ADDE);
    assert_eq!(computed, 0x1D88_7C84);
    assert_ne!(stored as u64, computed);
}

#[test]
fn the_exclusion_rule_differs_between_crc32_and_the_exfat_checksums() {
    // CRC32 users (GPT) ZERO the excluded bytes; the exFAT checksums SKIP them.
    // Conflating the two silently produces a wrong answer on a valid volume.
    let data = [0xAAu8, 0xBB, 0xCC, 0xDD];

    let crc_excluded = ChecksumAlgo::Crc32.compute(&data, &[(1, 2)]);
    let crc_zeroed = ChecksumAlgo::Crc32.compute(&[0xAA, 0x00, 0x00, 0xDD], &[]);
    assert_eq!(crc_excluded, crc_zeroed, "CRC32 exclusions must behave as zeros");

    let boot_excluded = ChecksumAlgo::ExfatBootRegion.compute(&data, &[(1, 2)]);
    let boot_shortened = ChecksumAlgo::ExfatBootRegion.compute(&[0xAA, 0xDD], &[]);
    assert_eq!(boot_excluded, boot_shortened, "exFAT exclusions must behave as absent");

    let boot_zeroed = ChecksumAlgo::ExfatBootRegion.compute(&[0xAA, 0x00, 0x00, 0xDD], &[]);
    assert_ne!(boot_excluded, boot_zeroed, "the two rules must not coincide by accident");
}

#[test]
fn checksum_widths_are_what_the_formats_store() {
    assert_eq!(ChecksumAlgo::Crc32.width_bytes(), 4);
    assert_eq!(ChecksumAlgo::ExfatBootRegion.width_bytes(), 4);
    assert_eq!(ChecksumAlgo::ExfatEntrySet.width_bytes(), 2);
    assert_eq!(ChecksumAlgo::FatShortName.width_bytes(), 1);
}
