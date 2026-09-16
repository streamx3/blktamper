# Changelog

## 0.1.1

Scrubbing recoverable records on FAT32 and exFAT — the first write operation, and
the one the program was built for.

### Added

- **Scrub deleted records.** `S` on a recoverable record describes what overwriting
  it would destroy, what survives, which sectors get rewritten in full, and what it
  pointedly does *not* touch. Two fills: `neutral` keeps the deleted marker and zeroes
  the other 31 bytes of each record, `zero` writes all 32. Random fill was considered
  and rejected — see [ADR-011](doc/03-decisions.md).
- **The `zero` guard.** `0x00` in a FAT name's first byte, or an exFAT `entry_type`,
  means *stop scanning* rather than *this record is empty*, so `zero` is offered only
  when no in-use record follows in the directory. Otherwise the tool refuses and says
  how many live records it would have hidden.
- **Whole-set scrubbing.** A FAT record is its 8.3 entry plus every long-filename
  fragment; an exFAT record is the file entry plus the stream extension plus every
  name entry. They are staged as one unit and refused as one unit, because half a
  scrub leaves the name recoverable from the other half.
- **Write path**: `BlockSink`, a staging overlay, an off-device undo journal, and a
  commit that rewrites whole sectors read-modify-write.
- `--rw` permits arming; `:arm` opens the write handle; `:commit` needs the device
  name typed. Three separate acts, and without `--rw` the process never opens a
  writable descriptor at all.
- `:diff`, `:revert`, `:disarm`, and a guard against quitting with staged edits.
- `cargo run -p blktamper-formats --example fields` prints the descriptor tables.

### Changed

- `Span::bytes`, `Span::flag_bit`, `end_byte` and `end_bit` saturate instead of
  overflowing. A byte offset past 2 EiB is reachable from a `BlockSource` that merely
  reports a large length, and with `overflow-checks` on in release it aborted.
- The GPT overlap diagnostic is bounded. A crafted table with 4096 mutually
  overlapping entries took 3.48 s and 2.44 GB; it now takes 0.13 s and 113 MB.
- Integration tests are feature-gated, so `--features fat` alone builds *and* tests.

### Fixed

- A false positive on every healthy FAT12/FAT16 volume: a check read offset `0x24` as
  `fat_size_32`, but that offset is only `fat_size_32` on FAT32.
- An off-by-one in the unused-entry collapse, which counted the end-of-directory
  record twice — and whose own test asserted the wrong number.

### Not included, deliberately

- Overwriting file *contents*. That is `sanitize`'s job, and the delete has already
  released the cluster chain, so only a deleted file's first cluster is even knowable
  from its metadata.
- Any claim about physical erasure. On flash an overwrite changes the mapping, not
  necessarily the cell.
- Compaction — moving later records up so no tombstone remains. `neutral` always
  leaves one, and `zero` only removes it at the tail of a directory.

## 0.1.0

Read-only viewer: MBR, GPT, FAT12/16/32 and exFAT.
