# Changelog

## 0.1.3

Portability research and a version flag. No behaviour change on Linux.

### Added

- **`-v` / `--version`.** Reports the version, the formats the build actually
  understands, whether it can write, the clipboard support compiled in, and the
  platform. The format list is asked of the registry rather than restated from cfg
  flags, so it cannot drift from what is really compiled in. A bare version number
  answers none of the questions a bug report about a disk needs.
- **[doc/10-other-platforms.md](doc/10-other-platforms.md)** — can this work on macOS
  and Windows? Researched against vendor documentation and, for macOS, against XNU and
  IOStorageFamily source.

  Both platforms document complete, supported interfaces and neither panics from
  userspace raw writes. Windows is the stricter of the two and unusually explicit:
  partition-table sectors stay writable on a mounted disk because *"there is no reason
  to block access to the sectors"*, and recovery programs are named as unaffected.
  macOS is the permissive one — its block node returns `EBUSY` when mounted even for
  `O_RDONLY`, while the raw node opened `O_RDWR` under a live read-write mount simply
  succeeds, with no equivalent of `CONFIG_BLK_DEV_WRITE_MOUNTED`.

  The real hazard on both is not a crash but the OS repairing behind you — `chkdsk` on
  the NTFS dirty bit, `fsck_*` from `diskarbitrationd` — which destroys exactly the
  residue this tool exists to show. Hard limits: the macOS boot disk is closed to
  third parties, and the Windows system volume can never be locked.

### Fixed

- The changelog filed the two entries above under 0.1.2, which was already tagged and
  pushed. They belong here.


## 0.1.2

Compaction, and the end of trusting filesystem markers about what is still there.

### Added

- **`compact`, now the default scrub mode.** Removes the deleted records from a
  directory, closes the gap so the survivors stay reachable, and zeroes every byte
  they vacate along with the rest of the directory's allocated space. The only mode
  that leaves no tombstone — which the stated threat model requires, since a
  tombstone with a zeroed payload says "a file was deleted and scrubbed here", more
  than an ordinary deletion would have said.
- **`sweep`**: blanks every deleted record in place while keeping its marker, then
  zeroes everything past the last live record. Lower blast radius than `compact` —
  nothing moves — at the cost of leaving tombstones between live files.
- Both directory modes also clear records marked never-used whose bytes are not
  zero: entries overwritten rather than erased.

### Changed

- **Zeroing warns instead of refusing.** The old refusal contradicted R-7.8 and
  overstated the consequence: hiding records from a driver is not destroying them,
  their bytes are untouched, and undo restores reachability. The dialog now names the
  affected files, states the cost, and points out that `compact` does the same job
  without hiding anything.
- **The scrub guards no longer stop at the end-of-directory marker.** The listers
  already walked past it; the code deciding what was safe did not. A record past the
  terminator is invisible to a driver and just as readable on disk, and the tool
  should not believe a marker its own viewer pointedly does not.
- `scrub_plan` takes a `ScrubMode` rather than a `Fill`.

### Fixed

- **A directory-wide mode could have accepted a file's first cluster.** It has the
  same shape the check looked for — one span, cluster-aligned, one cluster long — and
  compacting it would have rewritten file data as though it were directory records.
  Both modules now require the bytes to agree that they are a directory.
- The affected-record name for a FAT set read a long-filename fragment as text,
  producing nonsense; it now reads the 8.3 entry.

### Still not included

- **Carving.** Compaction cleans the directories it is pointed at, not deleted
  directories (whose cluster chain is released) or clusters a directory used before
  it shrank. Both hold filenames. This is now the limiting factor on the threat model
  rather than a detail — see [ADR-011](doc/03-decisions.md).
- Overwriting file contents, and any claim about physical erasure.

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
