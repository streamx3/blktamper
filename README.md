# blktamper

A forensic structure viewer for block devices. Opens `/dev/sdc` or a disk image and
shows its partition tables, filesystem headers and directory records as labelled,
navigable tables — with every field traceable to the exact bytes it came from.

It is built to answer one question precisely: **what is actually still on this disk?**
Deleted directory entries, orphaned long-filename fragments, unused-but-not-zero
partition slots and unclaimed bytes are shown by default and marked, rather than
hidden the way a filesystem driver would hide them.

> **It can write, behind three gates.** Devices open read-only; `--rw` permits
> arming; `:arm` opens the write handle; `:commit` needs the device name typed.
> Without `--rw` the process never opens a writable descriptor at all. The one write
> operation it has is scrubbing a deleted record — see below. Do not point it at data
> you are afraid to lose.

## Try it

```bash
cargo run -p blktamper-tui -- tests/fixtures/gen/mbr-fat32.img
```

Generate the test images first (no root required — everything happens on plain files):

```bash
./tests/fixtures/make-fixtures.sh
```

On a real device you will need privileges, because `/dev/sd*` is `root:disk 0660`:

```bash
sudo blktamper /dev/sdc
```

There is also a non-interactive mode, useful in scripts and bug reports:

```bash
cargo run -p blktamper-tui -- disk.img --dump --depth 3
```

## Status

| Format | State |
|---|---|
| MBR (+ extended boot record chain) | done — verified against `sfdisk` |
| GPT | done — both headers, both entry arrays, both CRC32s, primary/backup diff, 60 type GUIDs; verified against `sgdisk` |
| FAT12 / FAT16 / FAT32 | done — BPB/EBPB/FSInfo, derived geometry, cluster chains, FAT mirror comparison, directory records with long-filename assembly; verified against `fsck.vfat` and `mtools` |
| exFAT | done — 12-sector boot region with checksum, backup region diff, directory entry sets with set checksums, allocation bitmap, up-case table; verified against `dump.exfat` and `fsck.exfat` |
| everything else | see [doc/06-format-scope.md](doc/06-format-scope.md) |

299 tests, clippy clean, no `unsafe`. `./scripts/check.sh` runs everything CI would,
including the layering rules from [ADR-006](doc/03-decisions.md) — `blktamper-core`
must not pull in a terminal, and each format must build and test on its own.

## Scrubbing deleted records

The one thing it writes, and the reason it exists. Select a recoverable record and
press `S`:

```
 Record     deleted-payload.bin (deleted)
            3 record(s), 96 bytes at 0x00001FC840

 Mode       (o) [c] compact remove them, close the gap, zero the tail
            ( ) [s] sweep   blank every deleted record, zero the tail
            ( ) [n] neutral keep the deleted marker, zero the rest
            ( ) [z] zero    zero every byte; reads as never used

 Removes    the long filename, held in 2 fragment(s) that survived the
              delete intact
            the 8.3 name, less its already-destroyed first character
            the attribute byte
            the creation, last-access and last-write timestamps
            the recorded size, 50000 bytes
            the first cluster, 496
 Keeps      the 0xE5 marker on each record: that a file was deleted here
              stays visible, which file it was does not
            the file's data clusters, which this command does not reach

 !          this does not touch the file's data. Cluster 496 at 0x000023A000
            and whatever followed it are unchanged.

 Rewrites   1 sector(s) of 512 B, in full; 60 of 512 bytes actually change,
            and every other record in them is preserved
```

Three things that dialog is careful about:

- **`compact` is the default** because it is the only mode that leaves no tombstone.
  Survivors move up to close the gap — safe because neither FAT nor exFAT has
  positional back-references — and every byte they vacate is zeroed.
- **`zero` warns rather than refuses.** `0x00` in a FAT name's first byte means *stop
  scanning*, so zeroing ahead of live entries makes the OS stop seeing them. Their
  records and data are untouched and undo restores them, so the dialog names them and
  lets you decide.
- **The set goes together.** A FAT record is its 8.3 entry plus every long-filename
  fragment; exFAT is the file entry plus the stream extension plus every name entry.
  Half a scrub leaves the name recoverable from the other half.
- **It scrubs the name, not the file.** Overwriting contents is
  [`sanitize`](https://github.com/streamx3/sanitize)'s job — and the delete already
  released the cluster chain, so only the first cluster is even knowable here.

Nothing reaches the device until `:commit`, which journals the original bytes
off-device first. `blktamper --undo <journal>` is next.

## Layout

```
crates/blktamper-core      model: spans, nodes, descriptors, checksums. No I/O, no UI.
crates/blktamper-io        block devices and images. The only crate that knows about Linux.
crates/blktamper-formats   format knowledge, one module per format, behind cargo features.
crates/blktamper-tui       the terminal UI and the binary.
```

`blktamper-core` has one dependency and knows nothing about terminals; a consumer can
depend on it plus one format module and build a very small tool.

## Documentation

[doc/](doc/) — start with [doc/README.md](doc/README.md).
[doc/03-decisions.md](doc/03-decisions.md) has the architectural arguments, including
why this does not build on the existing Rust filesystem crates.

## Licence

MIT.
