# blktamper

A forensic structure viewer for block devices. Opens `/dev/sdc` or a disk image and
shows its partition tables, filesystem headers and directory records as labelled,
navigable tables — with every field traceable to the exact bytes it came from.

It is built to answer one question precisely: **what is actually still on this disk?**
Deleted directory entries, orphaned long-filename fragments, unused-but-not-zero
partition slots and unclaimed bytes are shown by default and marked, rather than
hidden the way a filesystem driver would hide them.

> **This build is read-only.** It opens devices `O_RDONLY` and has no write path.
> The name is aspirational. Do not point a future write-capable build at data you
> are afraid to lose.

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
