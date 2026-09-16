# Writing to block devices on Linux

You said you accept that this will eventually corrupt data. Fine — but there are
several things about Linux block I/O that will surprise you, and knowing them
changes the design. This document is the list.

## 1. You cannot write two bytes

Not physically. The device's minimum addressable unit is a sector — 512 B logical
(often 4096 B physical) on your `/dev/sdc`, and a flash device's real erase block
is megabytes.

What actually happens:

- **Buffered write** (normal `pwrite()` to `/dev/sdc`): the kernel reads the page
  containing your offset into the page cache, modifies your two bytes, and later
  writes the whole page back. Arbitrary byte offsets and lengths work fine.
- **`O_DIRECT`**: offset, length, *and the memory buffer address* must all be
  aligned to the logical block size. Your two-byte edit becomes "read 512 bytes,
  patch 2, write 512 bytes" and you do the read-modify-write yourself.

**Consequence for the design:** the commit screen must say which *sectors* will be
rewritten, not just which bytes change (see the commit mockup in
[05-tui-design.md](05-tui-design.md)). A user who thinks they're touching two bytes
should see that a full sector is going back to the disk.

**Recommendation:** use buffered I/O with an explicit `fsync()` after commit. Add
`--direct` as an option for people who need to bypass the page cache, and do the
read-modify-write explicitly in that path.

## 2. The page cache will lie to you

If anything else has the device open — a mounted filesystem, `udisks`, a running
`blkid` — the kernel's buffer cache holds its own copy of those sectors. Your write
goes into the same cache, but:

- The filesystem driver may write *its* version back over yours at any time.
- Your *reads* may come from cache and not reflect what's on the platter.
- `partprobe`-style tools re-read the partition table and may re-cache stale data.

Mitigations, in order of bluntness:

1. `fsync()` after writing.
2. `ioctl(fd, BLKFLSBUF)` to flush and invalidate the device's buffer cache.
3. `ioctl(fd, BLKRRPART)` to make the kernel re-read the partition table —
   **only when nothing is mounted**, and only when the user explicitly asks. Never
   automatically.
4. Don't write to devices with mounted partitions. Which brings us to:

## 3. The kernel may simply refuse

Linux 6.8 added `CONFIG_BLK_DEV_WRITE_MOUNTED`. When a distribution builds with it
disabled, **opening a mounted block device for writing fails with `EBUSY`**. There
is also a `bdev_allow_write_mounted=` kernel boot parameter.

The kernel commit's own justification is worth repeating: writing to a mounted
device's buffer cache "is very likely going to cause filesystem corruption", and
"it is also rather easy to crash the kernel in this way since the filesystem has no
practical way of detecting these writes to buffer cache and verifying its metadata
integrity."

This machine (6.8.0-138-generic) has `CONFIG_BLK_DEV_WRITE_MOUNTED=y`, so writes are
permitted here. Other machines won't be.

**Consequence:** `EBUSY` on open-for-write must be a recognised, explained condition —
"this device has a mounted filesystem and your kernel forbids writing to it; unmount
`/dev/sdc1` first" — not a raw errno. Note that as of right now `/dev/sdc1` *is*
mounted on `/media/andrii/E807-EC4E`, so this is your default state, not an edge case.

## 4. Permissions

`/dev/sdc` is `brw-rw---- root:disk`. Your account is not in `disk`. So blktamper
needs one of:

- `sudo blktamper /dev/sdc` — simplest, and honest about what the tool does.
- `usermod -aG disk andrii` — persistent, and a meaningful privilege grant. Members
  of `disk` can read every block device, which is equivalent to root for data
  purposes.
- `setcap cap_sys_rawio+ep` — narrower but still very powerful, and it doesn't help
  with the file mode bits anyway.

**Recommendation:** don't ship any privilege escalation. Detect `EACCES`, print
which of the above would fix it, and exit cleanly. A TUI that dies with
"Permission denied (os error 13)" on a `sudo`-able device is a bad first impression.

## 5. Sector size is not what you think

`BLKSSZGET` gives the *logical* sector size (what LBAs are counted in),
`BLKPBSZGET` the *physical* one. They differ on 512e drives (512 logical / 4096
physical). All LBA→offset arithmetic uses the logical size.

Then there are the ways it goes wrong:

- A raw image taken from a 4Kn disk with `dd` has no sector size of its own. Read it
  with the default 512 and every offset in the GPT is 8× wrong.
- USB bridges lie about sector size, sometimes differently across reboots.
- The GPT header itself doesn't store the sector size; it is implicit in
  "the backup header is in the last sector".

**Consequence:** `--sector-size` must exist, must be changeable at runtime, and the
current value must be permanently visible in the title bar. When the GPT signature
isn't found at offset 512, the app should *offer* to retry at 4096 — that single
heuristic will save you a lot of confusion.

## 6. Unreadable sectors are not zeros

A failing disk returns `EIO` for some reads. If the app silently substitutes zeros,
you will spend an hour debugging a "corrupt" structure that was never read.
`ReadOutcome::Unreadable` is a distinct state, renders as `?` in the gutter and `??`
in the hex pane, and never gets confused with `0x00`.

For the same reason: no retry loops by default. A failing drive that is being
hammered with retries is a failing drive that is about to stop responding entirely.
One attempt, report the failure, let the user decide.

## The write pipeline

```
  user edits a field
        |
        v
  RegionReader::encode(path, value) -> Vec<ByteEdit>     format-specific encoding
        |
        v
  Overlay::stage(edits)                                  in memory, nothing on disk
        |
        +--> all reads now see edited bytes
        |    -> checksum fields recompute and turn green/red live
        |    -> hex pane marks changed bytes
        |    -> `:diff` lists staged edits
        v
  :commit
        |
        +--> refuse unless armed (--rw + :arm)
        +--> warn if any partition is mounted; require extra confirmation
        +--> show byte diff, list affected sectors
        +--> require typing the device name
        |
        v
  Journal::append(original_bytes, new_bytes, path, timestamp)   off-device, fsync'd
        |
        v
  BlockSink::write_at(...) for each affected sector
        |
        v
  fsync() + optional BLKFLSBUF
```

The journal is written **and flushed before** the device write, so a crash between
the two leaves a recoverable record. It lives in
`$XDG_STATE_HOME/blktamper/journal/<timestamp>-<device>.jsonl`, one JSON object per
edit, containing offset, length, original bytes (hex), new bytes (hex), node path
and timestamp. `blktamper --undo <journal>` replays it backwards.

Storing the journal on the device you're editing would be idiotic, so the app
refuses if `$XDG_STATE_HOME` resolves to a path on the target device.

## Coarse before fine

R-7.6 says region dump/restore must exist **before** field editing. That ordering is
deliberate:

- `:save mbr.bin` then `:load mbr.bin` is ~50 lines and covers the "I want to be
  able to put it back" requirement completely.
- It is also the thing you actually want at 2 a.m., when the useful operation is
  "restore the whole header I saved twenty minutes ago", not "set byte 0x1C2 back
  to 0x0C".
- And it gives the field editor a safety net that exists before the field editor
  does.

## Recomputing checksums after an edit

Asked for explicitly. Here is the design, and the half of it that is already built.

### The key observation

**Computing a checksum is a viewing feature before it is a writing feature.** Every
checksum field renders as *stored* alongside *computed*, with a pass/fail marker —
that is useful with no write path at all, and it is already implemented. Recomputing
for a write is the same code with a byte write on the end.

So the build you have today already:

- knows the algorithm, the covered byte range, and the excluded bytes for every
  checksum field (`ChecksumSpec` in `blktamper-core/src/checksum.rs`);
- computes the expected value on every render and shows `0xA13F2290 != 0x7C41BE05`
  in red, or `OK` in green;
- can produce the exact `ByteEdit` that would make them agree, via
  `reader::recompute_edit_for` — which returns the proposed bytes and writes nothing.

### Supported algorithms

| Algorithm | Used by | Covered range | Excluded |
|---|---|---|---|
| CRC-32/ISO-HDLC | GPT header | `header_size` bytes from the header start | the 4 CRC bytes, **zeroed** not skipped |
| CRC-32/ISO-HDLC | GPT entry array | `num_entries × entry_size` bytes | nothing |
| exFAT boot region | exFAT sector 11 | sectors 0..=10 | bytes 106, 107, 112 of sector 0, **skipped** not zeroed |
| exFAT entry set | every exFAT directory entry set | the whole set | bytes 2..4 of the primary entry |
| FAT short-name | every FAT long-filename run | the 11 name bytes of the 8.3 entry | nothing |

The zeroed-versus-skipped distinction is not pedantry: CRC-32 over a zeroed field and
CRC-32 over a field that is simply absent give different answers, and each of these
formats picks a different one. Both behaviours are implemented and unit-tested
against each other.

### The cascade

Checksums in these formats are nested, and a naive "recompute everything" produces
either an infinite loop or a wrong answer. The order is fixed and must be respected:

```
edit a GPT partition entry
  └─> entry array CRC32 changes
        └─> primary header's entries_crc32 field changes
              └─> primary header's own header_crc32 changes
  and independently
  └─> the backup entry array is now stale
        └─> the backup header's entries_crc32 changes
              └─> the backup header's own header_crc32 changes
```

So `:recompute` resolves a dependency order, deepest first, and shows the whole
cascade as one staged change set before anything is written. Editing one byte of a
partition name is five derived updates; a user who is only shown the one byte they
typed has been misled.

exFAT has the same shape: change a filename and the entry set checksum changes;
change the volume flags and the boot region checksum changes — except that the volume
flags are among the bytes the boot checksum *skips*, so it does not. Getting that
backwards silently corrupts a volume that was fine.

### What `:recompute` will do

1. Collect every derived field whose stored value no longer matches its computed one.
2. Order them by dependency, deepest first.
3. Stage them all in the overlay as one change set.
4. Show the cascade: each field, its old value, its new value, and *why* it changed.
5. Write nothing. Committing is a separate, explicit act.

### What it will never do

- Run automatically after an edit. A forensic tool that silently repairs the evidence
  is worse than useless — sometimes a mismatched CRC is precisely the thing you are
  trying to preserve and show someone.
- Refuse to leave a checksum wrong. Writing a deliberately-corrupt header is a
  legitimate thing to want, and R-7.8 says the tool warns rather than vetoes.
- Recompute a checksum whose covered range it could not read. An unreadable sector
  produces `Status::Unreadable`, not a checksum computed over zeros.

### What is left to build

Only the last mile: the dependency ordering (`ChecksumSpec` already carries enough to
derive it), the overlay to stage into, and the commit path. The arithmetic, the
coverage rules, the exclusions and the proposed-edit generation are done and tested.

## Scrubbing deleted records

The first write operation blktamper will grow, and deliberately so: it is the use
case that motivated the program ([ADR-009](03-decisions.md)), and it is a *bounded*
target — the model already knows exactly which bytes to touch — which makes it the
safest possible way to prove the whole write path works. Decisions in
[ADR-011](03-decisions.md).

### Why the target is already solved

A deleted file is not one record. On FAT it is N long-filename fragments stored in
reverse order immediately before the 8.3 entry; on exFAT it is a file entry plus a
stream extension plus N name entries. The reader already groups these into one node
whose `Extent::Many` lists every 32-byte span, so "which bytes does this record
occupy" needs no new code — that was the hard part and `Extent::Many` existing from
day one (rather than being retrofitted) is what paid for it.

### The four hazards

**1. Zeroing byte 0 truncates the directory.** `0x00` in a FAT name's first byte, or
in an exFAT `entry_type`, means *stop scanning* — not *this record is empty*. Zeroing
a record that sits before live entries hides every one of them from every driver.
Guarded: `zero` is offered only when nothing in use follows. See ADR-011.

**2. The record shares a sector with live files.** A 32-byte write is physically a
read-modify-write of 512 or 4096 bytes, and a 512-byte sector holds sixteen directory
records. Scrubbing one deleted entry rewrites up to fifteen live ones. The overlay
preserves them by construction — which is the argument for building the overlay
properly rather than reaching for a targeted `pwrite`.

**3. The set must be scrubbed whole.** Clearing the 8.3 entry while leaving its
long-filename fragments leaves the name fully recoverable, and that is the exact
failure this feature exists to prevent. The command operates on the group, never on
one record inside it.

**4. Scrubbing the record does not scrub the file.** The entry points at a first
cluster; the data is elsewhere and untouched, and the delete already released the
chain so only that first cluster is even knowable. The command removes the *name*,
not the *content*, and the UI has to say so rather than leaving the user to assume
otherwise. Overwriting contents is `sanitize`'s job.

### What it looks like (implemented in 0.1.1)

```
     +- scrub deleted record ----------------------------------------------+
     | Record     ?ECRET.TXT (deleted)                                     |
     |            1 short entry + 0 long-filename fragments                |
     |            32 bytes at 0x00001FC4C0                                 |
     |                                                                     |
     | Fill       (o) neutral   keep the 0xE5 marker, zero the other 31 B  |
     |            ( ) zero      all 32 bytes -- REFUSED HERE:              |
     |                          3 in-use records follow in this directory  |
     |                                                                     |
     | Removes    name, attributes, all three timestamps, size, cluster    |
     | Keeps      the 0xE5 tombstone: that a file was deleted stays        |
     |            visible, which file it was does not                      |
     | Does NOT   touch the file's data. Cluster 495 and whatever follows  |
     |            it are unchanged -- use sanitize for contents.           |
     |                                                                     |
     | Rewrites   sector 4066 in full (512 B), which also holds 15 live    |
     |            directory records                                        |
     |                                                                     |
     | [Enter] stage in overlay   [Esc] cancel                             |
     +---------------------------------------------------------------------+
```

Staged, like every other edit. Nothing reaches the device until `:commit`, which
names the sectors, journals the original bytes off-device and asks for the device
name to be typed.

The refusal shown above is real: `zero` is offered only when the reader has walked
the rest of the directory and found nothing in use. When it cannot finish that walk —
an unreadable sector, an unusable geometry — it also refuses, because an unverifiable
guarantee is not one.

### What it will not do

- Offer a random or multi-pass fill. Rejected in ADR-011: on a 32-byte record inside
  one sector, noise is more conspicuous than zeros and multiple passes are theatre.
- Claim the bytes are physically gone. On flash they very likely are not, and that is
  out of scope by decision rather than by oversight.
- Scrub anything the user did not select. There is no "scrub all deleted records"
  sweep in the first version — it is exactly the operation whose blast radius is
  hardest to preview, and the preview is the safety feature.

## What the app will never do

- Escalate privileges on its own.
- Mount anything.
- Write anything without an explicit, typed confirmation.
- Silently recompute a checksum. `:recompute` stages a visible change.
- Refuse a value because it thinks it's wrong (R-7.8). It warns. You decide.
- Retry a failing sector in a loop.
