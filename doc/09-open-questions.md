# Open questions

> **All eight were answered on 2026-09-16 and are recorded as
> [ADR-010](03-decisions.md#adr-010-answers-to-the-open-questions).** The answers are
> inline below, marked **A:**. This file is kept as the record of the exchange; the
> binding version is the ADR.


Things I need from you. Roughly in the order they block work.

## 1. Format order — do you accept ADR-004?

Proposed: MBR → **GPT** → FAT32 → exFAT, instead of MBR → FAT32/exFAT → GPT.

Argument in [ADR-004](03-decisions.md#adr-004-do-gpt-before-fat32exfat). Short
version: GPT is two days and validates the architecture; exFAT is two weeks and
doesn't. Doing the cheap one second means finding out the design is wrong before
you've sunk the two weeks.

**Blocks:** M3/M4 ordering. Nothing else.

**A:** Yes, ADR-004 is ok.

## 2. What did "UEFI" mean in your rank 3?

The EFI System Partition is FAT32, which is already rank 1. So you meant something
else. Candidates:

- Boot file structures on the ESP (`\EFI\BOOT\BOOTX64.EFI`, PE/COFF headers)
- UEFI boot entries / `BootOrder` variables
- The firmware NVRAM variable store layout (as seen in a SPI flash dump)
- Nothing in particular, and it was shorthand for "the ESP"

These are very different amounts of work. The NVRAM variable store in particular is
interesting and completely unserved by existing tools, but it's a flash-dump format,
not a block-device format.

**A:** My bad, I did believe UEFI is some twisted FAT header, not just content. If it is covered fully by FAT32 -- so be it.

## 3. Is the TUI layout right?

[05-tui-design.md](05-tui-design.md) is the review target. Specific things I'd
push back on myself:

- **Three panes may be one too many on a laptop.** The region tree costs 30 columns
  permanently. The alternative is a breadcrumb line plus a popup tree on a key.
  I chose the persistent tree because "move between them" was an explicit
  requirement and a popup makes that feel far away — but it's a real trade.
- **Is the hex pane always-on, or on a key?** I made it always-on because it's the
  thing that makes the labels trustworthy. It costs 6 rows.
- **Vim keys vs arrow-and-function keys.** I assumed vim. If this is a tool you'd
  hand to a colleague who doesn't use vim, that assumption is wrong and `z`/`y`/`g`
  should become `F3`/`Ctrl-C`/`Enter`.

**A:** Somewhat.
I'm not that much interested in viewind folders in custom UI. I can do that elsewhere.
I would want to have a FS table viewer for folders and files, maybe with assistance view of actual folders. I want to figure out what FS entries where just deleted. And if I delete something (my sanitize app), I'd like to makre sure there is no traces in FS.

## 4. Copy format — is TSV right for tables?

`y t` produces tab-separated text so it pastes into a spreadsheet. Alternatives:
aligned plain text (better for forum posts and emails), Markdown table (better for
GitHub issues), or all three on different keys. What do you actually paste into?

**A:** I thinks it must be ok, lets make it and test.

## 5. Does the tool need to handle non-block sources?

Concretely: a `.img` file, yes (that's the test harness). But also —

- A raw dump over stdin (can't seek; would need buffering or refusal)
- A remote device over SSH (`ssh host dd ...`)
- A compressed image (`.img.xz`), which can't seek cheaply
- A `.vmdk` / `.qcow2`

Each of these is a `BlockSource` implementation and none is hard, but non-seekable
sources would constrain the model (no more "jump to the last sector"). If any of
these matter, say so now, because "always seekable" is currently baked in.

**A:**  *.img is a great idea, actually. SSH, compressed and proprietary be damned. No need to deal with them. I don't see how that effort pays off.

## 6. How much do you care about SPI flash / raw NAND?

You listed jffs2 and SPIFFS at rank 7. Those live on MTD devices, not block
devices: different access model (`/dev/mtd*`, erase blocks, OOB/spare areas, bad
block markers), and often you're looking at a dump from a programmer rather than a
device at all.

If that's a real target, it changes `BlockSource` — it would need an optional
out-of-band data channel and an erase-block concept. Cheap to design in now,
expensive to retrofit. If it's a "someday, maybe", I'd leave it out and accept the
retrofit cost.

**A:** little to not at all. Nice to have but I'll drop that requirement if that adds extra complexity.

## 7. Is `sudo blktamper` acceptable, or do you want a privileged helper?

The alternatives are: run the whole TUI as root (simple, and everything the TUI
does is then root — including the clipboard call into your session), or split a
small privileged I/O helper that talks to an unprivileged UI over a pipe (correct,
and a meaningful amount of extra work).

For a tool whose entire purpose is raw disk access, I'd argue `sudo` on the whole
thing is honest and the helper is over-engineering. But if you ever want this
usable by a non-admin, the helper is the only way, and the `BlockSource` trait is
where that seam would go.

**A:** I guess sudo is fine.

## 8. Name

`blktamper` reads as read-only, and the tool writes. Not important, but you'll be
typing it for a while. `blkedit`, `dsect`, `sectr`, `hexfs`, `stratum`? Your call —
and the current name is fine if the read-only connotation doesn't bother you.


**A:** Let's call it for what it is then, `blktamper`.

---

## Things I'm *not* asking, because I've assumed an answer

Tell me if any of these are wrong:

- Rust 2024 edition, MSRV = whatever's current. (You have 1.98.1.)
- MIT licence throughout, matching the existing `LICENSE`. This is why
  [ADR-001](03-decisions.md) says to transcribe partition-type tables rather than
  copy them from GPL sources.
- `ratatui` + `crossterm`, not `cursive`.
- No async runtime. One I/O worker thread and channels is enough; `tokio` would be
  a large dependency for one thread.
- Config file at `$XDG_CONFIG_HOME/blktamper/config.toml`, for keymap overrides and
  the clipboard command. Not needed before M2.
- Logs to `$XDG_STATE_HOME/blktamper/log`, never to stdout.
