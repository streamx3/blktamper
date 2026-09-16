# blktamper documentation

A TUI structure viewer/editor for raw block devices. Read-first, forensic, honest
about what is actually on the disk — including when what's there is garbage.

## Reading order

| Doc | What it answers |
|---|---|
| [01-requirements.md](01-requirements.md) | What the thing must do. Numbered, testable. |
| [02-research.md](02-research.md) | Prior art. What already exists, what's reusable, what isn't. |
| [03-decisions.md](03-decisions.md) | **The answers to your questions**, with the arguments. |
| [04-architecture.md](04-architecture.md) | Data model, crate split, traits. |
| [05-tui-design.md](05-tui-design.md) | Screen mockups + keymap. **This is the bit to review.** |
| [06-format-scope.md](06-format-scope.md) | The format ladder, field counts, effort estimates. |
| [07-write-safety.md](07-write-safety.md) | Linux block I/O reality. Overlay, undo journal, arming. |
| [08-roadmap.md](08-roadmap.md) | Milestones with exit criteria. |
| [09-open-questions.md](09-open-questions.md) | Things I need you to decide. |
| [10-other-platforms.md](10-other-platforms.md) | Can this work on macOS and Windows? Interfaces, permissions, and what breaks. |

## The one-paragraph version

Don't use the existing filesystem crates for the view path — they are *management*
libraries that parse into owned, normalised structs, validate, and reject. This app
needs the opposite: never fail, never normalise, keep every byte's provenance. Do use
existing work as **format knowledge** (Kaitai `.ksy`, ImHex `.hexpat`, libyal specs,
Microsoft's exFAT spec) and as **test oracles** (`gptman`, `mbrman`, `fatfs`, `sgdisk`,
`mkfs.*`). Describe fixed-layout records as const data tables in Rust; write traversal
(cluster chains, extent trees, EBR chains) as ordinary Rust code. Split the workspace
so the TUI is the thinnest layer.

## Status

Nothing is implemented. These are design documents, not descriptions of code.
