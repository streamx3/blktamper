//! Turning a node into text.
//!
//! Lives in core, not in the TUI, because the copy formats (R-6.1..R-6.4) and a
//! future non-interactive mode need exactly the same strings the screen shows. The
//! TUI adds colour; it does not add meaning (R-8.2).

use crate::node::{Node, NodeKind};
use crate::value::{
    ascii_lossy, format_guid_mixed_endian, group_digits, hex_bytes, human_size, RenderCtx, Repr,
    Value,
};

/// One spelling of a byte offset everywhere in the UI, so columns line up and
/// copied text is greppable. Ten hex digits covers a 1 PiB device.
pub fn fmt_offset(off: u64) -> String {
    format!("{off:#012X}")
}

/// The raw column: bytes exactly as stored.
pub fn render_raw(node: &Node, max_bytes: usize) -> String {
    if node.raw.is_empty() {
        return "--".into();
    }
    if node.raw.len() <= max_bytes {
        hex_bytes(&node.raw)
    } else {
        format!("{}..", hex_bytes(&node.raw[..max_bytes.saturating_sub(1)]))
    }
}

/// The decoded column: what the value means.
pub fn render_value(node: &Node, ctx: &RenderCtx) -> String {
    let v = &node.value;
    // Containers describe themselves by what they hold. "??" is reserved for a
    // value that genuinely could not be read, and must not be spent on a node that
    // was never going to have one.
    if matches!(node.kind, NodeKind::Array | NodeKind::Group | NodeKind::Region)
        || matches!(v, Value::Composite)
    {
        return match node.children.len_hint() {
            Some(0) | None => String::new(),
            Some(1) => "1 record".into(),
            Some(n) => format!("{n} records"),
        };
    }
    if v.is_unset() && node.raw.is_empty() {
        return "??".into();
    }
    match node.repr {
        Repr::Hex => match v.as_u64() {
            Some(n) => format!("{:#0width$X}", n, width = 2 + node.raw.len().max(1) * 2),
            None => hex_bytes(&node.raw),
        },
        Repr::Dec => match v {
            Value::Uint(n) => group_digits(*n),
            Value::Int(n) => n.to_string(),
            Value::Bool(b) => (if *b { "yes" } else { "no" }).into(),
            other => other.to_string(),
        },
        Repr::HexDec => match v.as_u64() {
            Some(n) => format!("{n:#X} ({})", group_digits(n)),
            None => v.to_string(),
        },
        Repr::Enum(table) => match table.lookup(v) {
            Some(e) => e.label.to_string(),
            None => match v {
                Value::Guid(g) => format!("{} (unknown)", format_guid_mixed_endian(g)),
                other => match other.as_u64() {
                    Some(n) => format!("{n:#X} (unknown)"),
                    None => other.to_string(),
                },
            },
        },
        Repr::Flags(table) => {
            let Some(n) = v.as_u64() else { return v.to_string() };
            let set: Vec<&str> = table
                .bits
                .iter()
                .filter(|b| (n >> b.bit) & 1 == 1)
                .map(|b| b.label)
                .collect();
            if set.is_empty() {
                format!("{n:#X} (none set)")
            } else {
                format!("{n:#X} {}", set.join(", "))
            }
        }
        Repr::Guid => match v {
            Value::Guid(g) => format_guid_mixed_endian(g),
            other => other.to_string(),
        },
        Repr::Chs => match v {
            Value::Chs { head, sector, cylinder } => {
                if *head == 0xFE && *sector == 0x3F && *cylinder == 0x3FF {
                    format!("h{head} s{sector} c{cylinder} (overflow marker)")
                } else {
                    format!("h{head} s{sector} c{cylinder}")
                }
            }
            other => other.to_string(),
        },
        Repr::Lba => match v.as_u64() {
            Some(n) => match ctx.lba_to_byte(n) {
                Some(b) => format!("{} -> {}", group_digits(n), fmt_offset(b)),
                None => format!("{} -> overflow", group_digits(n)),
            },
            None => v.to_string(),
        },
        Repr::Cluster => match v.as_u64() {
            Some(n) => match ctx.cluster_to_byte(n) {
                Some(b) => format!("{n} -> {}", fmt_offset(b)),
                None => format!("{n}"),
            },
            None => v.to_string(),
        },
        Repr::Ascii => match v {
            Value::Text(s) => format!("\"{s}\""),
            _ => format!("\"{}\"", ascii_lossy(&node.raw, true)),
        },
        Repr::Utf16Le => match v {
            Value::Text(s) if s.is_empty() => "\"\"".into(),
            Value::Text(s) => format!("\"{s}\""),
            _ => v.to_string(),
        },
        Repr::SizeBytes => match v.as_u64() {
            Some(n) => format!("{} ({})", group_digits(n), human_size(n)),
            None => v.to_string(),
        },
        Repr::SizeSectors => match v.as_u64() {
            Some(n) => {
                let bytes = n.saturating_mul(ctx.sector_size as u64);
                format!("{} sectors ({})", group_digits(n), human_size(bytes))
            }
            None => v.to_string(),
        },
        Repr::DosDateTime | Repr::DosDate | Repr::DosTime | Repr::ExfatTime => {
            render_time(node.repr, v)
        }
        Repr::Checksum => {
            let stored = v.as_u64().unwrap_or(0);
            match &node.derived {
                Some(d) => {
                    let computed = d.value.as_u64().unwrap_or(0);
                    if d.matches {
                        format!("{stored:#010X} OK")
                    } else {
                        format!("{stored:#010X} != {computed:#010X}")
                    }
                }
                None => format!("{stored:#010X}"),
            }
        }
        Repr::Raw => {
            if node.kind == NodeKind::Gap {
                format!("{} bytes", node.raw.len())
            } else if node.raw.iter().all(|&b| b == 0) && !node.raw.is_empty() {
                format!("all zero ({} bytes)", node.raw.len())
            } else if node.raw.iter().all(|&b| b == 0xFF) && !node.raw.is_empty() {
                format!("all 0xFF ({} bytes)", node.raw.len())
            } else {
                let printable = ascii_lossy(&node.raw, true);
                if printable.chars().filter(|c| *c != '.').count() * 2 > node.raw.len() {
                    format!("\"{printable}\"")
                } else {
                    format!("{} bytes", node.raw.len())
                }
            }
        }
    }
}

fn render_time(repr: Repr, v: &Value) -> String {
    let Some(raw) = v.as_u64() else { return v.to_string() };
    // DOS date: yyyyyyym mmmddddd counting years from 1980.
    // DOS time: hhhhhmmm mmmsssss with two-second resolution.
    let (date, time) = match repr {
        Repr::DosDate => ((raw & 0xFFFF) as u32, 0u32),
        Repr::DosTime => (0u32, (raw & 0xFFFF) as u32),
        _ => (((raw >> 16) & 0xFFFF) as u32, (raw & 0xFFFF) as u32),
    };
    let (y, mo, d) = (1980 + ((date >> 9) & 0x7F), (date >> 5) & 0x0F, date & 0x1F);
    let (h, mi, s) = ((time >> 11) & 0x1F, (time >> 5) & 0x3F, (time & 0x1F) * 2);
    match repr {
        Repr::DosDate => format!("{y:04}-{mo:02}-{d:02}"),
        Repr::DosTime => format!("{h:02}:{mi:02}:{s:02}"),
        _ => format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}"),
    }
}

/// `y` — just the decoded value.
pub fn copy_value(node: &Node, ctx: &RenderCtx) -> String {
    render_value(node, ctx)
}

/// `Y` — label, raw, decoded, offset and size. The form you paste into a bug report.
pub fn copy_labelled(node: &Node, path: &str, ctx: &RenderCtx) -> String {
    let loc = match node.extent.first() {
        Some(s) if s.is_byte_aligned() => {
            format!("@{} ({} B)", fmt_offset(s.start_byte()), s.byte_len())
        }
        Some(s) => format!("@{}.{} ({} bits)", fmt_offset(s.start_byte()), s.start_bit % 8, s.len_bits),
        None => "(computed)".into(),
    };
    let raw = render_raw(node, 16);
    format!("{path}  {raw}  {}  {loc}", render_value(node, ctx))
}

/// `y h` — a hex dump of the node's bytes.
pub fn copy_hexdump(node: &Node) -> String {
    let base = node.extent.first().map(|s| s.start_byte()).unwrap_or(0);
    hexdump(&node.raw, base)
}

/// `y t` — the visible rows as TSV, so it pastes into a spreadsheet (R-6.3).
pub fn copy_tsv(rows: &[(&str, &Node)], ctx: &RenderCtx) -> String {
    let mut out = String::from("path\toffset\tsize\traw\tdecoded\tstatus\n");
    for (path, n) in rows {
        let (off, size) = match n.extent.first() {
            Some(s) => (format!("{:#X}", s.start_byte()), s.byte_len().to_string()),
            None => ("".into(), "".into()),
        };
        out.push_str(&format!(
            "{path}\t{off}\t{size}\t{}\t{}\t{}\n",
            render_raw(n, 32),
            render_value(n, ctx).replace('\t', " "),
            n.status.glyph()
        ));
    }
    out
}

/// Classic 16-bytes-per-line hex dump with an ASCII gutter.
pub fn hexdump(bytes: &[u8], base: u64) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        out.push_str(&format!("{addr:08X}  "));
        for j in 0..16 {
            if j == 8 {
                out.push(' ');
            }
            match chunk.get(j) {
                Some(b) => out.push_str(&format!("{b:02X} ")),
                None => out.push_str("   "),
            }
        }
        out.push_str(" |");
        out.push_str(&ascii_lossy(chunk, false));
        out.push_str("|\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use crate::span::{Extent, Span};
    use crate::value::{EnumEntry, EnumTable};

    fn node(repr: Repr, value: Value, raw: Vec<u8>) -> Node {
        Node {
            label: "f".into(),
            extent: Extent::One(Span::bytes(0x1C2, raw.len() as u64)),
            value,
            repr,
            raw,
            ..Default::default()
        }
    }

    #[test]
    fn containers_report_their_contents_not_a_question_mark() {
        use crate::node::{Children, NodeKind};
        let mut n = node(Repr::Raw, Value::Composite, vec![]);
        n.kind = NodeKind::Array;
        n.children = Children::Resolved(vec![Node::default(), Node::default()]);
        assert_eq!(render_value(&n, &RenderCtx::default()), "2 records");

        // A field that really could not be read still says so.
        let unread = node(Repr::Dec, Value::Unset, vec![]);
        assert_eq!(render_value(&unread, &RenderCtx::default()), "??");
    }

    #[test]
    fn unknown_enum_values_still_show_the_number() {
        static T: EnumTable =
            EnumTable { name: "t", entries: &[EnumEntry::num(0x0C, "FAT32 LBA", "")] };
        let n = node(Repr::Enum(&T), Value::Uint(0x0C), vec![0x0C]);
        assert_eq!(render_value(&n, &RenderCtx::default()), "FAT32 LBA");
        let n = node(Repr::Enum(&T), Value::Uint(0x9A), vec![0x9A]);
        assert_eq!(render_value(&n, &RenderCtx::default()), "0x9A (unknown)");
    }

    #[test]
    fn lba_shows_its_byte_offset() {
        let n = node(Repr::Lba, Value::Uint(2048), vec![0, 8, 0, 0]);
        assert_eq!(render_value(&n, &RenderCtx::default()), "2,048 -> 0x0000100000");
    }

    #[test]
    fn chs_overflow_marker_is_called_out() {
        let n = node(Repr::Chs, Value::Chs { head: 254, sector: 63, cylinder: 1023 }, vec![0xFE, 0xFF, 0xFF]);
        assert!(render_value(&n, &RenderCtx::default()).contains("overflow marker"));
    }

    #[test]
    fn checksum_shows_stored_and_computed() {
        let mut n = node(Repr::Checksum, Value::Uint(0xA13F2290), vec![0x90, 0x22, 0x3F, 0xA1]);
        n.derived = Some(crate::checksum::Derived::checksum(0x7C41BE05, Some(0xA13F2290), ""));
        assert_eq!(render_value(&n, &RenderCtx::default()), "0xA13F2290 != 0x7C41BE05");
        n.derived = Some(crate::checksum::Derived::checksum(0xA13F2290, Some(0xA13F2290), ""));
        assert_eq!(render_value(&n, &RenderCtx::default()), "0xA13F2290 OK");
    }

    #[test]
    fn dos_datetime_decodes() {
        // 2026-09-16 02:29:00 -> date 0x5D10, time 0x13A0
        let date: u64 = ((2026 - 1980) << 9) | (9 << 5) | 16;
        let time: u64 = (2 << 11) | (29 << 5); // 02:29:00, seconds field zero
        let n = node(Repr::DosDateTime, Value::Uint((date << 16) | time), vec![0; 4]);
        assert_eq!(render_value(&n, &RenderCtx::default()), "2026-09-16 02:29:00");
    }

    #[test]
    fn labelled_copy_carries_the_offset() {
        let n = node(Repr::Hex, Value::Uint(0x0C), vec![0x0C]);
        let s = copy_labelled(&n, "mbr.entries[0].part_type", &RenderCtx::default());
        assert!(s.contains("mbr.entries[0].part_type"));
        assert!(s.contains("0C"));
        assert!(s.contains("@0x00000001C2"));
        assert!(s.contains("(1 B)"));
    }

    #[test]
    fn tsv_has_a_header_and_one_row_per_node() {
        let n = node(Repr::Dec, Value::Uint(7), vec![7]);
        let tsv = copy_tsv(&[("a.b", &n)], &RenderCtx::default());
        assert_eq!(tsv.lines().count(), 2);
        assert!(tsv.lines().next().unwrap().starts_with("path\toffset"));
    }

    #[test]
    fn hexdump_pads_short_final_lines() {
        let d = hexdump(&[1, 2, 3], 0x1B0);
        assert!(d.starts_with("000001B0  01 02 03 "));
        assert!(d.trim_end().ends_with("|...|"));
    }
}
