//! Print the descriptor tables as text.
//!
//! ```text
//! cargo run -p blktamper-formats --example fields                  # everything
//! cargo run -p blktamper-formats --example fields -- "directory"   # matching names
//! ```
//!
//! Useful when writing a new descriptor, when checking one against a specification,
//! and when answering "what exactly is in this record" without reading the source.
//! It also demonstrates the point of ADR-002: the tables are plain data, so this
//! whole program is thirty lines.

fn main() {
    let want: Vec<String> = std::env::args().skip(1).map(|s| s.to_lowercase()).collect();
    for d in blktamper_formats::all_descriptors() {
        let name = d.name.to_lowercase();
        if !want.is_empty() && !want.iter().any(|w| name.contains(w.as_str())) {
            continue;
        }
        match d.size {
            Some(n) => println!("\n## {}  ({n} bytes)  [{}]", d.name, d.spec),
            None => println!("\n## {}  (variable)  [{}]", d.name, d.spec),
        }
        println!("{:<7} {:<4} {:<30} {:<12} flags", "offset", "len", "field", "repr");
        let mut rows: Vec<(u32, u32, String, String, String)> = d
            .fields
            .iter()
            .map(|f| {
                let repr = format!("{:?}", f.repr);
                let repr = repr.split(['(', ' ']).next().unwrap_or("").to_string();
                (f.off, f.width.size(), f.name.to_string(), repr, format!("{:?}", f.flags))
            })
            .collect();
        for (off, len) in d.gaps() {
            rows.push((off, len, "(unclaimed)".into(), "-".into(), "-".into()));
        }
        rows.sort_by_key(|r| r.0);
        for (off, len, name, repr, flags) in rows {
            println!("{off:#06x}  {len:<4} {name:<30} {repr:<12} {flags}");
        }
    }
}
