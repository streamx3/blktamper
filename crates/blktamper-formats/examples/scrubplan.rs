//! Print the scrub plan for every deleted record in a FAT or exFAT volume.
//! Describes only — writes nothing.
use blktamper_core::scrub::ScrubMode;
use blktamper_core::{BlockSource, Children, Fill, Node, RegionReader};
use std::sync::Arc;

/// Every node the reader is willing to scrub. Not a label match: the two format
/// modules word their labels differently, and `scrub_plan` returning `Some` is the
/// actual predicate.
fn walk(n: &Node, src: &dyn BlockSource, r: &dyn RegionReader, out: &mut Vec<Node>) {
    if r.scrub_plan(n, ScrubMode::Record(Fill::Neutral)).is_some() {
        out.push(n.clone());
        return;
    }
    match &n.children {
        Children::Resolved(k) => k.iter().for_each(|c| walk(c, src, r, out)),
        Children::Lazy(e) => e.expand(src).iter().for_each(|c| walk(c, src, r, out)),
        Children::None => {}
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: scrubplan <image> [offset]");
    let at: u64 = std::env::args().nth(2).map(|s| s.parse().unwrap()).unwrap_or(0);
    let (src, _) = blktamper_io::open_path(&path, blktamper_io::Access::ReadOnly).unwrap();
    let src: Arc<dyn BlockSource> = src;
    let reg = blktamper_formats::registry();
    let (id, score) = reg.best(&*src, at).expect("nothing recognised");
    println!("{id} at {at:#x} (confidence {score})");
    let reader = reg.get(id).unwrap().open(src.clone(), at);

    let mut found = Vec::new();
    walk(&reader.root(), &*src, &*reader, &mut found);
    println!("{} deleted record(s)\n", found.len());

    for n in &found {
        for mode in [ScrubMode::Record(Fill::Neutral), ScrubMode::Record(Fill::Zero), ScrubMode::Sweep, ScrubMode::Compact] {
            match reader.scrub_plan(n, mode) {
                Some(p) => {
                    println!("== {} [{}]", p.label, mode.label());
                    println!("   {} record(s), {} bytes change", p.records(), p.bytes_changed());
                    for e in &p.edits {
                        println!("   edit @{:#012X} {} bytes", e.offset, e.new.len());
                    }
                    for (s, c) in p.sectors_touched(512) {
                        println!("   rewrites sector {s} in full ({c} of 512 bytes change)");
                    }
                    println!("   removes:");
                    for r in &p.removes { println!("     - {r}"); }
                    println!("   keeps:");
                    for k in &p.keeps { println!("     - {k}"); }
                    match &p.zero_refusal {
                        Some(r) => println!("   zero: REFUSED - {}", r.message()),
                        None => println!("   zero: available"),
                    }
                    for w in &p.warnings { println!("   ! {}", w.message); }
                    println!();
                }
                None => println!("== {} [{}]: no plan\n", n.label, mode.label()),
            }
        }
    }
}
