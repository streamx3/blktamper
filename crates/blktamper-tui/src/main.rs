//! `blktamper` — a forensic structure viewer for block devices.
//!
//! Read-only. This build cannot write to a device at all: `blktamper-io` has no
//! write path, and the device is opened `O_RDONLY`. See `doc/07-write-safety.md`
//! for what a write-capable build would have to do first.

#![forbid(unsafe_code)]

mod app;
mod clip;
mod rows;
mod session;
mod theme;
mod ui;

use app::App;
use clap::Parser;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use session::Session;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "blktamper",
    about = "View the on-disk structures of a block device or disk image",
    long_about = "Opens a block device or disk image and shows its partition tables, \
                  filesystem headers and directory records as labelled tables, with \
                  every field traceable to the bytes it came from.\n\n\
                  This build is READ-ONLY. It opens devices O_RDONLY and has no write path."
)]
struct Cli {
    /// Block device or image file, e.g. /dev/sdc or disk.img
    device: PathBuf,

    /// Override the logical sector size. Needed for images taken from 4Kn disks,
    /// where every LBA is otherwise 8x wrong.
    #[arg(long, value_name = "BYTES")]
    sector_size: Option<u32>,

    /// Print the discovered structure as text and exit, instead of starting the UI.
    #[arg(long)]
    dump: bool,

    /// With --dump, how deep to descend.
    #[arg(long, default_value_t = 3, value_name = "N")]
    depth: usize,

    /// Render one frame at WIDTHxHEIGHT to stdout and exit. For documentation,
    /// bug reports, and checking the layout at a size you do not have to hand.
    #[arg(long, value_name = "WxH")]
    screenshot: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(s) = cli.sector_size {
        if !s.is_power_of_two() || !(512..=65536).contains(&s) {
            anyhow::bail!("--sector-size must be a power of two between 512 and 65536");
        }
    }

    let session = match Session::open(&cli.device, cli.sector_size) {
        Ok(s) => s,
        Err(e) => {
            // The advice is the point; print it plainly rather than through a
            // terminal that has not been set up yet.
            eprintln!("blktamper: {e}");
            std::process::exit(2);
        }
    };

    if cli.dump {
        return dump(session, cli.depth);
    }

    if let Some(size) = &cli.screenshot {
        let (w, h) = size
            .split_once(['x', 'X'])
            .and_then(|(a, b)| Some((a.trim().parse().ok()?, b.trim().parse().ok()?)))
            .ok_or_else(|| anyhow::anyhow!("--screenshot expects WIDTHxHEIGHT, e.g. 120x40"))?;
        print!("{}", screenshot(App::new(session), w, h));
        return Ok(());
    }

    let mut app = App::new(session);
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;
        // Poll rather than block so a future background read can repaint (R-4.6).
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.on_key(key);
                }
            }
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

/// Render one frame into a string, without touching the real terminal.
fn screenshot(mut app: App, w: u16, h: u16) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut t = Terminal::new(TestBackend::new(w, h)).expect("test backend");
    t.draw(|f| ui::draw(f, &mut app)).expect("draw");
    let buf = t.backend().buffer().clone();
    (0..buf.area.height)
        .map(|y| (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Non-interactive output. Useful in scripts, in bug reports, and for diffing two
/// disks with ordinary text tools.
fn dump(mut session: Session, depth: usize) -> anyhow::Result<()> {
    use blktamper_core::render::{fmt_offset, render_raw, render_value};
    use blktamper_core::{Node, RenderCtx};

    let ctx = RenderCtx {
        sector_size: session.sector_size,
        cluster_base: None,
        device_len: session.src.len(),
    };

    let src = session.src.clone();
    println!(
        "{} - {} - {} bytes - {}/{} B sectors",
        session.info.path.display(),
        session.info.kind.label(),
        session.info.len,
        session.info.logical_sector_size,
        session.info.physical_sector_size
    );
    for m in &session.info.mounts {
        println!("  MOUNTED: /dev/{} on {} ({})", m.device, m.mount_point, m.fs_type);
    }

    // Lazy children exist so the UI reads only what is on screen; a dump has the
    // opposite job, so it resolves as it descends. Depth is the only bound, which
    // is why --depth defaults low.
    fn walk(
        n: &Node,
        d: usize,
        max: usize,
        ctx: &RenderCtx,
        src: &dyn blktamper_core::BlockSource,
    ) {
        let pad = "  ".repeat(d);
        let off = n
            .extent
            .first()
            .map(|s| fmt_offset(s.start_byte()))
            .unwrap_or_else(|| "            ".into());
        println!(
            "{off} {pad}{} {:<24} {:<20} {}",
            n.status.glyph(),
            n.label,
            render_raw(n, 8),
            render_value(n, ctx)
        );
        for diag in &n.diags {
            println!("{:12} {pad}  {} {}", "", diag.status.glyph(), diag.message);
        }
        if d >= max {
            return;
        }
        match &n.children {
            blktamper_core::Children::Resolved(kids) => {
                for k in kids {
                    walk(k, d + 1, max, ctx, src);
                }
            }
            blktamper_core::Children::Lazy(e) => {
                for k in e.expand(src) {
                    walk(&k, d + 1, max, ctx, src);
                }
            }
            blktamper_core::Children::None => {}
        }
    }

    for i in 0..session.regions.len() {
        let label = session.regions[i].label.clone();
        let base = session.regions[i].base;
        let score = session.regions[i].score;
        println!("\n=== {label} @{} (confidence {score}) ===", fmt_offset(base));
        let root = session.regions[i].root_mut().clone();
        walk(&root, 0, depth, &ctx, &*src);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;

    fn fixture(name: &str) -> Option<PathBuf> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/gen").join(name);
        p.exists().then_some(p)
    }

    fn app_for(name: &str) -> Option<App> {
        Some(App::new(Session::open(&fixture(name)?, None).ok()?))
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| ui::draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty())
    }

    #[test]
    fn renders_a_real_mbr_without_panicking() {
        let Some(mut app) = app_for("mbr-fat32.img") else { return };
        let out = render(&mut app, 120, 40);
        assert!(out.contains("blktamper"), "{out}");
        assert!(out.contains("READ-ONLY"));
        assert!(out.contains("MBR"));
        assert!(out.contains("disk_signature"));
        assert!(out.contains("FAT32 LBA"), "the type byte must be named, not just numeric");
    }

    #[test]
    fn survives_an_80x24_terminal() {
        // The tree pane must collapse rather than overlap (doc/05-tui-design.md).
        let Some(mut app) = app_for("mbr-fat32.img") else { return };
        let out = render(&mut app, 80, 24);
        assert!(out.contains("blktamper"));
        assert_eq!(out.lines().count(), 24);
        assert!(out.lines().all(|l| l.chars().count() == 80));
    }

    #[test]
    fn survives_an_absurdly_small_terminal() {
        let Some(mut app) = app_for("mbr-fat32.img") else { return };
        for (w, h) in [(20u16, 5u16), (40, 10), (10, 3)] {
            let _ = render(&mut app, w, h);
        }
    }

    #[test]
    fn the_filter_key_cycles_and_changes_what_is_shown() {
        let Some(mut app) = app_for("mbr-fat32.img") else { return };
        let all = render(&mut app, 120, 40);
        assert!(all.contains("[1] --"), "empty slots visible in `all`");

        app.on_key(key('z')); // hide-empty
        let hidden = render(&mut app, 120, 40);
        assert!(!hidden.contains("[1] --"), "empty slots must be hidden");
        assert!(hidden.contains("empty hidden"), "and counted, so they are not forgotten");

        app.on_key(key('z')); // anomalies
        let anomalies = render(&mut app, 120, 40);
        assert!(anomalies.contains("anomalies"));

        app.on_key(key('z')); // back to all
        assert!(render(&mut app, 120, 40).contains("[1] --"));
    }

    #[test]
    fn navigation_and_popups_do_not_panic() {
        let Some(mut app) = app_for("mbr-fat32.img") else { return };
        for c in ['j', 'j', 'l', 'j', 'k', 'h', 'G', 'z', 'Z', 'H', 'w', 'i', 'q'] {
            app.on_key(key(c));
            let _ = render(&mut app, 100, 30);
            if app.should_quit {
                app.should_quit = false;
            }
        }
    }

    #[test]
    fn the_hex_pane_highlights_the_selected_fields_bytes() {
        let Some(mut app) = app_for("mbr-fat32.img") else { return };
        // walk down to a field with known bytes
        for _ in 0..3 {
            app.on_key(key('j'));
        }
        let out = render(&mut app, 120, 40);
        assert!(out.contains("Hex"), "the hex pane is always on by default");
        assert!(out.contains("000001B"), "it follows the selection");
    }

    #[test]
    fn garbage_renders_as_garbage_rather_than_crashing() {
        let Some(path) = fixture("garbage.img") else { return };
        let session = Session::open(&path, None).unwrap();
        // Nothing should have been recognised, which is the honest answer.
        let mut app = App::new(session);
        let out = render(&mut app, 100, 30);
        assert!(out.contains("blktamper"));
    }

    #[test]
    fn a_gpt_disk_shows_its_protective_mbr() {
        let Some(mut app) = app_for("gpt-basic.img") else { return };
        let out = render(&mut app, 120, 40);
        assert!(out.contains("MBR"));
    }
}
