use std::alloc::Layout;

use anyhow::{bail, Context};
use aya::{
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;

#[derive(Parser)]
struct Options {
    #[arg(short)]
    interface: String,
    #[arg(short, long)]
    mode: Option<String>,
    #[arg(short, long, default_value_t = false)]
    logging: bool,
    #[arg(short, long, default_value_t = false)]
    pin_maps: bool,

    file: String,
}

fn main() -> anyhow::Result<()> {
    run()
}

fn run() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new()
        .env()
        .with_level(log::LevelFilter::Info)
        .init()?;

    let options = Options::parse();

    let mode = match options.mode.as_deref() {
        Some("driver") => XdpFlags::DRV_MODE,
        Some("hardware") => XdpFlags::HW_MODE,
        Some(unk) => bail!("Unknown XDP mode `{unk}`"),
        _ => {
            log::warn!("XDP mode not specified: using SKB_MODE. This emulated mode DOES NOT perform well and should not be used outside of testing");
            XdpFlags::default()
        }
    };

    log::info!("Chosen XDP flags: {mode:?}");

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::warn!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let read = std::fs::read(options.file)?;

    let alloc = unsafe { std::alloc::alloc(Layout::from_size_align(read.len(), 32).unwrap()) };
    let mut aligned = unsafe { Vec::from_raw_parts(alloc, 0, read.len()) };
    aligned.extend_from_slice(&read);

    let mut program = Ebpf::load(&aligned).unwrap();

    if options.logging {
        EbpfLogger::init(&mut program).unwrap();
    }

    if options.pin_maps {
        for (name, map) in program.maps() {
            let map_path = format!("/sys/fs/bpf/{name}");

            std::fs::remove_file(&map_path).ok();
            map.pin(&map_path).context("failed to pin map")?;
        }
    }

    for (name, program) in program.programs_mut() {
        log::info!("Loading {name} program...");

        let program: &mut Xdp = program.try_into().context("expected XDP program")?;

        program.load()?;
        program.attach(&options.interface, mode)?;
    }

    log::info!("Loaded everything!");
    // signal::ctrl_c().await?;
    // ctrlc::

    loop {
        std::thread::park()
    }
}
