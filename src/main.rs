use std::alloc::Layout;

use anyhow::Context;
use aya::{
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use tokio::signal;

#[derive(Parser)]
struct Options {
    interface: String,
    mode: Option<String>,
    file: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

async fn run() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new()
        .env()
        .with_level(log::LevelFilter::Info)
        .init()?;

    let options = Options::parse();

    let mode = match options.mode.as_deref() {
        Some("driver") => XdpFlags::DRV_MODE,
        Some("hardware") => XdpFlags::HW_MODE,
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

    EbpfLogger::init(&mut program).unwrap();

    for (name, program) in program.programs_mut() {
        log::info!("Loading {name} program...");

        let program: &mut Xdp = program.try_into().context("expected XDP program")?;

        program.load()?;
        program.attach(&options.interface, mode)?;
    }

    log::info!("Loaded everything!");

    signal::ctrl_c().await?;

    Ok(())
}
