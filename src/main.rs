#[warn(clippy::pedantic)]
mod config;
pub mod options;
pub mod pin;

use std::{collections::HashMap, time::Duration};

use anyhow::Context;
use aya::{
    maps::{Map, ProgramArray},
    programs::{links::FdLink, ProgramError, Xdp},
    EbpfLoader,
};
use clap::Parser;
use config::Config;
use log::LevelFilter;
use options::{Command, Options};
use pin::PinFolder;

pub struct DirectorySystem {
    maps: PinFolder,
    links: PinFolder,
    programs: PinFolder,
}

impl DirectorySystem {
    pub fn new(maps: PinFolder, links: PinFolder, programs: PinFolder) -> Self {
        Self {
            maps,
            links,
            programs,
        }
    }
}

// impl TryFrom<config::Directories> for DirectorySystem {
//     type Error = anyhow::Error;
//     fn try_from(value: config::Directories) -> Result<Self, Self::Error> {}
// }

fn detach_command(mut directories: DirectorySystem, cleanup: bool) -> anyhow::Result<()> {
    log::info!("Detaching XDP links and programs");

    directories.links.unpin_all()?;
    directories.programs.unpin_all()?;

    if !cleanup {
        return Ok(());
    }

    // proceed with folder cleanup
    directories.links.cleanup()?;
    directories.programs.cleanup()?;

    if directories.maps.cleanup().is_err() {
        log::warn!("Cannot cleanup maps because the folder is not empty. Retry the command with the -p (purge) option.");
    };

    Ok(())
}

fn run(options: Options) -> anyhow::Result<()> {
    let config = Config::from_file(&options.config).context("error reading configuration file")?;

    let [maps, links, programs] = config.directories.to_pin_folders()?;
    let mut directories = DirectorySystem::new(maps, links, programs);

    if options.purge_maps {
        log::warn!("Deleting maps as requested...");

        directories
            .maps
            .unpin_all()
            .context("error unloading maps")?;
    }

    let bpf_file = match options.command {
        Command::Detach { cleanup } => return detach_command(directories, cleanup),
        Command::Attach { file } => file,
    };

    // load the elf file containing the program
    // and load the existing bpf maps
    let mut bpf = EbpfLoader::new()
        .map_pin_path(&directories.maps)
        .load_file(&bpf_file)?;

    // get map names from bpf then create a hashmap of map names and maps
    let bpf_maps: Vec<String> = bpf.maps().map(|(name, _)| name.to_string()).collect();
    let mut bpf_maps: HashMap<String, Map> = bpf_maps
        .into_iter()
        .filter(|name| name != ".rodata")
        .map(|name| {
            let map = bpf.take_map(&name).unwrap();
            (name, map)
        })
        .collect();

    let mut programs: HashMap<&str, &mut Xdp> = bpf
        .programs_mut()
        .map(|(name, program)| Ok((name, program.try_into()?)))
        .collect::<Result<HashMap<_, _>, ProgramError>>()
        .context("One of the program specified is not an XDP program type")?;

    // try loading every program into kernel memory
    log::info!("Loading all programs into memory...");
    programs
        .iter_mut()
        .try_for_each(|(_, program)| program.load())?;

    std::thread::sleep(Duration::from_millis(100));

    log::info!("Setting up jump tables...");
    for (table_name, entries) in config.tables {
        let table = bpf_maps
            .get_mut(&table_name)
            .with_context(|| format!("{table_name} isn't a bpf map"))?;

        let mut table: ProgramArray<_> = table
            .try_into()
            .with_context(|| format!("{table_name} isn't an array of programs (wrong map type)"))?;

        for entry in entries {
            let program = programs
                .get(&*entry.program)
                .with_context(|| format!("table program {} was not found", &entry.program))?;

            let program = program.fd().context("could not get fd of program")?;

            table
                .set(entry.index, program, 0)
                .context("failed setting program into map")?;
        }
    }

    log::info!("Detaching all XDP links...");
    directories.links.unpin_all()?;
    std::thread::sleep(Duration::from_millis(100));

    log::info!("Attaching XDP links...");
    for attachable in config.attach {
        let program = programs
            .get_mut(&*attachable.program)
            .context("program to attach not found")?;

        for iface in attachable.ifaces {
            let link = program
                .attach(&iface, attachable.attach_mode.flag())
                .context("failed attaching interface")?;

            let link = program.take_link(link).context("error taking link")?;
            let link: FdLink = link.try_into()?;

            let link_name = format!("{}_{}", iface, &attachable.program);
            let path = directories.links.as_ref().join(link_name);

            link.pin(path)?;
        }
    }

    log::info!("Unpinning all old programs...");
    directories.programs.unpin_all()?;

    log::info!("Pinning new programs...");
    pin::pin_all(&directories.programs, programs.into_iter())?;

    Ok(())
}

fn main() {
    let options = Options::parse();

    let filter_level = if options.verbose {
        LevelFilter::Info
    } else {
        LevelFilter::Warn
    };

    // maybe in another life
    // let filter_level = [LevelFilter::Info, LevelFilter::Warn][options.verbose as usize];

    env_logger::builder()
        .filter_level(filter_level)
        .parse_default_env()
        .init();

    if let Err(error) = run(options) {
        log::error!("Program exited with error:\n{error:?}");
    }
}
