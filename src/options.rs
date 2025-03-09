use std::path::PathBuf;

use clap::{Parser, Subcommand};
use log::LevelFilter;

#[derive(Subcommand)]
pub enum Command {
    Attach {
        file: PathBuf,
    },
    Detach {
        #[arg(short, long)]
        cleanup: bool,
    },
}

#[derive(Parser)]
pub struct Options {
    #[arg(short, long)]
    /// creates maps from scratch, scrapping previously
    /// pinned maps and their contents
    pub purge_maps: bool,

    #[cfg_attr(debug_assertions, arg(short, long))] // defaults to true when compiling in debug
    #[cfg_attr(not(debug_assertions), arg(short, long))]
    /// verbose debug output (Info)
    pub verbose: bool,

    #[arg(long("vv"))]
    /// very verbose debug output (Debug)
    pub very_verbose: bool,

    #[arg(short, long)]
    /// limit console output to only hard errors
    pub silent: bool,

    #[arg(short, long, default_value = "./Config.toml")]
    /// specifies a config file
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

impl Options {
    pub fn log_level(&self) -> Option<LevelFilter> {
        const DEFAULT_LEVEL: LevelFilter = LevelFilter::Warn;

        match (self.verbose, self.very_verbose, self.silent) {
            // default
            (false, false, false) => Some(DEFAULT_LEVEL),
            // all other options
            (false, true, false) => Some(LevelFilter::Debug),
            (true, false, false) => Some(LevelFilter::Info),
            (false, false, true) => Some(LevelFilter::Error),
            _ => None, // invalid combination
        }
    }
}
