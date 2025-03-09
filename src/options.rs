use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
    /// creates maps from scratch, scrapping previously
    /// pinned maps and their contents
    #[arg(short, long)]
    pub purge_maps: bool,

    #[cfg_attr(debug_assertions, arg(short, long, default_value_t = true))]
    #[cfg_attr(not(debug_assertions), arg(short, long))]
    /// verbose debug output
    pub verbose: bool,

    #[arg(short, long, default_value = "./Config.toml")]
    /// specifies a config file
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}
