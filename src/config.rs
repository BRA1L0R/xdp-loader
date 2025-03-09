use std::{
    collections::HashMap,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use aya::programs::XdpFlags;
use serde::Deserialize;
use thiserror::Error;

use crate::pin::PinFolder;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}

#[derive(Deserialize, Default)]
pub enum AttachMode {
    Driver,
    Hardware,
    #[default]
    Skb,
}

impl AttachMode {
    pub fn flag(&self) -> XdpFlags {
        match self {
            AttachMode::Driver => XdpFlags::DRV_MODE,
            AttachMode::Hardware => XdpFlags::HW_MODE,
            AttachMode::Skb => XdpFlags::SKB_MODE,
        }
    }
}

#[derive(Deserialize, Default)]
pub struct Overrides {
    #[serde(default)]
    pub maps: Option<PathBuf>,
    #[serde(default)]
    pub links: Option<PathBuf>,
    #[serde(default)]
    pub programs: Option<PathBuf>,
}

#[derive(Deserialize)]
pub struct Directories {
    // pub maps: Option<PathBuf>,
    // pub links: Option<PathBuf>,
    // pub programs: Option<PathBuf>,
    base: PathBuf,

    #[serde(default)]
    overrides: Overrides,
}

impl Directories {
    /// returns an array of maps
    /// ```rust
    /// let [maps_folder, links_folder, programs_folder] = directories.to_pin_folders()?;
    /// ```
    pub fn to_pin_folders(&self) -> std::io::Result<[PinFolder; 3]> {
        if let Err(err) = std::fs::create_dir(&self.base) {
            if err.kind() != ErrorKind::AlreadyExists {
                return Err(err);
            }
        }

        let folders = [
            (&self.overrides.maps, "maps"),
            (&self.overrides.links, "links"),
            (&self.overrides.programs, "programs"),
        ];

        let [maps, links, programs] =
            folders.map(|(replacement, name)| replacement.clone().unwrap_or(self.base.join(name)));

        Ok([
            PinFolder::open_or_create(maps)?,
            PinFolder::open_or_create(links)?,
            PinFolder::open_or_create(programs)?,
        ])
    }

    pub fn base(&self) -> &Path {
        &self.base
    }
}

#[derive(Deserialize)]
pub struct AttachableProgram {
    pub program: String,
    pub ifaces: Vec<String>,

    #[serde(default)]
    pub attach_mode: AttachMode,
}

#[derive(Deserialize)]
pub struct TableEntry {
    pub program: String,
    pub index: u32,
}

#[derive(Deserialize)]
pub struct Config {
    // pub project_name: String,

    // pub base_directory: PathBuf,
    pub directories: Directories,

    pub tables: HashMap<String, Vec<TableEntry>>,
    pub attach: Vec<AttachableProgram>,
}

impl Config {
    pub fn from_file(file: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let read = std::fs::read_to_string(file)?;
        let config = toml::from_str(&read)?;

        Ok(config)
    }
}
