use std::path::{Path, PathBuf};

use aya::{
    maps::Map,
    pin::PinError,
    programs::{links::FdLink, Xdp},
};

/// defines a pinnable resource
pub trait Pinnable: Sized {
    type Error: std::fmt::Debug;
    fn pin(self, path: impl AsRef<Path>) -> Result<(), Self::Error>;
}

impl Pinnable for &Map {
    type Error = PinError;
    fn pin(self, path: impl AsRef<Path>) -> Result<(), Self::Error> {
        self.pin(path)
    }
}

impl Pinnable for &mut Xdp {
    type Error = PinError;

    fn pin(self, path: impl AsRef<Path>) -> Result<(), Self::Error> {
        Xdp::pin(self, path)
    }
}

impl Pinnable for FdLink {
    type Error = PinError;

    fn pin(self, path: impl AsRef<Path>) -> Result<(), PinError> {
        FdLink::pin(self, path).map(|_| ())
    }
}

/// Iterator: (name, pinnable)
///
/// Path will be computed as base.join(name), UNSANITIZED!
pub fn pin_all<I, N, P>(base: impl AsRef<Path>, objs: I) -> Result<(), P::Error>
where
    N: AsRef<Path>,
    P: Pinnable,
    I: Iterator<Item = (N, P)>,
{
    let base = base.as_ref();
    objs.map(|(name, pinnable)| (base.join(name), pinnable))
        .filter(|(path, _)| !path.exists())
        .try_for_each(|(path, pinnable)| pinnable.pin(path))
}

/// Unpins all files from a directory by deleting all files from the
/// bpf filesystem
pub fn unpin_all(directory: impl AsRef<Path>) -> std::io::Result<()> {
    let directory = directory.as_ref();

    // we do not want to delete a random folder in the system.
    assert!(directory.starts_with("/sys/fs/bpf"));

    std::fs::read_dir(directory)?
        .try_for_each(|dir_entry| std::fs::remove_file(dir_entry?.path()))?;

    Ok(())
}

// a folder that contains pinnable resources
#[derive(Debug)]
pub struct PinFolder(PathBuf);

impl PinFolder {
    pub fn open_or_create(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path: PathBuf = path.into();

        if !path.exists() {
            log::debug!("Creating folder {:#?}", &path);
            std::fs::create_dir(&path)?;
        }

        Ok(PinFolder(path.canonicalize()?))
    }

    pub fn unpin_all(&mut self) -> std::io::Result<()> {
        log::debug!("Unpinning all from {:#?}", &self.0);
        std::fs::read_dir(&self.0)?.try_for_each(|dir| std::fs::remove_file(dir?.path()))
    }

    // pub fn pin_all<P, I, N>(&self, iterator: I) -> Result<(), P::Error>
    // where
    //     P: Pinnable,
    //     N: AsRef<Path>,
    //     I: Iterator<Item = (N, P)>,
    // {
    //     log::debug!("Pinning all to {:#?}", &self.0);
    //     pin_all(&self.0, iterator)
    // }

    pub fn cleanup(self) -> std::io::Result<()> {
        std::fs::remove_dir(self.0)
    }
}

impl AsRef<Path> for PinFolder {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
