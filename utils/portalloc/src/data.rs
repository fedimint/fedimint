mod dto;

use std::path::PathBuf;
use std::time::Duration;
use std::{fs, thread};

use anyhow::{bail, Result};
use fs2::FileExt;
use tracing::{debug, info, warn};

use crate::util;

/// Root directory where we keep the lock & data file
pub struct DataDir {
    path: PathBuf,
    lock_file: fs::File,
}

impl DataDir {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        ensure_root_exists(&path)?;

        let lock = util::open_lock_file(&path)?;

        Ok(Self {
            path,
            lock_file: lock,
        })
    }

    pub fn with_lock<T>(&mut self, f: impl FnOnce(&mut LockedRoot) -> Result<T>) -> Result<T> {
        f(&mut LockedRoot::new(&self.path, &mut self.lock_file)?)
    }
}

fn ensure_root_exists(dir: &PathBuf) -> Result<()> {
    if !dir.try_exists()? {
        info!(dir = %dir.display(), "Creating root dir");
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// A handle passed to `with_lock` argument after root was acquired
pub struct LockedRoot<'a> {
    path: &'a PathBuf,
    lock_file: &'a mut fs::File,
    locked: bool,
}

impl<'a> Drop for LockedRoot<'a> {
    fn drop(&mut self) {
        if self.locked {
            let Ok(()) = self.lock_file.unlock() else {
                warn!("Failed to release the lock file");
                return;
            };
            self.locked = false;
        }
    }
}

impl<'a> LockedRoot<'a> {
    fn new(path: &'a PathBuf, lock_file: &'a mut fs::File) -> Result<Self> {
        let mut locked_root = Self {
            path,
            lock_file,
            locked: false,
        };
        locked_root.lock()?;
        Ok(locked_root)
    }

    fn lock(&mut self) -> Result<()> {
        debug!(path = %self.path.display(), "Acquiring lock...");
        if self.lock_file.try_lock_exclusive().is_err() {
            info!("Lock taken, waiting...");
            self.lock_file.lock_exclusive()?;
        };
        debug!("Acquired lock");
        self.locked = true;
        Ok(())
    }

    fn unlock(&mut self) -> Result<()> {
        self.ensure_locked()?;
        debug!(path = %self.path.display(), "Releasing lock...");
        self.lock_file.unlock()?;
        self.locked = false;
        Ok(())
    }

    fn data_file_path(&self) -> PathBuf {
        self.path.join("fm-portalloc.json")
    }

    fn ensure_locked(&self) -> anyhow::Result<()> {
        if !self.locked {
            bail!("LockedRoot no longer valid");
        }
        Ok(())
    }

    pub fn r#yield(&mut self, duration: Duration) -> Result<()> {
        self.unlock()?;
        thread::sleep(duration);
        self.lock()?;
        Ok(())
    }
    pub fn load_data(&self, now: u64) -> Result<dto::RootData> {
        self.ensure_locked()?;
        let path = self.data_file_path();
        if !path.try_exists()? {
            return Ok(Default::default());
        }
        let root_data: dto::RootData = serde_json::from_reader::<_, _>(std::fs::File::open(path)?)?;
        Ok(root_data.reclaim(now))
    }

    pub fn store_data(&mut self, data: &dto::RootData) -> Result<()> {
        util::store_json_pretty_to_file(&self.data_file_path(), data)
    }
}
