use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use serde::Serialize;
use tracing::debug;

#[cfg(test)]
mod tests;

pub fn open_lock_file(root_path: &Path) -> anyhow::Result<fs::File> {
    let path = root_path.join("lock");
    debug!(path = %path.display(), "Opening lock file...");
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path.clone())?;
    debug!(path = %path.display(), "Opened lock file");
    Ok(file)
}

pub fn store_json_pretty_to_file<T>(path: &Path, val: &T) -> anyhow::Result<()>
where
    T: Serialize,
{
    Ok(store_to_file_with(path, |f| {
        serde_json::to_writer_pretty(f, val).map_err(Into::into)
    })
    .and_then(|res| res)?)
}

fn store_to_file_with<E, F>(path: &Path, f: F) -> io::Result<Result<(), E>>
where
    F: Fn(&mut dyn io::Write) -> Result<(), E>,
{
    std::fs::create_dir_all(path.parent().expect("Not a root path"))?;
    let tmp_path = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp_path)?;
    {
        let mut writer = BufWriter::new(&mut file);
        if let Err(e) = f(&mut writer) {
            return Ok(Err(e));
        }
        // Propagate buffered write errors before syncing or replacing the destination.
        writer.flush()?;
    }
    file.sync_data()?;
    drop(file);
    std::fs::rename(tmp_path, path)?;
    Ok(Ok(()))
}
