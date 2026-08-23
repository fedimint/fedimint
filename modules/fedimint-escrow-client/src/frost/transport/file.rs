use std::path::PathBuf;

pub struct FileTransport {
    inner: PathBuf,
}

impl FileTransport {
    pub fn default() -> Result<FileTransport> {
        Ok(FileTransport { inner: () })
    }
}
