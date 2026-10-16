use std::io;

use redb::{Database, StorageBackend};
use web_sys::wasm_bindgen::JsValue;
use web_sys::{FileSystemReadWriteOptions, FileSystemSyncAccessHandle};

use crate::read_exact::read_exact_at;
use crate::{MemAndRedb, MemAndRedbOpenError};

#[derive(Debug)]
struct WasmBackend {
    sync_handle: FileSystemSyncAccessHandle,
}

fn js_error_to_io_error(err: impl Into<JsValue>) -> io::Error {
    match gloo_utils::errors::JsError::try_from(err.into()) {
        Ok(error) => io::Error::other(error),
        // A thrown value that is not an `Error` object is not `Send`; keep its
        // text.
        Err(error) => io::Error::other(error.to_string()),
    }
}

impl WasmBackend {
    fn new(sync_handle: FileSystemSyncAccessHandle) -> Self {
        Self { sync_handle }
    }

    fn read_impl(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let options = FileSystemReadWriteOptions::new();
        read_exact_at(offset, out, |offset, out| {
            options.set_at(offset as f64);
            self.sync_handle
                .read_with_u8_array_and_options(out, &options)
                .map(|read| read as usize)
                .map_err(js_error_to_io_error)
        })
    }

    fn write_impl(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let options = FileSystemReadWriteOptions::new();
        let mut bytes_written = 0;
        while bytes_written != data.len() {
            assert!(bytes_written < data.len());
            options.set_at((offset + bytes_written as u64) as f64);

            bytes_written += self
                .sync_handle
                .write_with_u8_array_and_options(&data[bytes_written..], &options)
                .map_err(js_error_to_io_error)? as usize;
        }
        Ok(())
    }

    fn len_impl(&self) -> io::Result<u64> {
        let size = self.sync_handle.get_size().map_err(js_error_to_io_error)?;
        Ok(size as u64)
    }

    fn set_len_impl(&self, len: u64) -> io::Result<()> {
        self.sync_handle
            .truncate_with_f64(len as f64)
            .map_err(js_error_to_io_error)?;
        Ok(())
    }

    fn sync_data_impl(&self) -> io::Result<()> {
        self.sync_handle.flush().map_err(js_error_to_io_error)?;
        Ok(())
    }
}

// redb 3 StorageBackend
impl StorageBackend for WasmBackend {
    fn len(&self) -> io::Result<u64> {
        self.len_impl()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.read_impl(offset, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.set_len_impl(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.sync_data_impl()
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.write_impl(offset, data)
    }
}

// redb 2 StorageBackend (for v2 -> v3 migration)
impl redb2::StorageBackend for WasmBackend {
    fn len(&self) -> io::Result<u64> {
        self.len_impl()
    }

    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_impl(offset, &mut buf)?;
        Ok(buf)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.set_len_impl(len)
    }

    fn sync_data(&self, _eventual: bool) -> io::Result<()> {
        self.sync_data_impl()
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.write_impl(offset, data)
    }
}

// SAFETY: we don't use threads in wasm, this will fail very loudly at runtime
// if this get sent across threads
unsafe impl Send for WasmBackend {}
unsafe impl Sync for WasmBackend {}

impl MemAndRedb {
    pub fn new(file: FileSystemSyncAccessHandle) -> Result<Self, MemAndRedbOpenError> {
        let backend = WasmBackend::new(file.clone());
        match Database::builder().create_with_backend(backend) {
            Ok(db) => Ok(Self::new_from_redb(db)?),
            Err(redb::DatabaseError::UpgradeRequired(_)) => {
                Self::migrate_v2_to_v3(&file)?;
                let backend = WasmBackend::new(file);
                let db = Database::builder()
                    .create_with_backend(backend)
                    .map_err(|e| MemAndRedbOpenError::OpenMigrated(e.into()))?;
                Ok(Self::new_from_redb(db)?)
            }
            Err(e) => Err(MemAndRedbOpenError::Open(e.into())),
        }
    }

    fn migrate_v2_to_v3(file: &FileSystemSyncAccessHandle) -> Result<(), MemAndRedbOpenError> {
        tracing::info!("Migrating redb database from v2 to v3 file format");
        let backend = WasmBackend::new(file.clone());
        let mut db = redb2::Database::builder()
            .create_with_backend(backend)
            .map_err(|e| MemAndRedbOpenError::OpenV2(e.into()))?;
        db.upgrade()
            .map_err(|e| MemAndRedbOpenError::UpgradeV2(e.into()))?;
        tracing::info!("Successfully migrated redb database to v3 format");
        Ok(())
    }
}
