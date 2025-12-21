use std::io;

use anyhow::{Context as _, Result};
use redb::{Database, StorageBackend};
use web_sys::wasm_bindgen::JsValue;
use web_sys::{FileSystemReadWriteOptions, FileSystemSyncAccessHandle};

use crate::MemAndRedb;

#[derive(Debug)]
struct WasmBackend {
    sync_handle: FileSystemSyncAccessHandle,
}

fn js_error_to_anyhow(unknown_error: impl Into<JsValue>) -> anyhow::Error {
    match gloo_utils::errors::JsError::try_from(unknown_error.into()) {
        Ok(error) => error.into(),
        Err(error) => anyhow::format_err!(error.to_string()),
    }
}

fn js_error_to_io_error(err: impl Into<JsValue>) -> std::io::Error {
    std::io::Error::other(js_error_to_anyhow(err))
}

impl WasmBackend {
    fn new(sync_handle: FileSystemSyncAccessHandle) -> Self {
        Self { sync_handle }
    }
}

impl StorageBackend for WasmBackend {
    fn len(&self) -> io::Result<u64> {
        let size = self.sync_handle.get_size().map_err(js_error_to_io_error)?;
        Ok(size as u64)
    }

    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];
        let mut bytes_read = 0;
        let options = FileSystemReadWriteOptions::new();
        // redb wants exact reads
        while bytes_read != len {
            assert!(bytes_read < len);
            options.set_at((offset + bytes_read as u64) as f64);

            bytes_read += self
                .sync_handle
                .read_with_u8_array_and_options(&mut buffer[bytes_read..], &options)
                .map_err(js_error_to_io_error)? as usize;
        }
        Ok(buffer)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.sync_handle
            .truncate_with_f64(len as f64)
            .map_err(js_error_to_io_error)?;
        Ok(())
    }

    fn sync_data(&self, _eventual: bool) -> io::Result<()> {
        self.sync_handle.flush().map_err(js_error_to_io_error)?;
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let options = FileSystemReadWriteOptions::new();
        options.set_at(offset as f64);
        let mut bytes_written = 0;
        // redb wants exact writes
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
}

// SAFETY: we don't use threads in wasm, this will fail very loudly at runtime
// if this get sent across threads
unsafe impl Send for WasmBackend {}
unsafe impl Sync for WasmBackend {}

impl MemAndRedb {
    pub fn new(file: FileSystemSyncAccessHandle) -> Result<Self> {
        let backend = WasmBackend::new(file);
        let db = Database::builder()
            .create_with_backend(backend)
            .context("Failed to create/open redb database")?;
        Ok(Self::new_from_redb(db)?)
    }
}
