//! A library for cooperative port allocation between multiple processes.
//!
//! Fedimint tests in many places need to allocate ranges of unused ports for
//! Federations and other software under tests, without being able to `bind`
//! them beforehand.
//!
//! We used to mitigate that using a global per-process atomic counter, as
//! as simple port allocation mechanism. But this does not prevent conflicts
//! between different processes.
//!
//! Normally this would prevent us from running multiple tests at the same time,
//! which also makes it impossible to use `cargo nextest`.
//!
//! This library keeps track of allocated ports (with an expiration timeout) in
//! a shared file, protected by an advisory fs lock, and uses `bind` to make
//! sure a given port is actually free

mod data;
mod envs;
mod util;

use std::path::PathBuf;

// ports below 10k are typically used by normal software increasing change they
// would get in a way
const LOW: u16 = 10000;
// ports above 32k are typically ephmeral increasing a chance of random conflict
// after port was already tried
const HIGH: u16 = 32000;

use anyhow::bail;
use tracing::trace;

use crate::data::DataDir;
use crate::envs::FM_PORTALLOC_DATA_DIR_ENV;

const LOG_PORT_ALLOC: &str = "port-alloc";

fn data_dir() -> anyhow::Result<PathBuf> {
    if let Some(env) = std::env::var_os(FM_PORTALLOC_DATA_DIR_ENV) {
        Ok(PathBuf::from(env))
    } else if let Some(dir) = dirs::cache_dir() {
        Ok(dir.join("fm-portalloc"))
    } else {
        bail!("Could not determine port alloc data dir. Try setting FM_PORTALLOC_DATA_DIR");
    }
}

pub fn port_alloc(range_size: u16) -> anyhow::Result<u16> {
    trace!(target: LOG_PORT_ALLOC, range_size, "Looking for port");
    if range_size == 0 {
        bail!("Can't allocate range of 0 bytes");
    }

    let mut data_dir = DataDir::new(data_dir()?)?;

    data_dir.with_lock(|data_dir| {
        let mut data = data_dir.load_data()?;
        let base_port = data.get_free_port_range(range_size);
        data_dir.store_data(&data)?;
        Ok(base_port)
    })
}
