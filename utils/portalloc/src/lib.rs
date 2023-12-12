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

pub mod data;
pub mod util;

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::bail;
use rand::{thread_rng, Rng};
use tracing::warn;

use crate::data::DataDir;

type UnixTimestamp = u64;

pub fn now_ts() -> UnixTimestamp {
    fedimint_core::time::duration_since_epoch().as_secs()
}

pub fn data_dir() -> anyhow::Result<PathBuf> {
    if let Some(env) = std::env::var_os("FM_PORTALLOC_DATA_DIR") {
        Ok(PathBuf::from(env))
    } else if let Some(dir) = dirs::cache_dir() {
        Ok(dir.join("fm-portalloc"))
    } else {
        bail!("Could not determine port alloc data dir. Try setting FM_PORTALLOC_DATA_DIR");
    }
}
pub fn port_alloc(range_size: u16) -> anyhow::Result<u16> {
    if range_size == 0 {
        bail!("Can't allocate range of 0 bytes");
    }

    let mut data_dir = DataDir::new(data_dir()?)?;

    // ports below 10k are typically used by normal software increasing change they
    // would get in a way
    const LOW: u16 = 10000;
    // ports above 32k are typically ephmeral increasing a chance of random conflict
    // after port was already tried
    const HIGH: u16 = 32000;

    data_dir.with_lock(|data_dir| {
        // `_listeners` are here only to prevent other processes from binding until
        // the port was allocated
        Ok('retry: loop {
            let mut data = data_dir.load_data(now_ts())?;

            let base_port: u16 = thread_rng().gen_range(LOW..HIGH - range_size);
            let range = base_port..base_port + range_size;
            if data.contains(&range) {
                warn!(
                    base_port,
                    range_size,
                    "Could not use a port (already reserved). Will try a different range."
                );
                data_dir.r#yield(Duration::from_millis(100))?;
                continue 'retry;
            }

            for port in range.clone() {
                match TcpListener::bind(("127.0.0.1", port)) {
                    Err(error) => {
                        warn!(
                            ?error,
                            port, "Could not use a port. Will try a different range"
                        );
                        data_dir.r#yield(Duration::from_millis(100))?;
                        continue 'retry;
                    }
                    Ok(l) => l,
                };
            }

            // The caller gets 120 seconds to use the port (`bind`), to prevent
            // other callers from re-using it.
            data.insert(range, now_ts() + 120);

            data_dir.store_data(&data)?;

            break base_port;
        })
    })
}
