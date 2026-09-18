use std::convert::Infallible;

use fedimint_core::fedimint_build_code_version_env;
#[cfg(feature = "jemalloc")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[unsafe(no_mangle)]
// Jemalloc reads this well-known symbol at startup for allocator defaults.
pub static malloc_conf: &[u8] =
    b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,narenas:4\0";

#[cfg(feature = "jemalloc")]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<Infallible> {
    fedimintd::run(
        fedimintd::default_modules(),
        fedimint_build_code_version_env!(),
        None,
    )
    .await
}
