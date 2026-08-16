use std::convert::Infallible;

use fedimint_core::fedimint_build_code_version_env;
#[cfg(feature = "jemalloc")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

// Without a background purge thread jemalloc only returns dirty pages to the
// OS on allocation events inside the owning arena, so per-arena high-water
// marks ratchet up with peak concurrency and are never released on quiescent
// arenas. Overridable at runtime via the `MALLOC_CONF` environment variable,
// see https://github.com/fedimint/fedimint/issues/9025.
#[cfg(feature = "jemalloc")]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] =
    b"background_thread:true,narenas:4,dirty_decay_ms:1000,muzzy_decay_ms:1000\0";

#[tokio::main]
async fn main() -> anyhow::Result<Infallible> {
    fedimintd::run(
        fedimintd::default_modules(),
        fedimint_build_code_version_env!(),
        None,
    )
    .await
}
