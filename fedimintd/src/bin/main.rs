use std::convert::Infallible;

use fedimint_core::fedimint_build_code_version_env;
#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
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
