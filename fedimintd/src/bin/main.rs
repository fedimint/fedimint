use std::convert::Infallible;

use fedimint_core::fedimint_build_code_version_env;

#[cfg(feature = "jemalloc")]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<Infallible> {
    fedimintd::run(
        fedimintd::default_modules(),
        fedimint_build_code_version_env!(),
        None,
    )
    .await
}
