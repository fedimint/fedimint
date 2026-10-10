use fedimint_cli::FedimintCli;
use fedimint_core::fedimint_build_code_version_env;
#[cfg(feature = "jemalloc")]
use tikv_jemallocator::Jemalloc;
#[cfg(all(feature = "rusty-alloc", not(feature = "jemalloc")))]
use rusty_alloc_api::RustyAlloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(all(feature = "rusty-alloc", not(feature = "jemalloc")))]
#[global_allocator]
// pure rust allocator optimized for live-set performance over standard allocator
static GLOBAL: RustyAlloc = RustyAlloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new(fedimint_build_code_version_env!())?
        .with_default_modules()
        .run()
        .await;
    Ok(())
}
