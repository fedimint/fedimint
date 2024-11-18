use fedimint_cli::FedimintCli;
use fedimint_core::fedimint_build_code_version_env;
#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new(fedimint_build_code_version_env!())?
        .with_default_modules()
        .run()
        .await;
    Ok(())
}
