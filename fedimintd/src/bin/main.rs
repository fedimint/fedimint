use fedimint_core::fedimint_build_code_version_env;
use fedimintd::Fedimintd;
#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new(fedimint_build_code_version_env!(), None)?
        .with_default_modules()
        .run()
        .await
}
