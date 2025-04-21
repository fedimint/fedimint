use fedimint_core::fedimint_build_code_version_env;
use fedimintd::Fedimintd;
#[cfg(not(any(target_env = "msvc", target_os = "ios")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "ios")))]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new(fedimint_build_code_version_env!(), None)?
        .with_default_modules()?
        .run()
        .await
}
