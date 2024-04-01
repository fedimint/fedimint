use fedimint_core::fedimint_build_code_version_env;
use fedimintd::Fedimintd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new(fedimint_build_code_version_env!())?
        .with_default_modules()
        .run()
        .await
}
