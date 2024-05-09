use fedimint_core::fedimint_build_code_version_env;
use fedimint_dbtool::FedimintDBTool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintDBTool::new(fedimint_build_code_version_env!())?
        .with_default_modules_inits()
        .run()
        .await
}
