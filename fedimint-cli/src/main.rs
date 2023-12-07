use fedimint_cli::FedimintCli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new(env!("FEDIMINT_BUILD_CODE_VERSION"))?
        .with_default_modules()
        .run()
        .await;
    Ok(())
}
