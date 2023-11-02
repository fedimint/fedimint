use fedimint_cli::FedimintCli;
use nostrmint_client::NostrmintClientGen;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new()?
        .with_default_modules()
        .with_module(NostrmintClientGen)
        .run()
        .await;
    Ok(())
}
