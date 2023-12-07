use fedimint_cli::FedimintCli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new_upstream()?
        .with_default_modules()
        .run()
        .await;
    Ok(())
}
