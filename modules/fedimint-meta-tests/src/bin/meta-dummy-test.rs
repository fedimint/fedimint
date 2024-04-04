#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_test(|process_mgr| async move {
        let dev_fed = devimint::devfed::DevJitFed::new(&process_mgr)?;

        dev_fed.finalize(&process_mgr).await?;
        let client = dev_fed.internal_client().await?;
        client.balance().await?;
        Ok(())
    })
    .await
}
