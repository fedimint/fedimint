#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|_fed, _process_mgr| async move { Ok(()) }).await
}
