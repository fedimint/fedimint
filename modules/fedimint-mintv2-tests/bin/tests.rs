use anyhow::ensure;
use clap::Parser;
use devimint::cmd;
use devimint::devfed::DevJitFed;
use devimint::federation::Client;
use fedimint_core::envs::{FM_ENABLE_MODULE_MINT_ENV, FM_ENABLE_MODULE_MINTV2_ENV};
use fedimint_mintv2_client::FinalReceiveOperationState;
use tracing::info;

#[derive(Parser)]
#[command(name = "mintv2-module-tests")]
#[command(about = "MintV2 module integration tests", long_about = None)]
struct Cli {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();

    // Enable MintV2 module and disable MintV1 for these tests
    unsafe { std::env::set_var(FM_ENABLE_MODULE_MINTV2_ENV, "true") };
    unsafe { std::env::set_var(FM_ENABLE_MODULE_MINT_ENV, "false") };

    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move { test_mintv2(&dev_fed).await })
        .await
}

async fn module_is_present(client: &Client, kind: &str) -> anyhow::Result<bool> {
    let modules = cmd!(client, "module").out_json().await?;

    let modules = modules["list"].as_array().expect("module list is an array");

    Ok(modules.iter().any(|m| m["kind"].as_str() == Some(kind)))
}

async fn test_mintv2(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let federation = dev_fed.fed().await?;

    let client = federation.new_joined_client("mintv2-test-client").await?;

    info!("Verify that mint is not present and mintv2 is present...");

    ensure!(
        !module_is_present(&client, "mint").await?,
        "mint module should not be present"
    );

    ensure!(
        module_is_present(&client, "mintv2").await?,
        "mintv2 module should be present"
    );

    info!("Testing peg-in...");

    federation.pegin_client(10_000, &client).await?;

    info!("Testing ecash send...");

    let ecash = cmd!(client, "module", "mintv2", "send", "1000000")
        .out_json()
        .await?
        .as_str()
        .expect("ecash should be a string")
        .to_string();

    info!("Testing ecash receive...");

    let value = cmd!(client, "module", "mintv2", "receive", ecash)
        .out_json()
        .await?;

    assert_eq!(
        FinalReceiveOperationState::Success,
        serde_json::from_value(value)?,
        "Receive operation should succeed"
    );

    info!("MintV2 module tests complete!");

    Ok(())
}
