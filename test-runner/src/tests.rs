use std::env;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use devimint::cmd;
use devimint::util::is_backwards_compatibility_test;

use crate::test_wrapper::run_test;
use crate::util::set_env;
use crate::versions::{Version, set_binary_version_base_executable};

#[derive(Parser, Debug)]
pub struct RunOneArgs {
    /// Test to run
    #[arg(value_enum)]
    pub test: TestId,

    /// Federation version
    #[arg(long, default_value = "current")]
    pub fed_version: Version,

    /// Client version
    #[arg(long, default_value = "current")]
    pub client_version: Version,

    /// Gateway version
    #[arg(long, default_value = "current")]
    pub gateway_version: Version,

    /// Enable LNv2 module
    #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
    pub enable_lnv2: bool,
}

/// Run the test when running as the child.
pub async fn run_one_test(args: RunOneArgs) -> Result<()> {
    setup_test_env(&args)?;

    let test_name = args.test.to_possible_value().expect("test has value");
    let test_name = test_name.get_name();
    let version_str = format_version_str(&args);

    run_test(test_name, &version_str, async move || args.test.run().await).await
}

fn format_version_str(args: &RunOneArgs) -> String {
    let is_backwards_compat = args.fed_version != Version::Current
        || args.client_version != Version::Current
        || args.gateway_version != Version::Current;

    if is_backwards_compat {
        format!(
            "FM: {}, CLI: {}, GW: {} LNv2: {}",
            args.fed_version, args.client_version, args.gateway_version, args.enable_lnv2,
        )
    } else {
        format!("LNv2: {}", args.enable_lnv2)
    }
}

// Setup test specific env
fn setup_test_env(args: &RunOneArgs) -> anyhow::Result<()> {
    let is_backwards_compat = args.fed_version != Version::Current
        || args.client_version != Version::Current
        || args.gateway_version != Version::Current;

    if is_backwards_compat {
        set_env("FM_BACKWARDS_COMPATIBILITY_TEST", "1");
        set_env("FM_OFFLINE_NODES", "0");
        set_env("FM_USE_UNKNOWN_MODULE", "0");
        set_env("FM_ENABLE_IROH", "false");
    } else {
        set_env("FM_OFFLINE_NODES", "1");
        set_env("FM_DISCOVER_API_VERSION_TIMEOUT", "5");
    }

    set_env(
        "FM_ENABLE_MODULE_LNV2",
        if args.enable_lnv2 { "1" } else { "0" },
    );

    set_binary_version_base_executable("fedimintd", &args.fed_version);
    set_binary_version_base_executable("gatewayd", &args.gateway_version);
    set_binary_version_base_executable("gateway-cli", &args.gateway_version);
    set_binary_version_base_executable("fedimint-cli", &args.client_version);
    Ok(())
}

/// Define a list of tests for a clap argument
macro_rules! define_tests {
    ($($name:ident),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
        #[clap(rename_all = "snake_case")]
        #[allow(non_camel_case_types)]
        pub enum TestId {
            $($name),*
        }

        impl TestId {
            pub fn all() -> &'static [TestId] {
                &[$(TestId::$name),*]
            }

            pub async fn run(&self) -> anyhow::Result<()> {
                match self {
                    $(TestId::$name => Box::pin($name()).await),*
                }
            }
        }
    };
}

define_tests! {
    always_success_test,
    rust_unit_tests,
    bckn_bitcoind_dummy,
    bckn_bitcoind_mint,
    bckn_bitcoind_wallet,
    bckn_bitcoind_ln,
    bckn_bitcoind_lnv2,
    bckn_gw_client,
    bckn_gw_not_client,
    bckn_esplora,
    latency_reissue,
    latency_ln_send,
    latency_ln_receive,
    latency_fm_pay,
    latency_restore,
    reconnect_test,
    ln_reconnect_test,
    gw_reboot_test,
    gw_config_test_lnd,
    gw_restore_test,
    gw_liquidity_test,
    gw_esplora_test,
    lnv2_module_gateway_registration,
    lnv2_module_payments,
    lnv2_module_lnurl_pay,
    lnv1_lnv2_swap,
    mint_client_sanity,
    mint_client_restore,
    guardian_backup,
    cannot_replay_tx,
    test_offline_client_initialization,
    test_client_config_change_detection,
    test_guardian_password_change,
    circular_deposit,
    wallet_recovery,
    wallet_recovery_2,
    devimint_cli_test,
    devimint_cli_test_single,
    load_test_tool_test,
    recoverytool_tests,
    meta_module,
    recurringd_test,
    large_setup_test,
}

// eventually scripts will removed and all logic will be inlined into the
// functions

async fn always_success_test() -> Result<()> {
    cmd!("./scripts/tests/always-success-test.sh").run().await
}

async fn rust_unit_tests() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    let cargo_profile = env::var("CARGO_PROFILE").unwrap_or_default();
    let mut test_cmd = cmd!("cargo", "nextest", "run", "--workspace", "--all-targets");
    if !cargo_profile.is_empty() {
        test_cmd = test_cmd
            .arg(&"--cargo-profile")
            .arg(&cargo_profile)
            .arg(&"--profile")
            .arg(&cargo_profile);
    }
    test_cmd.run().await
}

async fn bckn_bitcoind_dummy() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    cmd!("./scripts/tests/backend-test.sh")
        .env("FM_TEST_ONLY", "bitcoind")
        .env("FM_BITCOIND_TEST_ONLY", "dummy")
        .run()
        .await
}

async fn bckn_bitcoind_mint() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    cmd!("./scripts/tests/backend-test.sh")
        .env("FM_TEST_ONLY", "bitcoind")
        .env("FM_BITCOIND_TEST_ONLY", "mint")
        .run()
        .await
}

async fn bckn_bitcoind_wallet() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    cmd!("./scripts/tests/backend-test.sh")
        .env("FM_TEST_ONLY", "bitcoind")
        .env("FM_BITCOIND_TEST_ONLY", "wallet")
        .run()
        .await
}

async fn bckn_bitcoind_ln() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    cmd!("./scripts/tests/backend-test.sh")
        .env("FM_TEST_ONLY", "bitcoind")
        .env("FM_BITCOIND_TEST_ONLY", "ln")
        .run()
        .await
}

async fn bckn_bitcoind_lnv2() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    cmd!("./scripts/tests/backend-test.sh")
        .env("FM_TEST_ONLY", "bitcoind")
        .env("FM_BITCOIND_TEST_ONLY", "lnv2")
        .run()
        .await
}

async fn bckn_gw_client() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    cmd!("./scripts/tests/backend-test.sh")
        .env("FM_TEST_ONLY", "bitcoind-ln-gateway")
        .env("FM_BITCOIND_GW_TEST_ONLY", "gateway-client")
        .run()
        .await
}

async fn bckn_gw_not_client() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    cmd!("./scripts/tests/backend-test.sh")
        .env("FM_TEST_ONLY", "bitcoind-ln-gateway")
        .env("FM_BITCOIND_GW_TEST_ONLY", "not-gateway-client")
        .run()
        .await
}

async fn bckn_esplora() -> Result<()> {
    if is_backwards_compatibility_test() {
        return Ok(());
    }
    cmd!("./scripts/tests/backend-test.sh")
        .env("FM_TEST_ONLY", "esplora")
        .run()
        .await
}

async fn latency_reissue() -> Result<()> {
    cmd!("./scripts/tests/latency-test.sh", "reissue")
        .run()
        .await
}

async fn latency_ln_send() -> Result<()> {
    cmd!("./scripts/tests/latency-test.sh", "ln-send")
        .run()
        .await
}

async fn latency_ln_receive() -> Result<()> {
    cmd!("./scripts/tests/latency-test.sh", "ln-receive")
        .run()
        .await
}

async fn latency_fm_pay() -> Result<()> {
    cmd!("./scripts/tests/latency-test.sh", "fm-pay")
        .run()
        .await
}

async fn latency_restore() -> Result<()> {
    cmd!("./scripts/tests/latency-test.sh", "restore")
        .run()
        .await
}

async fn reconnect_test() -> Result<()> {
    cmd!("./scripts/tests/reconnect-test.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn ln_reconnect_test() -> Result<()> {
    cmd!("./scripts/tests/lightning-reconnect-test.sh")
        .run()
        .await
}

async fn gw_reboot_test() -> Result<()> {
    cmd!("./scripts/tests/gateway-reboot-test.sh").run().await
}

async fn gw_config_test_lnd() -> Result<()> {
    cmd!(
        "./scripts/tests/gateway-module-test.sh",
        "config-test",
        "lnd"
    )
    .run()
    .await
}

async fn gw_restore_test() -> Result<()> {
    cmd!(
        "./scripts/tests/gateway-module-test.sh",
        "backup-restore-test"
    )
    .run()
    .await
}

async fn gw_liquidity_test() -> Result<()> {
    cmd!("./scripts/tests/gateway-module-test.sh", "liquidity-test")
        .run()
        .await
}

async fn gw_esplora_test() -> Result<()> {
    cmd!("./scripts/tests/gateway-module-test.sh", "esplora-test")
        .run()
        .await
}

async fn lnv2_module_gateway_registration() -> Result<()> {
    cmd!(
        "./scripts/tests/lnv2-module-test.sh",
        "gateway-registration"
    )
    .env("FM_OFFLINE_NODES", "0")
    .run()
    .await
}

async fn lnv2_module_payments() -> Result<()> {
    cmd!("./scripts/tests/lnv2-module-test.sh", "payments")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn lnv2_module_lnurl_pay() -> Result<()> {
    cmd!("./scripts/tests/lnv2-module-test.sh", "lnurl-pay")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn lnv1_lnv2_swap() -> Result<()> {
    cmd!("./scripts/tests/lnv1-lnv2-swap-test.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn mint_client_sanity() -> Result<()> {
    cmd!("./scripts/tests/mint-client-sanity.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn mint_client_restore() -> Result<()> {
    cmd!("./scripts/tests/mint-client-restore.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn guardian_backup() -> Result<()> {
    cmd!("./scripts/tests/guardian-backup.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn cannot_replay_tx() -> Result<()> {
    cmd!("./scripts/tests/cannot-replay-tx.sh").run().await
}

async fn test_offline_client_initialization() -> Result<()> {
    cmd!("./scripts/tests/test-offline-client-initialization.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn test_client_config_change_detection() -> Result<()> {
    cmd!("./scripts/tests/test-client-config-change-detection.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn test_guardian_password_change() -> Result<()> {
    cmd!("./scripts/tests/test-guardian-password-change.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn circular_deposit() -> Result<()> {
    cmd!("./scripts/tests/circular-deposit-test.sh").run().await
}

async fn wallet_recovery() -> Result<()> {
    cmd!("./scripts/tests/wallet-recovery-test.sh").run().await
}

async fn wallet_recovery_2() -> Result<()> {
    cmd!("./scripts/tests/wallet-recovery-test-2.sh")
        .run()
        .await
}

async fn devimint_cli_test() -> Result<()> {
    cmd!("./scripts/tests/devimint-cli-test.sh").run().await
}

async fn devimint_cli_test_single() -> Result<()> {
    cmd!("./scripts/tests/devimint-cli-test-single.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn load_test_tool_test() -> Result<()> {
    cmd!("./scripts/tests/load-test-tool-test.sh").run().await
}

async fn recoverytool_tests() -> Result<()> {
    cmd!("./scripts/tests/recoverytool-tests.sh").run().await
}

async fn meta_module() -> Result<()> {
    cmd!("./scripts/tests/meta-module-test.sh")
        .env("FM_OFFLINE_NODES", "0")
        .run()
        .await
}

async fn recurringd_test() -> Result<()> {
    cmd!("./scripts/tests/recurringd-test.sh").run().await
}

async fn large_setup_test() -> Result<()> {
    cmd!("./scripts/tests/large-setup-test.sh").run().await
}
