use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use devimint::cmd;
use devimint::util;
use devimint::version_constants::VERSION_0_5_0_ALPHA;
use fedimint_walletv2_client::FinalOperationState;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = util::FedimintCli::version_or_default().await;
        let fedimintd_version = util::FedimintdCmd::version_or_default().await;

        if fedimint_cli_version < *VERSION_0_5_0_ALPHA {
            info!(%fedimint_cli_version, "Version did not support walletv2 module, skipping");
            return Ok(());
        }

        if fedimintd_version < *VERSION_0_5_0_ALPHA {
            info!(%fedimintd_version, "Version did not support walletv2 module, skipping");
            return Ok(());
        }

        let client = dev_fed
            .fed()
            .await?
            .new_joined_client("walletv2-test-send-and-receive-client")
            .await?;

        assert_eq!(
            cmd!(client, "module", "walletv2", "address", "increment")
                .out_json()
                .await?
                .as_u64()
                .expect("JSON Value is not an integer"),
            0
        );

        assert_eq!(
            cmd!(client, "module", "walletv2", "address", "count")
                .out_json()
                .await?
                .as_u64()
                .expect("JSON Value is not an integer"),
            1
        );

        let address = serde_json::from_value::<Address<NetworkUnchecked>>(
            cmd!(client, "module", "walletv2", "address", "derive", "0")
                .out_json()
                .await?,
        )?
        .assume_checked();

        dev_fed
            .fed()
            .await?
            .send_to_address(address.to_string(), 100_000)
            .await?;

        dev_fed
            .fed()
            .await?
            .send_to_address(address.to_string(), 200_000)
            .await?;

        assert_eq!(
            cmd!(client, "module", "walletv2", "check", "esplora.xyz", "0")
                .out_json()
                .await?
                .as_array()
                .expect("JSON Value is not an array")
                .len(),
            2
        );

        assert_eq!(
            cmd!(client, "module", "walletv2", "receive", "esplora.xyz", "0")
                .out_json()
                .await?,
            serde_json::to_value(FinalOperationState::Success).expect("JSON serialization failed"),
        );

        assert_eq!(
            cmd!(client, "module", "walletv2", "check", "esplora.xyz", "0")
                .out_json()
                .await?
                .as_array()
                .expect("JSON Value is not an array")
                .len(),
            1
        );

        assert_eq!(
            cmd!(client, "module", "walletv2", "receive", "esplora.xyz", "0")
                .out_json()
                .await?,
            serde_json::to_value(FinalOperationState::Success).expect("JSON serialization failed"),
        );

        assert_eq!(
            cmd!(client, "module", "walletv2", "check", "esplora.xyz", "0")
                .out_json()
                .await?
                .as_array()
                .expect("JSON Value is not an array")
                .len(),
            0
        );

        Ok(())
    })
    .await
}
