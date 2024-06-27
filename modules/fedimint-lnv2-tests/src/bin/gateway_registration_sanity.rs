use devimint::version_constants::VERSION_0_4_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::util::SafeUrl;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = util::FedimintCli::version_or_default().await;
        let fedimintd_version = util::FedimintdCmd::version_or_default().await;
        let gatewayd_version = util::Gatewayd::version_or_default().await;

        if fedimint_cli_version < *VERSION_0_4_0_ALPHA {
            info!(%fedimint_cli_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        if fedimintd_version < *VERSION_0_4_0_ALPHA {
            info!(%fedimintd_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        if gatewayd_version < *VERSION_0_4_0_ALPHA {
            info!(%gatewayd_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        let client = dev_fed
            .fed()
            .await?
            .new_joined_client("lnv2-module-client")
            .await?;

        let gateway = SafeUrl::parse("https://gateway.xyz").expect("Valid Url");

        assert_eq!(
            cmd!(
                client,
                "--our-id",
                "0",
                "--password",
                "pass",
                "module",
                "lnv2",
                "add-gateway",
                gateway.clone().to_string(),
            )
            .out_json()
            .await?,
            serde_json::to_value(true).expect("JSON serialization failed")
        );

        assert_eq!(
            cmd!(client, "module", "lnv2", "gateways", "0")
                .out_json()
                .await?,
            serde_json::to_value(vec![gateway.clone()]).expect("JSON serialization failed")
        );

        assert_eq!(
            cmd!(
                client,
                "--our-id",
                "0",
                "--password",
                "pass",
                "module",
                "lnv2",
                "remove-gateway",
                gateway.to_string(),
            )
            .out_json()
            .await?,
            serde_json::to_value(true).expect("JSON serialization failed")
        );

        assert_eq!(
            cmd!(client, "module", "lnv2", "gateways", "0",)
                .out_json()
                .await?,
            serde_json::to_value(Vec::<SafeUrl>::new()).expect("JSON serialization failed")
        );

        Ok(())
    })
    .await
}
