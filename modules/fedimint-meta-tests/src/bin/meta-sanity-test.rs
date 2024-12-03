use std::future::Future;

use anyhow::{bail, Result};
use devimint::federation::Client;
use devimint::util::poll_simple;
use devimint::version_constants::{VERSION_0_4_0, VERSION_0_5_0_ALPHA};
use devimint::{cmd, util};
use fedimint_core::PeerId;
use semver::Version;
use serde_json::json;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = util::FedimintCli::version_or_default().await;
        let fedimintd_version = util::FedimintdCmd::version_or_default().await;

        // TODO(support:v0.2): remove
        if fedimint_cli_version < Version::parse("0.3.0-rc.2").unwrap() {
            info!(%fedimint_cli_version, "Version did not support meta module, skipping");
            return Ok(());
        }

        // TODO(support:v0.2): remove
        if fedimintd_version < Version::parse("0.3.0-rc.2").unwrap() {
            info!(%fedimintd_version, "Version did not support meta module, skipping");
            return Ok(());
        }

        let client = dev_fed
            .fed()
            .await?
            .new_joined_client("meta-module-client")
            .await?;

        async fn get_consensus(client: &Client) -> anyhow::Result<serde_json::Value> {
            cmd!(client, "module", "meta", "get").out_json().await
        }

        async fn get_submissions(
            client: &Client,
            peer_id: PeerId,
        ) -> anyhow::Result<serde_json::Value> {
            cmd!(
                client,
                "--our-id",
                &peer_id.to_string(),
                "--password",
                "notset",
                "module",
                "meta",
                "get-submissions"
            )
            .out_json()
            .await
        }

        async fn submit(
            client: &Client,
            peer_id: PeerId,
            value: &serde_json::Value,
        ) -> anyhow::Result<serde_json::Value> {
            info!(%peer_id, ?value, "Peer submitting value");

            cmd!(
                client,
                "--our-id",
                &peer_id.to_string(),
                "--password",
                "notset",
                "module",
                "meta",
                "submit",
                &value.to_string(),
            )
            .out_json()
            .await
        }

        pub async fn poll_value<Fut>(
            name: &str,
            f: impl Fn() -> Fut,
            expected_value: serde_json::Value,
        ) -> Result<serde_json::Value>
        where
            Fut: Future<Output = Result<serde_json::Value, anyhow::Error>>,
        {
            poll_simple(name, || async {
                let value = f().await?;
                if value == expected_value {
                    Ok(value)
                } else {
                    bail!("Incorrect value: {}, expected: {}", value, expected_value);
                }
            })
            .await
        }

        async fn get_meta_fields(client: &Client) -> anyhow::Result<serde_json::Value> {
            cmd!(client, "dev", "meta-fields",).out_json().await
        }

        // check starting conditions
        assert_eq!(get_consensus(&client).await?, serde_json::Value::Null);
        assert_eq!(
            get_submissions(&client, PeerId::from(1)).await?,
            json! {
                {}
            }
        );

        let submission_value = json! {
            { "foo": "bar" }
        };
        let minority_submission_value = json! {
            { "bar": "baz" }
        };

        // check submissions visible
        submit(&client, PeerId::from(1), &submission_value).await?;

        info!("Checking submission");
        poll_value(
            "submission visible on same peer",
            || async { get_submissions(&client, PeerId::from(1)).await },
            json! {
                {  "1": submission_value }
            },
        )
        .await?;
        poll_value(
            "submission visible on a different peer",
            || async { get_submissions(&client, PeerId::from(3)).await },
            json! {
                {  "1": submission_value }
            },
        )
        .await?;

        // form a consensus with a minority vote
        submit(&client, PeerId::from(0), &minority_submission_value).await?;
        submit(&client, PeerId::from(2), &submission_value).await?;
        assert_eq!(
            submit(&client, PeerId::from(3), &submission_value).await?,
            serde_json::Value::Bool(true)
        );

        // TODO(support:v0.3): a fix for a race condition was introduced in v0.4.0
        // see: https://github.com/fedimint/fedimint/pull/4772
        if fedimintd_version >= *VERSION_0_4_0 {
            info!(expected = %submission_value, "Checking consensus");
            if let Err(e) = poll_value(
                "consensus set",
                || async { get_consensus(&client).await },
                json! {
                    {
                        "revision": 0,
                        "value":submission_value
                    }
                },
            )
            .await
            {
                let submissions = get_submissions(&client, PeerId::from(3)).await?;
                warn!(%submissions, "Getting expected consensus value failed");
                return Err(e);
            }

            // minority vote should be still visible
            poll_value(
                "minor submission visible",
                || async { get_submissions(&client, PeerId::from(0)).await },
                json! {
                    {  "0": minority_submission_value}
                },
            )
            .await?;

            // If the peer with outstanding vote votes for the consensu value,
            // their submission will clear.
            submit(&client, PeerId::from(0), &submission_value).await?;
            poll_value(
                "submission cleared",
                || async { get_submissions(&client, PeerId::from(1)).await },
                json! { {} },
            )
            .await?;

            // TODO(support:v0.4): meta fields were introduced in v0.5.0
            // see: https://github.com/fedimint/fedimint/pull/5781
            if fedimint_cli_version >= *VERSION_0_5_0_ALPHA {
                let meta_fields = get_meta_fields(&client).await?;
                assert_eq!(
                    meta_fields,
                    json! {
                        {
                            "revision": 0,
                            "values": submission_value,
                        }
                    }
                );
            }
        }

        Ok(())
    })
    .await
}
