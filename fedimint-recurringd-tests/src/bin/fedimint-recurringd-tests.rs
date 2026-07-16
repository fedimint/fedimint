use std::ops::ControlFlow;

use devimint::tests::log_binary_versions;
use devimint::util::{almost_equal, poll};
use devimint::{DevFed, cmd};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, process_mgr| async move {
            log_binary_versions().await?;

            let DevFed {
                fed,
                gw_lnd,
                gw_ldk_second,
                recurringd,
                ..
            } = dev_fed.to_dev_fed(&process_mgr).await?;

            // Test admin auth is checked
            {
                let dummy_invite = "fed114znk7uk7ppugdjuytr8venqf2tkywd65cqvg3u93um64tu5cw4yr0n3fvn7qmwvm4g48cpndgnm4gqq4waen5te0xyerwt3s9cczuvf6xyurzde597s7crdvsk2vmyarjw9gwyqjdzj";
                let url = format!("{}lnv1/federations", recurringd.api_url);
                let client = reqwest::Client::new();
                let response_no_auth = client
                    .put(&url)
                    .header("Content-Type", "application/json")
                    .json(&serde_json::json!({ "invite": dummy_invite }))
                    .send()
                    .await?;
                assert!(response_no_auth.status().is_client_error());

                let response_with_wrong_auth = client
                    .put(&url)
                    .header("Authorization", "Bearer wrong-token")
                    .header("Content-Type", "application/json")
                    .json(&serde_json::json!({ "invite": dummy_invite }))
                    .send()
                    .await?;
                assert!(response_with_wrong_auth.status().is_client_error());
            }

            // Give the LND Gateway a balance, it's the only GW serving LNv1 and recurringd
            // is currently LNv1-only
            fed.pegin_gateways(10_000_000, vec![&gw_lnd]).await?;

            let client = fed.new_joined_client("recurringd-test-client").await?;

            let lnurl = cmd!(
                client,
                "module",
                "ln",
                "lnurl",
                "register",
                recurringd.api_url()
            )
            .out_json()
            .await?["lnurl"]
                .as_str()
                .unwrap()
                .to_owned();

            let lnurl_list = cmd!(client, "module", "ln", "lnurl", "list")
                .out_json()
                .await?["codes"]
                .as_object()
                .unwrap()
                .clone();

            assert_eq!(lnurl_list.len(), 1);

            let listed_lnurl = lnurl_list["0"].clone();
            assert_eq!(listed_lnurl["lnurl"].as_str().unwrap(), &lnurl);
            assert_eq!(listed_lnurl["last_derivation_index"].as_i64().unwrap(), 0);

            let url = fedimint_lnurl::parse_lnurl(&lnurl).expect("valid lnurl");
            let pay_response = fedimint_lnurl::request(&url).await.expect("pay request");
            let invoice_response = fedimint_lnurl::get_invoice(&pay_response, 1_000_000)
                .await
                .expect("invoice request");
            gw_ldk_second.client().pay_invoice(invoice_response.pr.clone()).await?;

            let invoice_op_id = poll("lnurl_receive", || async {
                cmd!(client, "dev", "wait", "2")
                    .run()
                    .await
                    .map_err(ControlFlow::Break)?;

                let invoice_list = cmd!(client, "module", "ln", "lnurl", "invoices", "0")
                    .out_json()
                    .await
                    .map_err(ControlFlow::Break)?["invoices"]
                    .as_object()
                    .unwrap()
                    .clone();

                if invoice_list.is_empty() {
                    return Err(ControlFlow::Continue(anyhow::anyhow!(
                        "No invoice recognized yet"
                    )));
                }

                Ok(invoice_list["1"]["operation_id"]
                    .as_str()
                    .unwrap()
                    .to_owned())
            })
            .await?;

            let await_invoice_result = cmd!(
                client,
                "module",
                "ln",
                "lnurl",
                "await-invoice-paid",
                invoice_op_id
            )
            .out_json()
            .await?;

            assert_eq!(
                await_invoice_result["amount_msat"].as_i64().unwrap(),
                1_000_000
            );
            assert_eq!(
                await_invoice_result["invoice"].as_str().unwrap(),
                &invoice_response.pr.to_string()
            );

            let client_balance = client.balance().await?;
            almost_equal(client_balance, 1_000_000, 5_000).unwrap();
            info!("Client balance: {client_balance}");

            // Exercise LNv1 `module ln pay <lnurl> --all`: a single payment that
            // drains (nearly) the client's whole balance to a second client's
            // LNURL. gw_lnd both issues the invoice and settles the payment, so
            // this is a direct ecash swap within the federation.
            let drain_receiver = fed
                .new_joined_client("recurringd-test-drain-receiver")
                .await?;
            let drain_lnurl = cmd!(
                drain_receiver,
                "module",
                "ln",
                "lnurl",
                "register",
                recurringd.api_url()
            )
            .out_json()
            .await?["lnurl"]
                .as_str()
                .unwrap()
                .to_owned();

            let balance_before_drain = client.balance().await?;
            let drain_outcome = cmd!(
                client,
                "module",
                "ln",
                "pay",
                &drain_lnurl,
                "--all",
                "--gateway-id",
                &gw_lnd.gateway_id,
            )
            .out_json()
            .await?;
            // `LightningPaymentOutcome` is externally tagged; success serializes
            // as `{"Success": {..}}`.
            assert!(
                drain_outcome.get("Success").is_some(),
                "draining the balance with `--all` should succeed, got: {drain_outcome}"
            );

            let balance_after_drain = client.balance().await?;
            info!(
                "Client balance after `--all` drain: {balance_after_drain} (was {balance_before_drain})"
            );
            // A spend-all leaves only sub-denomination dust behind — in practice
            // a few hundred msats out of ~1_000_000.
            assert!(
                balance_after_drain < 20_000,
                "`pay --all` should have drained (nearly) the whole balance, but {balance_after_drain} of {balance_before_drain} msats remain"
            );

            Ok(())
        })
        .await
}
