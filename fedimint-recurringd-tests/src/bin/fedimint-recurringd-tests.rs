use std::ops::ControlFlow;

use devimint::tests::log_binary_versions;
use devimint::util::{almost_equal, poll};
use devimint::{DevFed, cmd};
use lightning_invoice::Bolt11Invoice;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, process_mgr| async move {
            log_binary_versions().await?;

            info!("Setting up development federation...");
            let DevFed {
                fed,
                gw_lnd,
                gw_ldk_second,
                recurringd,
                ..
            } = dev_fed.to_dev_fed(&process_mgr).await?;
            info!("Development federation setup complete");

            // Test admin auth is checked
            info!("Testing admin authentication...");
            {
                let dummy_invite = "fed114znk7uk7ppugdjuytr8venqf2tkywd65cqvg3u93um64tu5cw4yr0n3fvn7qmwvm4g48cpndgnm4gqq4waen5te0xyerwt3s9cczuvf6xyurzde597s7crdvsk2vmyarjw9gwyqjdzj";
                let url = format!("{}lnv1/federations", recurringd.api_url);
                let client = reqwest::Client::new();

                info!("Testing request without authentication...");
                let response_no_auth = client
                    .put(&url)
                    .header("Content-Type", "application/json")
                    .json(&serde_json::json!({ "invite": dummy_invite }))
                    .send()
                    .await?;
                assert!(response_no_auth.status().is_client_error());
                info!("✓ Request without auth correctly rejected with status: {}", response_no_auth.status());

                info!("Testing request with wrong authentication...");
                let response_with_wrong_auth = client
                    .put(&url)
                    .header("Authorization", "Bearer wrong-token")
                    .header("Content-Type", "application/json")
                    .json(&serde_json::json!({ "invite": dummy_invite }))
                    .send()
                    .await?;
                assert!(response_with_wrong_auth.status().is_client_error());
                info!("✓ Request with wrong auth correctly rejected with status: {}", response_with_wrong_auth.status());
            }
            info!("Admin authentication tests completed successfully");

            // Give the LND Gateway a balance, it's the only GW serving LNv1 and recurringd
            // is currently LNv1-only
            info!("Funding LND Gateway with 10,000,000 msats...");
            fed.pegin_gateways(10_000_000, vec![&gw_lnd]).await?;
            info!("✓ LND Gateway funded successfully");

            info!("Creating new fedimint client...");
            let client = fed.new_joined_client("recurringd-test-client").await?;
            info!("✓ Client 'recurringd-test-client' created and joined federation");

            info!("Registering LNURL with recurringd...");
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
            info!("✓ LNURL registered: {}", lnurl);

            info!("Listing registered LNURLs...");
            let lnurl_list = cmd!(client, "module", "ln", "lnurl", "list")
                .out_json()
                .await?["codes"]
                .as_object()
                .unwrap()
                .clone();
            info!("Found {} registered LNURL(s)", lnurl_list.len());

            assert_eq!(lnurl_list.len(), 1);

            let listed_lnurl = lnurl_list["0"].clone();
            assert_eq!(listed_lnurl["lnurl"].as_str().unwrap(), &lnurl);
            assert_eq!(listed_lnurl["last_derivation_index"].as_i64().unwrap(), 0);
            info!("✓ LNURL list verification passed - derivation index: {}", listed_lnurl["last_derivation_index"].as_i64().unwrap());

            info!("Creating invoice for 1000 sats using LNURL...");
            let invoice = cmd!("lnurlp", "--amount", "1000sat", lnurl)
                .out_string()
                .await?
                .parse::<Bolt11Invoice>()
                .unwrap();
            info!("✓ Invoice created: {}", invoice.to_string());

            info!("Paying invoice with LDK gateway...");
            gw_ldk_second.pay_invoice(invoice.clone()).await?;
            info!("✓ Invoice payment initiated");

            info!("Polling for invoice recognition...");
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
            info!("✓ Invoice recognized with operation ID: {}", invoice_op_id);

            info!("Waiting for invoice payment confirmation...");
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
            info!("✓ Invoice payment confirmed");

            info!("Verifying payment details...");
            assert_eq!(
                await_invoice_result["amount_msat"].as_i64().unwrap(),
                1_000_000
            );
            assert_eq!(
                await_invoice_result["invoice"].as_str().unwrap(),
                &invoice.to_string()
            );
            info!("✓ Payment verification passed - amount: {} msats", await_invoice_result["amount_msat"].as_i64().unwrap());

            info!("Checking final client balance...");
            let client_balance = client.balance().await?;
            almost_equal(client_balance, 1_000_000, 5_000).unwrap();
            info!("✓ Client balance verified: {} msats", client_balance);

            info!("🎉 All recurringd tests completed successfully!");
            Ok(())
        })
        .await
}
