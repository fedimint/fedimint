use std::ops::ControlFlow;

use devimint::tests::log_binary_versions;
use devimint::util::poll;
use devimint::version_constants::VERSION_0_7_0_ALPHA;
use devimint::{DevFed, cmd};
use lightning_invoice::Bolt11Invoice;
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

            let fedimint_cli_version = devimint::util::FedimintCli::version_or_default().await;

            if fedimint_cli_version < *VERSION_0_7_0_ALPHA {
                info!("Skipping recurringd test because fedimint-cli is lower than v0.7.0");
                return Ok(());
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

            let invoice = cmd!("lnurlp", "--amount", "1000sat", lnurl)
                .out_string()
                .await?
                .parse::<Bolt11Invoice>()
                .unwrap();

            gw_ldk_second.pay_invoice(invoice.clone()).await?;

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
                &invoice.to_string()
            );

            let client_balance = client.balance().await?;
            assert_eq!(client_balance, 1_000_000);
            info!("Client balance: {client_balance}");

            Ok(())
        })
        .await
}
