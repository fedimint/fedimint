use anyhow::Result;
use fedimint_client::secret::PlainRootSecretStrategy;
use fedimint_core::api::InviteCode;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_ln_client::LightningClientGen;
use fedimint_mint_client::MintClientGen;
use fedimint_wallet_client::WalletClientGen;

async fn client(invite_code: &InviteCode) -> Result<fedimint_client::Client> {
    let mut builder = fedimint_client::ClientBuilder::default();
    builder.with_module(LightningClientGen);
    builder.with_module(MintClientGen);
    builder.with_module(WalletClientGen::default());
    builder.with_primary_module(1);
    builder.with_invite_code(invite_code.clone());
    builder.with_database(MemDatabase::default());
    builder.build_stopped::<PlainRootSecretStrategy>().await
}

mod faucet {
    pub async fn invite_code() -> anyhow::Result<String> {
        let resp = gloo_net::http::Request::get("http://localhost:15243/connect-string")
            .send()
            .await?;
        Ok(resp.text().await?)
    }

    pub async fn pay_invoice(invoice: &str) -> anyhow::Result<()> {
        let resp = gloo_net::http::Request::post("http://localhost:15243/pay")
            .body(invoice)
            .send()
            .await?;
        if resp.ok() {
            Ok(())
        } else {
            anyhow::bail!(resp.text().await?);
        }
    }

    pub async fn gateway_api() -> anyhow::Result<String> {
        let resp = gloo_net::http::Request::get("http://localhost:15243/gateway-api")
            .send()
            .await?;
        Ok(resp.text().await?)
    }

    pub async fn generate_invoice(amt: u64) -> anyhow::Result<String> {
        let resp = gloo_net::http::Request::post("http://localhost:15243/invoice")
            .body(amt)
            .send()
            .await?;
        if resp.ok() {
            Ok(resp.text().await?)
        } else {
            anyhow::bail!(resp.text().await?);
        }
    }
}

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
mod tests {
    use fedimint_client::derivable_secret::DerivableSecret;
    use fedimint_core::Amount;
    use fedimint_ln_client::{LightningClientExt, LnPayState, LnReceiveState, PayType};
    use futures::StreamExt;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    async fn build_client() -> Result<()> {
        let _client = client(&faucet::invite_code().await?.parse()?).await?;
        Ok(())
    }

    async fn set_gateway(client: &fedimint_client::Client) -> anyhow::Result<()> {
        let gws = client.fetch_registered_gateways().await?;
        let gw_api = faucet::gateway_api().await?;
        let lnd_gw = gws
            .into_iter()
            .find(|x| x.api.to_string() == gw_api)
            .expect("no gateway with api");

        client.set_active_gateway(&lnd_gw.gateway_id).await?;
        Ok(())
    }

    #[wasm_bindgen_test]
    async fn receive() -> Result<()> {
        let client = client(&faucet::invite_code().await?.parse()?).await?;
        client.start_executor().await;
        set_gateway(&client).await?;
        let (opid, invoice) = client
            .create_bolt11_invoice(Amount::from_sats(21), "test".to_string(), None, ())
            .await?;
        faucet::pay_invoice(&invoice.to_string()).await?;

        let mut updates = client.subscribe_ln_receive(opid).await?.into_stream();
        while let Some(update) = updates.next().await {
            match update {
                LnReceiveState::Claimed => return Ok(()),
                LnReceiveState::Canceled { reason } => {
                    return Err(reason.into());
                }
                _ => {}
            }
        }
        Err(anyhow::anyhow!("Lightning receive failed"))
    }

    // Tests that ChaCha20 crypto functions used for backup and recovery are
    // available in WASM at runtime. Related issue: https://github.com/fedimint/fedimint/issues/2843
    #[wasm_bindgen_test]
    async fn derive_chacha_key() {
        let root_secret = DerivableSecret::new_root(&[0x42; 32], &[0x2a; 32]);
        let key = root_secret.to_chacha20_poly1305_key();

        // Prevent optimization
        // FIXME: replace with `std::hint::black_box` once stabilized
        assert!(format!("key: {key:?}").len() > 8);
    }

    #[wasm_bindgen_test]
    async fn receive_and_pay() -> Result<()> {
        let client = client(&faucet::invite_code().await?.parse()?).await?;
        client.start_executor().await;
        set_gateway(&client).await?;
        let (opid, invoice) = client
            .create_bolt11_invoice(Amount::from_sats(21), "test".to_string(), None, ())
            .await?;
        faucet::pay_invoice(&invoice.to_string()).await?;

        let mut updates = client.subscribe_ln_receive(opid).await?.into_stream();

        loop {
            match updates.next().await {
                Some(LnReceiveState::Claimed) => break,
                Some(LnReceiveState::Canceled { reason }) => {
                    return Err(reason.into());
                }
                None => return Err(anyhow::anyhow!("Lightning receive failed")),
                _ => {}
            }
        }

        let bolt11 = faucet::generate_invoice(11).await?;
        let (pay_types, _contract_id) = client.pay_bolt11_invoice(bolt11.parse()?).await?;
        let PayType::Lightning(operation_id) = pay_types else {
            unreachable!("paying invoice over lightning");
        };

        let mut updates = client.subscribe_ln_pay(operation_id).await?.into_stream();

        loop {
            match updates.next().await {
                Some(LnPayState::Success { preimage: _ }) => {
                    break;
                }
                Some(LnPayState::Refunded { gateway_error }) => {
                    return Err(anyhow::anyhow!("refunded {gateway_error}"));
                }
                None => return Err(anyhow::anyhow!("Lightning send failed")),
                _ => {}
            }
        }

        Ok(())
    }
}
