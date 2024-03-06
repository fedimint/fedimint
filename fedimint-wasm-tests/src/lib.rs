use anyhow::Result;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::Client;
use fedimint_core::api::InviteCode;
use fedimint_core::config::ClientConfig;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_ln_client::LightningClientInit;
use fedimint_mint_client::MintClientInit;
use fedimint_wallet_client::WalletClientInit;
use rand::thread_rng;

async fn load_or_generate_mnemonic(db: &Database) -> anyhow::Result<[u8; 64]> {
    Ok(match Client::load_decodable_client_secret(db).await {
        Ok(s) => s,

        Err(_) => {
            let secret = PlainRootSecretStrategy::random(&mut thread_rng());
            Client::store_encodable_client_secret(db, secret).await?;
            secret
        }
    })
}

fn make_client_builder() -> fedimint_client::ClientBuilder {
    let mem_database = MemDatabase::default();
    let mut builder = fedimint_client::Client::builder(mem_database.into());
    builder.with_module(LightningClientInit);
    builder.with_module(MintClientInit);
    builder.with_module(WalletClientInit::default());
    builder.with_primary_module(1);

    builder
}

async fn client(invite_code: &InviteCode) -> Result<fedimint_client::ClientHandle> {
    let client_config = ClientConfig::download_from_invite_code(invite_code).await?;
    let mut builder = make_client_builder();
    let client_secret = load_or_generate_mnemonic(builder.db()).await?;
    builder.stopped();
    builder
        .join(
            PlainRootSecretStrategy::to_root_secret(&client_secret),
            client_config.to_owned(),
            invite_code.clone(),
        )
        .await
}

mod faucet {
    pub async fn invite_code() -> anyhow::Result<String> {
        let resp = gloo_net::http::Request::get("http://localhost:15243/connect-string")
            .send()
            .await?;
        if resp.ok() {
            Ok(resp.text().await?)
        } else {
            anyhow::bail!(resp.text().await?);
        }
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
        if resp.ok() {
            Ok(resp.text().await?)
        } else {
            anyhow::bail!(resp.text().await?);
        }
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
    use std::time::Duration;

    use anyhow::{anyhow, bail};
    use fedimint_client::derivable_secret::DerivableSecret;
    use fedimint_core::Amount;
    use fedimint_ln_client::{
        LightningClientModule, LnPayState, LnReceiveState, OutgoingLightningPayment, PayType,
    };
    use fedimint_mint_client::{MintClientModule, ReissueExternalNotesState, SpendOOBState};
    use futures::StreamExt;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    async fn build_client() -> Result<()> {
        let _client = client(&faucet::invite_code().await?.parse()?).await?;
        Ok(())
    }

    async fn set_gateway(client: &fedimint_client::ClientHandle) -> anyhow::Result<()> {
        let lightning_module = client.get_first_module::<LightningClientModule>();
        let gws = lightning_module.fetch_registered_gateways().await?;
        let gw_api = faucet::gateway_api().await?;
        let lnd_gw = gws
            .into_iter()
            .find(|x| x.info.api.to_string() == gw_api)
            .expect("no gateway with api");

        lightning_module
            .set_active_gateway(&lnd_gw.info.gateway_id)
            .await?;
        Ok(())
    }

    #[wasm_bindgen_test]
    async fn receive() -> Result<()> {
        let client = client(&faucet::invite_code().await?.parse()?).await?;
        client.start_executor().await;
        set_gateway(&client).await?;
        futures::future::try_join_all(
            (0..10).map(|_| receive_once(client.clone(), Amount::from_sats(21))),
        )
        .await?;
        Ok(())
    }

    async fn receive_once(client: fedimint_client::ClientHandle, amount: Amount) -> Result<()> {
        let lightning_module = client.get_first_module::<LightningClientModule>();
        let (opid, invoice, _) = lightning_module
            .create_bolt11_invoice(amount, "test".to_string(), None, ())
            .await?;
        faucet::pay_invoice(&invoice.to_string()).await?;

        let mut updates = lightning_module
            .subscribe_ln_receive(opid)
            .await?
            .into_stream();
        while let Some(update) = updates.next().await {
            match update {
                LnReceiveState::Claimed => return Ok(()),
                LnReceiveState::Canceled { reason } => {
                    return Err(reason.into());
                }
                _ => {}
            }
        }
        Err(anyhow!("Lightning receive failed"))
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

    async fn pay_once(client: fedimint_client::ClientHandle) -> Result<(), anyhow::Error> {
        let lightning_module = client.get_first_module::<LightningClientModule>();
        let bolt11 = faucet::generate_invoice(11).await?;
        let gateway = lightning_module.select_active_gateway_opt().await;
        let OutgoingLightningPayment {
            payment_type,
            contract_id: _,
            fee: _,
        } = lightning_module
            .pay_bolt11_invoice(gateway, bolt11.parse()?, ())
            .await?;
        let PayType::Lightning(operation_id) = payment_type else {
            unreachable!("paying invoice over lightning");
        };
        let lightning_module = client.get_first_module::<LightningClientModule>();
        let mut updates = lightning_module
            .subscribe_ln_pay(operation_id)
            .await?
            .into_stream();
        loop {
            match updates.next().await {
                Some(LnPayState::Success { preimage: _ }) => {
                    break;
                }
                Some(LnPayState::Refunded { gateway_error }) => {
                    return Err(anyhow!("refunded {gateway_error}"));
                }
                None => return Err(anyhow!("Lightning send failed")),
                _ => {}
            }
        }
        Ok(())
    }

    #[wasm_bindgen_test]
    async fn receive_and_pay() -> Result<()> {
        let client = client(&faucet::invite_code().await?.parse()?).await?;
        client.start_executor().await;
        set_gateway(&client).await?;

        futures::future::try_join_all(
            (0..10).map(|_| receive_once(client.clone(), Amount::from_sats(21))),
        )
        .await?;
        futures::future::try_join_all((0..10).map(|_| pay_once(client.clone()))).await?;

        Ok(())
    }

    async fn send_and_recv_ecash_once(
        client: fedimint_client::ClientHandle,
    ) -> Result<(), anyhow::Error> {
        let mint = client.get_first_module::<MintClientModule>();
        let (_, notes) = mint
            .spend_notes(Amount::from_sats(11), Duration::from_secs(10000), false, ())
            .await?;
        let operation_id = mint.reissue_external_notes(notes, ()).await?;
        let mut updates = mint
            .subscribe_reissue_external_notes(operation_id)
            .await?
            .into_stream();
        loop {
            match updates.next().await {
                Some(ReissueExternalNotesState::Done) => {
                    break;
                }
                Some(ReissueExternalNotesState::Failed(error)) => {
                    return Err(anyhow!("reissue failed {error}"));
                }
                None => return Err(anyhow!("reissue failed")),
                _ => {}
            }
        }
        Ok(())
    }

    async fn send_ecash_exact(
        client: fedimint_client::ClientHandle,
        amount: Amount,
    ) -> Result<(), anyhow::Error> {
        let mint = client.get_first_module::<MintClientModule>();
        'retry: loop {
            let (operation_id, notes) = mint
                .spend_notes(amount, Duration::from_secs(10000), false, ())
                .await?;
            if notes.total_amount() == amount {
                return Ok(());
            }
            mint.try_cancel_spend_notes(operation_id).await;
            let mut updates = mint
                .subscribe_spend_notes(operation_id)
                .await?
                .into_stream();
            while let Some(update) = updates.next().await {
                if update == SpendOOBState::UserCanceledSuccess {
                    continue 'retry;
                }
            }
            bail!("failed to cancel notes");
        }
    }

    #[wasm_bindgen_test]
    async fn test_ecash() -> Result<()> {
        let client = client(&faucet::invite_code().await?.parse()?).await?;
        client.start_executor().await;
        set_gateway(&client).await?;

        futures::future::try_join_all(
            (0..10).map(|_| receive_once(client.clone(), Amount::from_sats(21))),
        )
        .await?;
        futures::future::try_join_all((0..10).map(|_| send_and_recv_ecash_once(client.clone())))
            .await?;
        Ok(())
    }

    #[wasm_bindgen_test]
    async fn test_ecash_exact() -> Result<()> {
        let client = client(&faucet::invite_code().await?.parse()?).await?;
        client.start_executor().await;
        set_gateway(&client).await?;

        receive_once(client.clone(), Amount::from_sats(100)).await?;
        futures::future::try_join_all(
            (0..3).map(|_| send_ecash_exact(client.clone(), Amount::from_sats(1))),
        )
        .await?;
        Ok(())
    }
}
