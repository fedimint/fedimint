use std::str::FromStr;
use std::time::Duration;

use anyhow::bail;
use bitcoin::secp256k1;
use bitcoin_hashes::hex;
use clap::Subcommand;
use fedimint_client::backup::Metadata;
use fedimint_client::sm::OperationId;
use fedimint_client::Client;
use fedimint_core::config::ClientConfig;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, OutPoint, ParseAmountError, TieredMulti, TieredSummary};
use fedimint_ln_client::{LightningClientExt, LnPayState, LnReceiveState};
use fedimint_mint_client::{MintClientExt, MintClientModule, SpendableNote};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::metadata_from_clap_cli;

#[derive(Debug, Clone, Subcommand)]
pub enum ClientNg {
    Info,
    Reissue {
        #[clap(value_parser = parse_ecash)]
        notes: TieredMulti<SpendableNote>,
    },
    Spend {
        amount: Amount,
    },
    LnInvoice {
        #[clap(long, value_parser = parse_fedimint_amount)]
        amount: Amount,
        #[clap(long, default_value = "")]
        description: String,
        #[clap(long)]
        expiry_time: Option<u64>,
    },
    LnPay {
        bolt11: lightning_invoice::Invoice,
    },
    ListGateways,
    SwitchGateway {
        /// node public key for a gateway
        #[clap(value_parser = parse_node_pub_key)]
        pubkey: secp256k1::PublicKey,
    },
    /// Upload the (encrypted) snapshot of mint notes to federation
    Backup {
        #[clap(long = "metadata")]
        /// Backup metadata, encoded as `key=value` (use `--metadata=key=value`,
        /// possibly multiple times)
        // TODO: Can we make it `*Map<String, String>` and avoid custom parsing?
        metadata: Vec<String>,
    },
    /// Wipe the state of the client (mostly for testing purposes)
    #[clap(hide = true)]
    Wipe {
        #[clap(long)]
        force: bool,
    },
    /// Restore the previously created backup of mint notes (with `backup`
    /// command)
    Restore {
        #[clap(value_parser = parse_secret)]
        secret: [u8; 64],
    },
    /// Print the secret key of the client
    PrintSecret,
}

pub fn parse_node_pub_key(s: &str) -> Result<secp256k1::PublicKey, secp256k1::Error> {
    secp256k1::PublicKey::from_str(s)
}

fn parse_secret(s: &str) -> Result<[u8; 64], hex::Error> {
    hex::FromHex::from_hex(s)
}

pub async fn handle_ng_command(
    command: ClientNg,
    config: ClientConfig,
    client: Client,
) -> anyhow::Result<serde_json::Value> {
    match command {
        ClientNg::Info => {
            return get_note_summary(&client).await;
        }
        ClientNg::Reissue { notes } => {
            let amount = notes.total_amount();

            let operation_id = client.reissue_external_notes(notes, ()).await?;
            let mut updates = client
                .subscribe_reissue_external_notes_updates(operation_id)
                .await
                .unwrap();

            while let Some(update) = updates.next().await {
                if let fedimint_mint_client::ReissueExternalNotesState::Failed(e) = update {
                    return Err(anyhow::Error::msg(format!("Reissue failed: {e}")));
                }

                info!("Update: {:?}", update);
            }

            Ok(serde_json::to_value(amount).unwrap())
        }
        ClientNg::Spend { amount } => {
            let (operation, notes) = client
                .spend_notes(amount, Duration::from_secs(30), ())
                .await?;
            info!("Spend e-cash operation: {operation:?}");

            Ok(serde_json::to_value(notes).unwrap())
        }
        ClientNg::LnInvoice {
            amount,
            description,
            expiry_time,
        } => {
            client.select_active_gateway().await?;

            let (operation_id, _) = client
                .create_bolt11_invoice_and_receive(amount, description, expiry_time)
                .await?;
            let mut updates = client.subscribe_to_ln_receive_updates(operation_id).await?;
            while let Some(update) = updates.next().await {
                match update {
                    LnReceiveState::Claimed { txid } => {
                        client.await_claim_notes(operation_id, txid).await?;
                        return get_note_summary(&client).await;
                    }
                    LnReceiveState::Canceled { reason } => {
                        return Err(reason.into());
                    }
                    _ => {}
                }

                info!("Update: {:?}", update);
            }

            return Err(anyhow::anyhow!("Unknown Lightning receive state"));
        }
        ClientNg::LnPay { bolt11 } => {
            client.select_active_gateway().await?;

            let (operation_id, txid) = client
                .pay_bolt11_invoice(config.federation_id, bolt11)
                .await?;

            let mut updates = client.subscribe_ln_pay_updates(operation_id).await?;

            while let Some(update) = updates.next().await {
                match update {
                    LnPayState::Success { preimage } => {
                        client
                            .await_mint_change(operation_id, OutPoint { txid, out_idx: 1 })
                            .await?;
                        return Ok(serde_json::to_value(PayInvoiceResponse {
                            operation_id,
                            preimage,
                        })
                        .unwrap());
                    }
                    LnPayState::Refunded { refund_txid } => {
                        client.await_claim_notes(operation_id, refund_txid).await?;
                    }
                    _ => {}
                }

                info!("Update: {:?}", update);
            }

            return Err(anyhow::anyhow!("Lightning Payment failed"));
        }
        ClientNg::ListGateways => {
            let gateways = client.fetch_registered_gateways().await?;
            if gateways.is_empty() {
                return Ok(serde_json::to_value(Vec::<String>::new()).unwrap());
            }

            let mut gateways_json = json!(&gateways);
            let active_gateway = client.select_active_gateway().await?;

            gateways_json
                .as_array_mut()
                .expect("gateways_json is not an array")
                .iter_mut()
                .for_each(|gateway| {
                    if gateway["node_pub_key"] == json!(active_gateway.node_pub_key) {
                        gateway["active"] = json!(true);
                    } else {
                        gateway["active"] = json!(false);
                    }
                });
            Ok(serde_json::to_value(gateways_json).unwrap())
        }
        ClientNg::SwitchGateway { pubkey } => {
            client.set_active_gateway(&pubkey).await?;
            let gateway = client.select_active_gateway().await?;
            let mut gateway_json = json!(&gateway);
            gateway_json["active"] = json!(true);
            Ok(serde_json::to_value(gateway_json).unwrap())
        }

        ClientNg::Backup { metadata } => {
            let metadata = metadata_from_clap_cli(metadata)?;

            client
                .backup_to_federation(Metadata::from_json_serialized(metadata))
                .await?;
            Ok(serde_json::to_value(()).unwrap())
        }
        ClientNg::Restore { .. } => {
            panic!("Has to be handled before initializing client")
        }
        ClientNg::Wipe { force } => {
            if !force {
                bail!("This will wipe the state of the client irrecoverably. Use `--force` to proceed.")
            }
            client.wipe_state().await?;
            Ok(serde_json::to_value(()).unwrap())
        }
        ClientNg::PrintSecret => {
            let secret = client.get_secret().await;
            let hex_secret = hex::ToHex::to_hex(secret.0.as_ref());

            Ok(json!({
                "secret": hex_secret,
            }))
        }
    }
}

async fn get_note_summary(client: &Client) -> anyhow::Result<serde_json::Value> {
    let (mint_client, _) = client.get_first_module::<MintClientModule>(&fedimint_mint_client::KIND);
    let summary = mint_client
        .get_wallet_summary(&mut client.db().begin_transaction().await.with_module_prefix(1))
        .await;
    Ok(serde_json::to_value(InfoResponse {
        total_msat: summary.total_amount(),
        denominations_msat: summary,
    })
    .unwrap())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InfoResponse {
    total_msat: Amount,
    denominations_msat: TieredSummary,
}

pub fn parse_fedimint_amount(s: &str) -> Result<fedimint_core::Amount, ParseAmountError> {
    if let Some(i) = s.find(char::is_alphabetic) {
        let (amt, denom) = s.split_at(i);
        fedimint_core::Amount::from_str_in(amt, denom.parse()?)
    } else {
        //default to millisatoshi
        fedimint_core::Amount::from_str_in(s, bitcoin::Denomination::MilliSatoshi)
    }
}

pub fn parse_ecash(s: &str) -> anyhow::Result<TieredMulti<SpendableNote>> {
    let bytes = base64::decode(s)?;
    Ok(Decodable::consensus_decode(
        &mut std::io::Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PayInvoiceResponse {
    operation_id: OperationId,
    preimage: String,
}
