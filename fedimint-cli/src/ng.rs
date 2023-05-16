use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail};
use bitcoin::secp256k1;
use bitcoin_hashes::hex;
use bitcoin_hashes::hex::ToHex;
use clap::Subcommand;
use fedimint_client::backup::Metadata;
use fedimint_client::secret::PlainRootSecretStrategy;
use fedimint_client::sm::OperationId;
use fedimint_client::Client;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::time::now;
use fedimint_core::{Amount, ParseAmountError, TieredMulti, TieredSummary};
use fedimint_ln_client::contracts::ContractId;
use fedimint_ln_client::{
    InternalPayState, LightningClientExt, LnPayState, LnReceiveState, PayType,
};
use fedimint_mint_client::{MintClientExt, MintClientModule, SpendableNote};
use fedimint_wallet_client::{WalletClientExt, WithdrawState};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::{metadata_from_clap_cli, LnInvoiceResponse};

#[derive(Debug, Clone)]
pub enum ModuleSelector {
    Id(ModuleInstanceId),
    Kind(ModuleKind),
}

impl FromStr for ModuleSelector {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s.chars().all(|ch| ch.is_ascii_digit()) {
            Self::Id(s.parse()?)
        } else {
            Self::Kind(ModuleKind::clone_from_str(s))
        })
    }
}

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
    WaitInvoice {
        operation_id: OperationId,
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
    DepositAddress,
    AwaitDeposit {
        operation_id: OperationId,
    },
    Withdraw {
        #[clap(long)]
        amount: bitcoin::Amount,
        #[clap(long)]
        address: bitcoin::Address,
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
    _config: ClientConfig,
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
                .subscribe_reissue_external_notes(operation_id)
                .await
                .unwrap()
                .into_stream();

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
                .spend_notes(amount, Duration::from_secs(3600), ())
                .await?;
            info!("Spend e-cash operation: {operation}");

            Ok(json!({
                "notes": serialize_ecash(&notes),
            }))
        }
        ClientNg::LnInvoice {
            amount,
            description,
            expiry_time,
        } => {
            client.select_active_gateway().await?;

            let (operation_id, invoice) = client
                .create_bolt11_invoice(amount, description, expiry_time)
                .await?;
            Ok(serde_json::to_value(LnInvoiceResponse {
                operation_id,
                invoice: invoice.to_string(),
            })
            .unwrap())
        }
        ClientNg::WaitInvoice { operation_id } => {
            let mut updates = client
                .subscribe_ln_receive(operation_id)
                .await?
                .into_stream();
            while let Some(update) = updates.next().await {
                match update {
                    LnReceiveState::Claimed => {
                        return get_note_summary(&client).await;
                    }
                    LnReceiveState::Canceled { reason } => {
                        return Err(reason.into());
                    }
                    _ => {}
                }

                info!("Update: {:?}", update);
            }

            return Err(anyhow::anyhow!("Lightning receive failed"));
        }
        ClientNg::LnPay { bolt11 } => {
            client.select_active_gateway().await?;

            let (pay_type, contract_id) = client.pay_bolt11_invoice(bolt11).await?;

            match pay_type {
                PayType::Internal(operation_id) => {
                    let mut updates = client
                        .subscribe_internal_pay(operation_id)
                        .await?
                        .into_stream();

                    while let Some(update) = updates.next().await {
                        match update {
                            InternalPayState::Preimage(preimage) => {
                                return Ok(serde_json::to_value(PayInvoiceResponse {
                                    operation_id,
                                    contract_id,
                                    preimage: preimage.to_public_key()?.to_string(),
                                })
                                .unwrap());
                            }
                            InternalPayState::RefundSuccess(outpoint) => {
                                let e = format!(
                                    "Internal payment failed. A refund was issued to {outpoint}"
                                );
                                return Err(anyhow!(e));
                            }
                            InternalPayState::Error(e) => {
                                return Err(anyhow!(e));
                            }
                            _ => {}
                        }

                        info!("Update: {:?}", update);
                    }
                }
                PayType::Lightning(operation_id) => {
                    let mut updates = client.subscribe_ln_pay(operation_id).await?.into_stream();

                    while let Some(update) = updates.next().await {
                        match update {
                            LnPayState::Success { preimage } => {
                                return Ok(serde_json::to_value(PayInvoiceResponse {
                                    operation_id,
                                    contract_id,
                                    preimage,
                                })
                                .unwrap());
                            }
                            LnPayState::Refunded { gateway_error } => {
                                info!("{gateway_error}");
                                return get_note_summary(&client).await;
                            }
                            _ => {}
                        }

                        info!("Update: {:?}", update);
                    }
                }
            };

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
        ClientNg::DepositAddress => {
            let (operation_id, address) = client
                .get_deposit_address(now() + Duration::from_secs(600))
                .await?;
            Ok(serde_json::json! {
                {
                    "address": address,
                    "operation_id": operation_id,
                }
            })
        }
        ClientNg::AwaitDeposit { operation_id } => {
            let mut updates = client
                .subscribe_deposit_updates(operation_id)
                .await?
                .into_stream();

            while let Some(update) = updates.next().await {
                info!("Update: {update:?}");
            }

            Ok(serde_json::to_value(()).unwrap())
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
            let secret = client.get_secret::<PlainRootSecretStrategy>().await;
            let hex_secret = hex::ToHex::to_hex(&secret[..]);

            Ok(json!({
                "secret": hex_secret,
            }))
        }
        ClientNg::Withdraw { amount, address } => {
            let fees = client.get_withdraw_fee(address.clone(), amount).await?;
            let absolute_fees = fees.amount();

            info!("Attempting withdraw with fees: {fees:?}");

            let operation_id = client.withdraw(address, amount, fees).await?;

            let mut updates = client
                .subscribe_withdraw_updates(operation_id)
                .await?
                .into_stream();

            while let Some(update) = updates.next().await {
                info!("Update: {update:?}");

                match update {
                    WithdrawState::Succeeded(txid) => {
                        return Ok(json!({
                            "txid": txid.to_hex(),
                            "fees_sat": absolute_fees.to_sat(),
                        }));
                    }
                    WithdrawState::Failed(e) => {
                        return Err(anyhow!("Withdraw failed: {e}"));
                    }
                    _ => {}
                }
            }

            unreachable!("Update stream ended without outcome");
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
    contract_id: ContractId,
    preimage: String,
}

pub fn serialize_ecash(c: &TieredMulti<SpendableNote>) -> String {
    let mut bytes = Vec::new();
    Encodable::consensus_encode(c, &mut bytes).expect("encodes correctly");
    base64::encode(&bytes)
}
