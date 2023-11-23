use std::collections::BTreeMap;
use std::ffi;
use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{bail, Context};
use bitcoin::{secp256k1, Network};
use bitcoin_hashes::hex;
use bitcoin_hashes::hex::ToHex;
use clap::Subcommand;
use fedimint_client::backup::Metadata;
use fedimint_client::ClientArc;
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::core::{ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::encoding::Encodable;
use fedimint_core::time::now;
use fedimint_core::{Amount, BitcoinAmountOrAll, ParseAmountError, TieredSummary};
use fedimint_ln_client::{
    InternalPayState, LightningClientModule, LnPayState, LnReceiveState, OutgoingLightningPayment,
    PayType,
};
use fedimint_ln_common::contracts::ContractId;
use fedimint_mint_client::{MintClientModule, OOBNotes};
use fedimint_wallet_client::{WalletClientModule, WithdrawState};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::format_description::well_known::iso8601;
use time::OffsetDateTime;
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
pub enum ClientCmd {
    /// Display wallet info (holdings, tiers)
    Info,
    /// Reissue notes received from a third party to avoid double spends
    Reissue { oob_notes: OOBNotes },
    /// Prepare notes to send to a third party as a payment
    Spend {
        #[clap(value_parser = parse_fedimint_amount)]
        amount: Amount,
    },
    /// Verifies the signatures of e-cash notes, but *not* if they have been
    /// spent already
    Validate { oob_notes: OOBNotes },
    /// Create a lightning invoice to receive payment via gateway
    LnInvoice {
        #[clap(long, value_parser = parse_fedimint_amount)]
        amount: Amount,
        #[clap(long, default_value = "")]
        description: String,
        #[clap(long)]
        expiry_time: Option<u64>,
    },
    /// Wait for incoming invoice to be paid
    AwaitInvoice { operation_id: OperationId },
    /// Pay a lightning invoice via a gateway
    LnPay {
        bolt11: lightning_invoice::Bolt11Invoice,
        /// Will return immediately after funding the payment
        #[clap(long, action)]
        finish_in_background: bool,
    },
    /// Wait for a lightning payment to complete
    AwaitLnPay { operation_id: OperationId },
    /// List registered gateways
    ListGateways,
    /// Switch active gateway
    SwitchGateway {
        #[clap(value_parser = parse_gateway_id)]
        gateway_id: secp256k1::PublicKey,
    },
    /// Generate a new deposit address, funds sent to it can later be claimed
    DepositAddress,
    /// Wait for deposit on previously generated address
    AwaitDeposit { operation_id: OperationId },
    /// Withdraw funds from the federation
    Withdraw {
        #[clap(long)]
        amount: BitcoinAmountOrAll,
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
    /// Discover the common api version to use to communicate with the
    /// federation
    #[clap(hide = true)]
    DiscoverVersion,
    /// Restore the previously created backup of mint notes (with `backup`
    /// command)
    Restore {
        #[clap(value_parser = parse_secret)]
        secret: [u8; 64],
    },
    /// Print the secret key of the client
    PrintSecret,
    ListOperations {
        #[clap(long, default_value = "10")]
        limit: usize,
    },
    /// Call a module subcommand
    Module {
        /// Module selector (either module id or module kind)
        #[clap(long)]
        module: ModuleSelector,
        args: Vec<ffi::OsString>,
    },
    /// Returns the client config
    Config,
}

pub fn parse_gateway_id(s: &str) -> Result<secp256k1::PublicKey, secp256k1::Error> {
    secp256k1::PublicKey::from_str(s)
}

fn parse_secret(s: &str) -> Result<[u8; 64], hex::Error> {
    hex::FromHex::from_hex(s)
}

pub async fn handle_command(
    command: ClientCmd,
    _config: ClientConfig,
    client: ClientArc,
) -> anyhow::Result<serde_json::Value> {
    match command {
        ClientCmd::Info => get_note_summary(&client).await,
        ClientCmd::Reissue { oob_notes } => {
            let amount = oob_notes.total_amount();

            let mint = client.get_first_module::<MintClientModule>();

            let operation_id = mint.reissue_external_notes(oob_notes, ()).await?;
            let mut updates = mint
                .subscribe_reissue_external_notes(operation_id)
                .await
                .unwrap()
                .into_stream();

            while let Some(update) = updates.next().await {
                if let fedimint_mint_client::ReissueExternalNotesState::Failed(e) = update {
                    bail!("Reissue failed: {e}");
                }

                info!("Update: {update:?}");
            }

            Ok(serde_json::to_value(amount).unwrap())
        }
        ClientCmd::Spend { amount } => {
            let (operation, notes) = client
                .get_first_module::<MintClientModule>()
                .spend_notes(amount, Duration::from_secs(3600), ())
                .await?;
            info!("Spend e-cash operation: {operation}");

            Ok(json!({
                "notes": notes,
            }))
        }
        ClientCmd::Validate { oob_notes } => {
            let amount = client
                .get_first_module::<MintClientModule>()
                .validate_notes(oob_notes)
                .await?;

            Ok(json!({
                "amount_msat": amount,
            }))
        }
        ClientCmd::LnInvoice {
            amount,
            description,
            expiry_time,
        } => {
            let lightning_module = client.get_first_module::<LightningClientModule>();
            lightning_module.select_active_gateway().await?;

            let (operation_id, invoice) = lightning_module
                .create_bolt11_invoice(amount, description, expiry_time, ())
                .await?;
            Ok(serde_json::to_value(LnInvoiceResponse {
                operation_id,
                invoice: invoice.to_string(),
            })
            .unwrap())
        }
        ClientCmd::AwaitInvoice { operation_id } => {
            let lightning_module = &client.get_first_module::<LightningClientModule>();
            let mut updates = lightning_module
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

                info!("Update: {update:?}");
            }

            Err(anyhow::anyhow!(
                "Unexpected end of update stream. Lightning receive failed"
            ))
        }
        ClientCmd::LnPay {
            bolt11,
            finish_in_background,
        } => {
            let lightning_module = client.get_first_module::<LightningClientModule>();
            lightning_module.select_active_gateway().await?;

            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee,
            } = lightning_module.pay_bolt11_invoice(bolt11).await?;
            let operation_id = payment_type.operation_id();
            info!("Gateway fee: {fee}, payment operation id: {operation_id}");
            if finish_in_background {
                wait_for_ln_payment(&client, payment_type, contract_id, true).await?;
                info!("Payment will finish in background, use await-ln-pay to get the result");
                Ok(serde_json::json! {
                    {
                        "operation_id": operation_id,
                        "payment_type": payment_type.payment_type(),
                        "contract_id": contract_id,
                        "fee": fee,
                    }
                })
            } else {
                Ok(
                    wait_for_ln_payment(&client, payment_type, contract_id, false)
                        .await?
                        .context("expected a response")?,
                )
            }
        }
        ClientCmd::AwaitLnPay { operation_id } => {
            let lightning_module = client.get_first_module::<LightningClientModule>();
            let ln_pay_details = lightning_module
                .get_ln_pay_details_for(operation_id)
                .await?;
            let payment_type = if ln_pay_details.is_internal_payment {
                PayType::Internal(operation_id)
            } else {
                PayType::Lightning(operation_id)
            };
            Ok(
                wait_for_ln_payment(&client, payment_type, ln_pay_details.contract_id, false)
                    .await?
                    .context("expected a response")?,
            )
        }
        ClientCmd::ListGateways => {
            let lightning_module = client.get_first_module::<LightningClientModule>();
            let gateways = lightning_module.fetch_registered_gateways().await?;
            if gateways.is_empty() {
                return Ok(serde_json::to_value(Vec::<String>::new()).unwrap());
            }

            let mut gateways_json = json!(&gateways);
            let active_gateway = lightning_module.select_active_gateway().await?;

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
        ClientCmd::SwitchGateway { gateway_id } => {
            let lightning_module = client.get_first_module::<LightningClientModule>();
            lightning_module.set_active_gateway(&gateway_id).await?;
            let gateway = lightning_module.select_active_gateway().await?;
            let mut gateway_json = json!(&gateway);
            gateway_json["active"] = json!(true);
            Ok(serde_json::to_value(gateway_json).unwrap())
        }
        ClientCmd::DepositAddress => {
            let (operation_id, address) = client
                .get_first_module::<WalletClientModule>()
                .get_deposit_address(now() + Duration::from_secs(600))
                .await?;
            Ok(serde_json::json! {
                {
                    "address": address,
                    "operation_id": operation_id,
                }
            })
        }
        ClientCmd::AwaitDeposit { operation_id } => {
            let mut updates = client
                .get_first_module::<WalletClientModule>()
                .subscribe_deposit_updates(operation_id)
                .await?
                .into_stream();

            while let Some(update) = updates.next().await {
                info!("Update: {update:?}");
            }

            Ok(serde_json::to_value(()).unwrap())
        }

        ClientCmd::Backup { metadata } => {
            let metadata = metadata_from_clap_cli(metadata)?;

            client
                .backup_to_federation(Metadata::from_json_serialized(metadata))
                .await?;
            Ok(serde_json::to_value(()).unwrap())
        }
        ClientCmd::Restore { .. } => {
            panic!("Has to be handled before initializing client")
        }
        ClientCmd::Wipe { force } => {
            if !force {
                bail!("This will wipe the state of the client irrecoverably. Use `--force` to proceed.")
            }
            client.wipe_state().await?;
            Ok(serde_json::to_value(()).unwrap())
        }
        ClientCmd::PrintSecret => {
            let secret = client.get_decoded_client_secret::<[u8; 64]>().await?;
            let hex_secret = hex::ToHex::to_hex(&secret[..]);

            Ok(json!({
                "secret": hex_secret,
            }))
        }
        ClientCmd::ListOperations { limit } => {
            #[derive(Serialize)]
            #[serde(rename_all = "snake_case")]
            struct OperationOutput {
                id: OperationId,
                creation_time: String,
                operation_kind: String,
                operation_meta: serde_json::Value,
                #[serde(skip_serializing_if = "Option::is_none")]
                outcome: Option<serde_json::Value>,
            }

            const ISO8601_CONFIG: iso8601::EncodedConfig = iso8601::Config::DEFAULT
                .set_formatted_components(iso8601::FormattedComponents::DateTime)
                .encode();
            let operations = client
                .operation_log()
                .list_operations(limit, None)
                .await
                .into_iter()
                .map(|(k, v)| {
                    let creation_time = OffsetDateTime::from_unix_timestamp(
                        k.creation_time
                            .duration_since(UNIX_EPOCH)
                            .expect("Couldn't convert time from SystemTime to timestamp")
                            .as_secs() as i64,
                    )
                    .expect("Couldn't convert time from SystemTime to OffsetDateTime")
                    .format(&iso8601::Iso8601::<ISO8601_CONFIG>)
                    .expect("Couldn't format OffsetDateTime as ISO8601");

                    OperationOutput {
                        id: k.operation_id,
                        creation_time,
                        operation_kind: v.operation_module_kind().to_owned(),
                        operation_meta: v.meta(),
                        outcome: v.outcome(),
                    }
                })
                .collect::<Vec<_>>();

            Ok(json!({
                "operations": operations,
            }))
        }
        ClientCmd::Withdraw { amount, address } => {
            let wallet_module = client.get_first_module::<WalletClientModule>();
            let (amount, fees) = match amount {
                // If the amount is "all", then we need to subtract the fees from
                // the amount we are withdrawing
                BitcoinAmountOrAll::All => {
                    let balance =
                        bitcoin::Amount::from_sat(client.get_balance().await.msats * 1000);
                    let fees = wallet_module
                        .get_withdraw_fees(address.clone(), balance)
                        .await?;
                    (balance - fees.amount(), fees)
                }
                BitcoinAmountOrAll::Amount(amount) => (
                    amount,
                    wallet_module
                        .get_withdraw_fees(address.clone(), amount)
                        .await?,
                ),
            };
            let absolute_fees = fees.amount();

            info!("Attempting withdraw with fees: {fees:?}");

            let operation_id = wallet_module.withdraw(address, amount, fees).await?;

            let mut updates = wallet_module
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
                        bail!("Withdraw failed: {e}");
                    }
                    _ => {}
                }
            }

            unreachable!("Update stream ended without outcome");
        }
        ClientCmd::DiscoverVersion => {
            Ok(json!({ "versions": client.discover_common_api_version().await? }))
        }
        ClientCmd::Module { module, args } => {
            let module_instance_id = match module {
                ModuleSelector::Id(id) => id,
                ModuleSelector::Kind(kind) => client
                    .get_first_instance(&kind)
                    .context("No module with this kind found")?,
            };

            client
                .get_module_client_dyn(module_instance_id)
                .context("Module not found")?
                .handle_cli_command(&args)
                .await
        }
        ClientCmd::Config => {
            let config = client.get_config_json();
            Ok(serde_json::to_value(config).expect("Client config is serializable"))
        }
    }
}

async fn wait_for_ln_payment(
    client: &ClientArc,
    payment_type: PayType,
    contract_id: ContractId,
    return_on_funding: bool,
) -> anyhow::Result<Option<serde_json::Value>> {
    let lightning_module = client.get_first_module::<LightningClientModule>();
    lightning_module.select_active_gateway().await?;

    match payment_type {
        PayType::Internal(operation_id) => {
            let mut updates = lightning_module
                .subscribe_internal_pay(operation_id)
                .await?
                .into_stream();

            while let Some(update) = updates.next().await {
                match update {
                    InternalPayState::Preimage(preimage) => {
                        return Ok(Some(
                            serde_json::to_value(PayInvoiceResponse {
                                operation_id,
                                contract_id,
                                preimage: preimage.consensus_encode_to_hex().expect("Cannot fail"),
                            })
                            .unwrap(),
                        ));
                    }
                    InternalPayState::RefundSuccess { out_points, error } => {
                        let e = format!(
                            "Internal payment failed. A refund was issued to {:?} Error: {error}",
                            out_points
                        );
                        bail!("{e}");
                    }
                    InternalPayState::UnexpectedError(e) => {
                        bail!("{e}");
                    }
                    InternalPayState::Funding if return_on_funding => return Ok(None),
                    InternalPayState::Funding => {}
                    InternalPayState::RefundError {
                        error_message,
                        error,
                    } => bail!("RefundError: {error_message} {error}"),
                    InternalPayState::FundingFailed { error } => {
                        bail!("FundingFailed: {error}")
                    }
                }
                info!("Update: {update:?}");
            }
        }
        PayType::Lightning(operation_id) => {
            let mut updates = lightning_module
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            while let Some(update) = updates.next().await {
                match update {
                    LnPayState::Success { preimage } => {
                        return Ok(Some(
                            serde_json::to_value(PayInvoiceResponse {
                                operation_id,
                                contract_id,
                                preimage,
                            })
                            .unwrap(),
                        ));
                    }
                    LnPayState::Refunded { gateway_error } => {
                        info!("{gateway_error}");
                        return Ok(Some(get_note_summary(client).await?));
                    }
                    LnPayState::Created
                    | LnPayState::Canceled
                    | LnPayState::AwaitingChange
                    | LnPayState::WaitingForRefund { .. } => {}
                    LnPayState::Funded if return_on_funding => return Ok(None),
                    LnPayState::Funded => {}
                    LnPayState::UnexpectedError { error_message } => {
                        bail!("UnexpectedError: {error_message}")
                    }
                }
                info!("Update: {update:?}");
            }
        }
    };
    bail!("Lightning Payment failed")
}

async fn get_note_summary(client: &ClientArc) -> anyhow::Result<serde_json::Value> {
    let mint_client = client.get_first_module::<MintClientModule>();
    let wallet_client = client.get_first_module::<WalletClientModule>();
    let summary = mint_client
        .get_wallet_summary(
            &mut client
                .db()
                .begin_transaction_nc()
                .await
                .to_ref_with_prefix_module_id(1),
        )
        .await;
    Ok(serde_json::to_value(InfoResponse {
        federation_id: client.federation_id(),
        network: wallet_client.get_network(),
        meta: client.get_config().global.meta.clone(),
        total_amount_msat: summary.total_amount(),
        total_num_notes: summary.count_items(),
        denominations_msat: summary,
    })
    .unwrap())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct InfoResponse {
    federation_id: FederationId,
    network: Network,
    meta: BTreeMap<String, String>,
    total_amount_msat: Amount,
    total_num_notes: usize,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PayInvoiceResponse {
    operation_id: OperationId,
    contract_id: ContractId,
    preimage: String,
}
