use std::collections::BTreeMap;
use std::ffi;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Network, secp256k1};
use clap::Subcommand;
use fedimint_bip39::Mnemonic;
use fedimint_client::backup::Metadata;
use fedimint_client::{Client, ClientHandleArc};
use fedimint_core::config::{ClientModuleConfig, FederationId};
use fedimint_core::core::{ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::encoding::Encodable;
use fedimint_core::{Amount, BitcoinAmountOrAll, TieredCounts, TieredMulti};
use fedimint_ln_client::cli::LnInvoiceResponse;
use fedimint_ln_client::{LightningClientModule, LnReceiveState, OutgoingLightningPayment};
use fedimint_logging::LOG_CLIENT;
use fedimint_mint_client::{
    MintClientModule, OOBNotes, SelectNotesWithAtleastAmount, SelectNotesWithExactAmount,
};
use fedimint_wallet_client::{WalletClientModule, WithdrawState};
use futures::StreamExt;
use itertools::Itertools;
use lightning_invoice::{Bolt11InvoiceDescription, Description};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::iso8601;
use tracing::{debug, info, warn};

use crate::metadata_from_clap_cli;

#[derive(Debug, Clone)]
pub enum ModuleSelector {
    Id(ModuleInstanceId),
    Kind(ModuleKind),
}

impl ModuleSelector {
    pub fn resolve(&self, client: &Client) -> anyhow::Result<ModuleInstanceId> {
        Ok(match self {
            ModuleSelector::Id(id) => {
                client.get_module_client_dyn(*id)?;
                *id
            }
            ModuleSelector::Kind(kind) => client
                .get_first_instance(kind)
                .context("No module with this kind found")?,
        })
    }
}
#[derive(Debug, Clone, Serialize)]
pub enum ModuleStatus {
    Active,
    UnsupportedByClient,
}

#[derive(Serialize)]
struct ModuleInfo {
    kind: ModuleKind,
    id: u16,
    status: ModuleStatus,
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
    Reissue {
        oob_notes: OOBNotes,
        #[arg(long = "no-wait", action = clap::ArgAction::SetFalse)]
        wait: bool,
    },
    /// Prepare notes to send to a third party as a payment
    Spend {
        /// The amount of e-cash to spend
        amount: Amount,
        /// If the exact amount cannot be represented, return e-cash of a higher
        /// value instead of failing
        #[clap(long)]
        allow_overpay: bool,
        /// After how many seconds we will try to reclaim the e-cash if it
        /// hasn't been redeemed by the recipient. Defaults to one week.
        #[clap(long, default_value_t = 60 * 60 * 24 * 7)]
        timeout: u64,
        /// If the necessary information to join the federation the e-cash
        /// belongs to should be included in the serialized notes
        #[clap(long)]
        include_invite: bool,
    },
    /// Splits a string containing multiple e-cash notes (e.g. from the `spend`
    /// command) into ones that contain exactly one.
    Split { oob_notes: OOBNotes },
    /// Combines two or more serialized e-cash notes strings
    Combine {
        #[clap(required = true)]
        oob_notes: Vec<OOBNotes>,
    },
    /// Create a lightning invoice to receive payment via gateway
    #[clap(hide = true)]
    LnInvoice {
        #[clap(long)]
        amount: Amount,
        #[clap(long, default_value = "")]
        description: String,
        #[clap(long)]
        expiry_time: Option<u64>,
        #[clap(long)]
        gateway_id: Option<secp256k1::PublicKey>,
        #[clap(long, default_value = "false")]
        force_internal: bool,
    },
    /// Wait for incoming invoice to be paid
    AwaitInvoice { operation_id: OperationId },
    /// Pay a lightning invoice or lnurl via a gateway
    #[clap(hide = true)]
    LnPay {
        /// Lightning invoice or lnurl
        payment_info: String,
        /// Amount to pay, used for lnurl
        #[clap(long)]
        amount: Option<Amount>,
        /// Invoice comment/description, used on lnurl
        #[clap(long)]
        lnurl_comment: Option<String>,
        #[clap(long)]
        gateway_id: Option<secp256k1::PublicKey>,
        #[clap(long, default_value = "false")]
        force_internal: bool,
    },
    /// Wait for a lightning payment to complete
    AwaitLnPay { operation_id: OperationId },
    /// List registered gateways
    ListGateways {
        /// Don't fetch the registered gateways from the federation
        #[clap(long, default_value = "false")]
        no_update: bool,
    },
    /// Generate a new deposit address, funds sent to it can later be claimed
    #[clap(hide = true)]
    DepositAddress,
    /// Wait for deposit on previously generated address
    #[clap(hide = true)]
    AwaitDeposit { operation_id: OperationId },
    /// Withdraw funds from the federation
    Withdraw {
        #[clap(long)]
        amount: BitcoinAmountOrAll,
        #[clap(long)]
        address: bitcoin::Address<NetworkUnchecked>,
    },
    /// Upload the (encrypted) snapshot of mint notes to federation
    Backup {
        #[clap(long = "metadata")]
        /// Backup metadata, encoded as `key=value` (use `--metadata=key=value`,
        /// possibly multiple times)
        // TODO: Can we make it `*Map<String, String>` and avoid custom parsing?
        metadata: Vec<String>,
    },
    /// Discover the common api version to use to communicate with the
    /// federation
    #[clap(hide = true)]
    DiscoverVersion,
    /// Join federation and restore modules that support it
    Restore {
        #[clap(long)]
        mnemonic: String,
        #[clap(long)]
        invite_code: String,
    },
    /// Print the secret key of the client
    PrintSecret,
    ListOperations {
        #[clap(long, default_value = "10")]
        limit: usize,
    },
    /// Call a module subcommand
    // Make `--help` be passed to the module handler, not root cli one
    #[command(disable_help_flag = true)]
    Module {
        /// Module selector (either module id or module kind)
        module: Option<ModuleSelector>,
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        args: Vec<ffi::OsString>,
    },
    /// Returns the client config
    Config,
    /// Gets the current fedimint AlephBFT session count
    SessionCount,
}

pub async fn handle_command(
    command: ClientCmd,
    client: ClientHandleArc,
) -> anyhow::Result<serde_json::Value> {
    match command {
        ClientCmd::Info => get_note_summary(&client).await,
        ClientCmd::Reissue { oob_notes, wait } => {
            let amount = oob_notes.total_amount();

            let mint = client.get_first_module::<MintClientModule>()?;

            let operation_id = mint.reissue_external_notes(oob_notes, ()).await?;
            if wait {
                let mut updates = mint
                    .subscribe_reissue_external_notes(operation_id)
                    .await
                    .unwrap()
                    .into_stream();

                while let Some(update) = updates.next().await {
                    if let fedimint_mint_client::ReissueExternalNotesState::Failed(e) = update {
                        bail!("Reissue failed: {e}");
                    }

                    debug!(target: LOG_CLIENT, ?update, "Reissue external notes state update");
                }
            }

            Ok(serde_json::to_value(amount).unwrap())
        }
        ClientCmd::Spend {
            amount,
            allow_overpay,
            timeout,
            include_invite,
        } => {
            warn!(
                target: LOG_CLIENT,
                "The client will try to double-spend these notes after the duration specified by the --timeout option to recover any unclaimed e-cash."
            );

            let mint_module = client.get_first_module::<MintClientModule>()?;
            let timeout = Duration::from_secs(timeout);
            let (operation, notes) = if allow_overpay {
                let (operation, notes) = mint_module
                    .spend_notes_with_selector(
                        &SelectNotesWithAtleastAmount,
                        amount,
                        timeout,
                        include_invite,
                        (),
                    )
                    .await?;

                let overspend_amount = notes.total_amount().saturating_sub(amount);
                if overspend_amount != Amount::ZERO {
                    warn!(
                        target: LOG_CLIENT,
                        "Selected notes {} worth more than requested",
                        overspend_amount
                    );
                }

                (operation, notes)
            } else {
                mint_module
                    .spend_notes_with_selector(
                        &SelectNotesWithExactAmount,
                        amount,
                        timeout,
                        include_invite,
                        (),
                    )
                    .await?
            };
            info!(target: LOG_CLIENT, "Spend e-cash operation: {}", operation.fmt_short());

            Ok(json!({
                "notes": notes,
            }))
        }
        ClientCmd::Split { oob_notes } => {
            let federation = oob_notes.federation_id_prefix();
            let notes = oob_notes
                .notes()
                .iter()
                .map(|(amount, notes)| {
                    let notes = notes
                        .iter()
                        .map(|note| {
                            OOBNotes::new(
                                federation,
                                TieredMulti::new(vec![(amount, vec![*note])].into_iter().collect()),
                            )
                        })
                        .collect::<Vec<_>>();
                    (amount, notes)
                })
                .collect::<BTreeMap<_, _>>();

            Ok(json!({
                "notes": notes,
            }))
        }
        ClientCmd::Combine { oob_notes } => {
            let federation_id_prefix = match oob_notes
                .iter()
                .map(OOBNotes::federation_id_prefix)
                .all_equal_value()
            {
                Ok(id) => id,
                Err(None) => panic!("At least one e-cash notes string expected"),
                Err(Some((a, b))) => {
                    bail!("Trying to combine e-cash from different federations: {a} and {b}");
                }
            };

            let combined_notes = oob_notes
                .iter()
                .flat_map(|notes| notes.notes().iter_items().map(|(amt, note)| (amt, *note)))
                .collect();

            let combined_oob_notes = OOBNotes::new(federation_id_prefix, combined_notes);

            Ok(json!({
                "notes": combined_oob_notes,
            }))
        }
        ClientCmd::LnInvoice {
            amount,
            description,
            expiry_time,
            gateway_id,
            force_internal,
        } => {
            warn!(
                target: LOG_CLIENT,
                "Command deprecated. Use `fedimint-cli module ln invoice` instead."
            );
            let lightning_module = client.get_first_module::<LightningClientModule>()?;
            let ln_gateway = lightning_module
                .get_gateway(gateway_id, force_internal)
                .await?;

            let lightning_module = client.get_first_module::<LightningClientModule>()?;
            let desc = Description::new(description)?;
            let (operation_id, invoice, _) = lightning_module
                .create_bolt11_invoice(
                    amount,
                    Bolt11InvoiceDescription::Direct(desc),
                    expiry_time,
                    (),
                    ln_gateway,
                )
                .await?;
            Ok(serde_json::to_value(LnInvoiceResponse {
                operation_id,
                invoice: invoice.to_string(),
            })
            .unwrap())
        }
        ClientCmd::AwaitInvoice { operation_id } => {
            let lightning_module = &client.get_first_module::<LightningClientModule>()?;
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

                debug!(target: LOG_CLIENT, ?update, "Await invoice state update");
            }

            Err(anyhow::anyhow!(
                "Unexpected end of update stream. Lightning receive failed"
            ))
        }
        ClientCmd::LnPay {
            payment_info,
            amount,
            lnurl_comment,
            gateway_id,
            force_internal,
        } => {
            warn!(
                target: LOG_CLIENT,
                "Command deprecated. Use `fedimint-cli module ln pay` instead."
            );
            let bolt11 =
                fedimint_ln_client::get_invoice(&payment_info, amount, lnurl_comment).await?;
            info!(target: LOG_CLIENT, "Paying invoice: {bolt11}");
            let lightning_module = client.get_first_module::<LightningClientModule>()?;
            let ln_gateway = lightning_module
                .get_gateway(gateway_id, force_internal)
                .await?;

            let lightning_module = client.get_first_module::<LightningClientModule>()?;
            let OutgoingLightningPayment {
                payment_type,
                contract_id: _,
                fee,
            } = lightning_module
                .pay_bolt11_invoice(ln_gateway, bolt11, ())
                .await?;
            let operation_id = payment_type.operation_id();
            info!(
                target: LOG_CLIENT,
                "Gateway fee: {fee}, payment operation id: {}",
                operation_id.fmt_short()
            );
            let lnv1 = client.get_first_module::<LightningClientModule>()?;
            let outcome = lnv1.await_outgoing_payment(operation_id).await?;
            Ok(serde_json::to_value(outcome).expect("Cant fail"))
        }
        ClientCmd::AwaitLnPay { operation_id } => {
            let lightning_module = client.get_first_module::<LightningClientModule>()?;
            let outcome = lightning_module
                .await_outgoing_payment(operation_id)
                .await?;
            Ok(serde_json::to_value(outcome).expect("Cant fail"))
        }
        ClientCmd::ListGateways { no_update } => {
            let lightning_module = client.get_first_module::<LightningClientModule>()?;
            if !no_update {
                lightning_module.update_gateway_cache().await?;
            }
            let gateways = lightning_module.list_gateways().await;
            if gateways.is_empty() {
                return Ok(serde_json::to_value(Vec::<String>::new()).unwrap());
            }

            Ok(json!(&gateways))
        }
        ClientCmd::DepositAddress => {
            eprintln!(
                "`deposit-address` command is deprecated. Use `module wallet new-deposit-address` instead."
            );
            let (operation_id, address, tweak_idx) = client
                .get_first_module::<WalletClientModule>()?
                .allocate_deposit_address_expert_only(())
                .await?;
            Ok(serde_json::json! {
                {
                    "address": address,
                    "operation_id": operation_id,
                    "idx": tweak_idx.0
                }
            })
        }
        ClientCmd::AwaitDeposit { operation_id } => {
            eprintln!("`await-deposit` is deprecated. Use `module wallet await-deposit` instead.");
            client
                .get_first_module::<WalletClientModule>()?
                .await_num_deposits_by_operation_id(operation_id, 1)
                .await?;

            Ok(serde_json::to_value(()).unwrap())
        }

        ClientCmd::Backup { metadata } => {
            let metadata = metadata_from_clap_cli(metadata)?;

            #[allow(deprecated)]
            client
                .backup_to_federation(Metadata::from_json_serialized(metadata))
                .await?;
            Ok(serde_json::to_value(()).unwrap())
        }
        ClientCmd::Restore { .. } => {
            panic!("Has to be handled before initializing client")
        }
        ClientCmd::PrintSecret => {
            let entropy = client.get_decoded_client_secret::<Vec<u8>>().await?;
            let mnemonic = Mnemonic::from_entropy(&entropy)?;

            Ok(json!({
                "secret": mnemonic,
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

            let operations = client
                .operation_log()
                .paginate_operations_rev(limit, None)
                .await
                .into_iter()
                .map(|(k, v)| {
                    let creation_time = time_to_iso8601(&k.creation_time);

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
            let wallet_module = client.get_first_module::<WalletClientModule>()?;
            let address = address.require_network(wallet_module.get_network())?;
            let (amount, fees) = match amount {
                // If the amount is "all", then we need to subtract the fees from
                // the amount we are withdrawing
                BitcoinAmountOrAll::All => {
                    let balance =
                        bitcoin::Amount::from_sat(client.get_balance_for_btc().await?.msats / 1000);
                    let fees = wallet_module.get_withdraw_fees(&address, balance).await?;
                    let amount = balance.checked_sub(fees.amount());
                    if amount.is_none() {
                        bail!("Not enough funds to pay fees");
                    }
                    (amount.unwrap(), fees)
                }
                BitcoinAmountOrAll::Amount(amount) => (
                    amount,
                    wallet_module.get_withdraw_fees(&address, amount).await?,
                ),
            };
            let absolute_fees = fees.amount();

            info!(
                target: LOG_CLIENT,
                "Attempting withdraw with fees: {fees:?}"
            );

            let operation_id = wallet_module.withdraw(&address, amount, fees, ()).await?;

            let mut updates = wallet_module
                .subscribe_withdraw_updates(operation_id)
                .await?
                .into_stream();

            while let Some(update) = updates.next().await {
                debug!(target: LOG_CLIENT, ?update, "Withdraw state update");

                match update {
                    WithdrawState::Succeeded(txid) => {
                        return Ok(json!({
                            "txid": txid.consensus_encode_to_hex(),
                            "fees_sat": absolute_fees.to_sat(),
                        }));
                    }
                    WithdrawState::Failed(e) => {
                        bail!("Withdraw failed: {e}");
                    }
                    WithdrawState::Created => {}
                }
            }

            unreachable!("Update stream ended without outcome");
        }
        ClientCmd::DiscoverVersion => {
            Ok(json!({ "versions": client.load_and_refresh_common_api_version().await? }))
        }
        ClientCmd::Module { module, args } => {
            if let Some(module) = module {
                let module_instance_id = module.resolve(&client)?;

                client
                    .get_module_client_dyn(module_instance_id)
                    .context("Module not found")?
                    .handle_cli_command(&args)
                    .await
            } else {
                let module_list: Vec<ModuleInfo> = client
                    .config()
                    .await
                    .modules
                    .iter()
                    .map(|(id, ClientModuleConfig { kind, .. })| ModuleInfo {
                        kind: kind.clone(),
                        id: *id,
                        status: if client.has_module(*id) {
                            ModuleStatus::Active
                        } else {
                            ModuleStatus::UnsupportedByClient
                        },
                    })
                    .collect();
                Ok(json!({
                    "list": module_list,
                }))
            }
        }
        ClientCmd::Config => {
            let config = client.get_config_json().await;
            Ok(serde_json::to_value(config).expect("Client config is serializable"))
        }
        ClientCmd::SessionCount => {
            let count = client.api().session_count().await?;
            Ok(json!({ "count": count }))
        }
    }
}

async fn get_note_summary(client: &ClientHandleArc) -> anyhow::Result<serde_json::Value> {
    let mint_client = client.get_first_module::<MintClientModule>()?;
    let mint_module_id = client
        .get_first_instance(&fedimint_mint_client::KIND)
        .context("Mint module not found")?;
    let wallet_client = client.get_first_module::<WalletClientModule>()?;
    let summary = mint_client
        .get_note_counts_by_denomination(
            &mut client
                .db()
                .begin_transaction_nc()
                .await
                .to_ref_with_prefix_module_id(mint_module_id)
                .0,
        )
        .await;
    Ok(serde_json::to_value(InfoResponse {
        federation_id: client.federation_id(),
        network: wallet_client.get_network(),
        meta: client.config().await.global.meta.clone(),
        total_amount_msat: summary.total_amount(),
        total_num_notes: summary.count_items(),
        denominations_msat: summary,
    })
    .unwrap())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InfoResponse {
    federation_id: FederationId,
    network: Network,
    meta: BTreeMap<String, String>,
    total_amount_msat: Amount,
    total_num_notes: usize,
    denominations_msat: TieredCounts,
}

pub(crate) fn time_to_iso8601(time: &SystemTime) -> String {
    const ISO8601_CONFIG: iso8601::EncodedConfig = iso8601::Config::DEFAULT
        .set_formatted_components(iso8601::FormattedComponents::DateTime)
        .encode();

    OffsetDateTime::from_unix_timestamp_nanos(
        time.duration_since(UNIX_EPOCH)
            .expect("Couldn't convert time from SystemTime to timestamp")
            .as_nanos()
            .try_into()
            .expect("Time overflowed"),
    )
    .expect("Couldn't convert time from SystemTime to OffsetDateTime")
    .format(&iso8601::Iso8601::<ISO8601_CONFIG>)
    .expect("Couldn't format OffsetDateTime as ISO8601")
}
