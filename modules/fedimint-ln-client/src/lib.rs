#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]

pub use fedimint_ln_common as common;

pub mod api;
#[cfg(feature = "cli")]
pub mod cli;
pub mod db;
pub mod events;
pub mod incoming;
pub mod pay;
pub mod receive;
/// Implements recurring payment codes (e.g. LNURL, BOLT12)
pub mod recurring;

use std::collections::{BTreeMap, BTreeSet};
use std::iter::once;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail, ensure, format_err};
use api::LnFederationApi;
use async_stream::{stream, try_stream};
use bitcoin::Network;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
use db::{
    DbKeyPrefix, LightningGatewayKey, LightningGatewayKeyPrefix, PaymentResult, PaymentResultKey,
    RecurringPaymentCodeKeyPrefix,
};
use fedimint_api_client::api::{DynModuleApi, ServerError};
use fedimint_client_module::db::{ClientModuleMigrationFn, migrate_state};
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{
    ClientContext, ClientModule, IClientModule, OutPointRange, decode_current_fee_consensus,
};
use fedimint_client_module::oplog::UpdateStreamOrOutcome;
use fedimint_client_module::sm::{DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, ClientOutputSM, FeeQuote,
    FeeQuoteRequest, TransactionBuilder,
};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::CurrentFeeConsensus;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{
    Amounts, ApiVersion, CommonModuleInit, FeeCharge, FeeComponent, FeePriority, FeeRate,
    ModuleCommon, ModuleInit, MultiApiVersion, TransactionItemFees,
};
use fedimint_core::secp256k1::{
    All, Keypair, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification,
};
use fedimint_core::task::{MaybeSend, MaybeSync, timeout};
use fedimint_core::util::update_merge::UpdateMerge;
use fedimint_core::util::{BoxStream, FmtCompactAnyhow as _, backoff_util, retry};
use fedimint_core::{
    Amount, OutPoint, apply, async_trait_maybe_send, push_db_pair_items, runtime, secp256k1,
};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_ln_common::client::GatewayApi;
use fedimint_ln_common::config::{
    FeeConsensus as LightningFeeConsensus, FeeToAmount, LightningClientConfig,
};
use fedimint_ln_common::contracts::incoming::{IncomingContract, IncomingContractOffer};
use fedimint_ln_common::contracts::outgoing::{
    OutgoingContract, OutgoingContractAccount, OutgoingContractData,
};
use fedimint_ln_common::contracts::{
    Contract, ContractId, DecryptedPreimage, EncryptedPreimage, IdentifiableContract, Preimage,
    PreimageKey,
};
use fedimint_ln_common::gateway_endpoint_constants::{
    GET_GATEWAY_ID_ENDPOINT, PAY_INVOICE_ENDPOINT,
};
use fedimint_ln_common::{
    ContractOutput, KIND, LightningCommonInit, LightningGateway, LightningGatewayAnnouncement,
    LightningGatewayRegistration, LightningInput, LightningModuleTypes, LightningOutput,
    LightningOutputV0,
};
use fedimint_logging::LOG_CLIENT_MODULE_LN;
use futures::{Future, StreamExt};
use incoming::IncomingSmError;
use itertools::Itertools;
use lightning_invoice::{
    Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret, RouteHint, RouteHintHop, RoutingFees,
};
use pay::PayInvoicePayload;
use rand::rngs::OsRng;
use rand::seq::IteratorRandom as _;
use rand::{CryptoRng, Rng, RngCore};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tokio::sync::Notify;
use tracing::{debug, error, info};

use crate::db::PaymentResultPrefix;
use crate::incoming::{
    FundingOfferState, IncomingSmCommon, IncomingSmStates, IncomingStateMachine,
};
use crate::pay::lightningpay::LightningPayStates;
use crate::pay::{
    GatewayPayError, LightningPayCommon, LightningPayCreatedOutgoingLnContract,
    LightningPayStateMachine,
};
use crate::receive::{
    LightningReceiveConfirmedInvoice, LightningReceiveError, LightningReceiveStateMachine,
    LightningReceiveStates, LightningReceiveSubmittedOffer, get_incoming_contract,
};
use crate::recurring::RecurringPaymentCodeEntry;

/// Number of blocks until outgoing lightning contracts times out and user
/// client can get refund
const OUTGOING_LN_CONTRACT_TIMELOCK: u64 = 500;
const LN_FEE_PRIORITY: FeePriority = FeePriority(1);

// 24 hours. Many wallets default to 1 hour, but it's a bad user experience if
// invoices expire too quickly
const DEFAULT_INVOICE_EXPIRY_TIME: Duration = Duration::from_hours(24);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
#[serde(rename_all = "snake_case")]
pub enum PayType {
    // Payment from this client to another user within the federation
    Internal(OperationId),
    // Payment from this client to another user, facilitated by a gateway
    Lightning(OperationId),
}

impl PayType {
    pub fn operation_id(&self) -> OperationId {
        match self {
            PayType::Internal(operation_id) | PayType::Lightning(operation_id) => *operation_id,
        }
    }

    pub fn payment_type(&self) -> String {
        match self {
            PayType::Internal(_) => "internal",
            PayType::Lightning(_) => "lightning",
        }
        .into()
    }
}

/// Where to receive the payment to, either to ourselves or to another user
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum ReceivingKey {
    /// The keypair used to receive payments for ourselves, we will use this to
    /// sweep to our own ecash wallet on success
    Personal(Keypair),
    /// A public key of another user, the lightning payment will be locked to
    /// this key for them to claim on success
    External(PublicKey),
}

impl ReceivingKey {
    /// The public key of the receiving key
    pub fn public_key(&self) -> PublicKey {
        match self {
            ReceivingKey::Personal(keypair) => keypair.public_key(),
            ReceivingKey::External(public_key) => *public_key,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum LightningPaymentOutcome {
    Success { preimage: String },
    Failure { error_message: String },
}

/// The high-level state of an pay operation internal to the federation,
/// started with [`LightningClientModule::pay_bolt11_invoice`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalPayState {
    Funding,
    Preimage(Preimage),
    RefundSuccess {
        out_points: Vec<OutPoint>,
        error: IncomingSmError,
    },
    RefundError {
        error_message: String,
        error: IncomingSmError,
    },
    FundingFailed {
        error: IncomingSmError,
    },
    UnexpectedError(String),
}

/// The high-level state of a pay operation over lightning,
/// started with [`LightningClientModule::pay_bolt11_invoice`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LnPayState {
    Created,
    Canceled,
    Funded { block_height: u32 },
    WaitingForRefund { error_reason: String },
    AwaitingChange,
    Success { preimage: String },
    Refunded { gateway_error: GatewayPayError },
    UnexpectedError { error_message: String },
}

/// The high-level state of a reissue operation started with
/// [`LightningClientModule::create_bolt11_invoice`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LnReceiveState {
    Created,
    WaitingForPayment { invoice: String, timeout: Duration },
    Canceled { reason: LightningReceiveError },
    Funded,
    AwaitingFunds,
    Claimed,
}

fn invoice_has_internal_payment_markers(
    invoice: &Bolt11Invoice,
    markers: (fedimint_core::secp256k1::PublicKey, u64),
) -> bool {
    // Asserts that the invoice src_node_id and short_channel_id match known
    // values used as internal payment markers
    invoice
        .route_hints()
        .first()
        .and_then(|rh| rh.0.last())
        .map(|hop| (hop.src_node_id, hop.short_channel_id))
        == Some(markers)
}

fn invoice_routes_back_to_federation(
    invoice: &Bolt11Invoice,
    gateways: Vec<LightningGateway>,
) -> bool {
    gateways.into_iter().any(|gateway| {
        invoice
            .route_hints()
            .first()
            .and_then(|rh| rh.0.last())
            .map(|hop| (hop.src_node_id, hop.short_channel_id))
            == Some((gateway.node_pub_key, gateway.federation_index))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LightningOperationMetaPay {
    pub out_point: OutPoint,
    pub invoice: Bolt11Invoice,
    pub fee: Amount,
    pub change: Vec<OutPoint>,
    pub is_internal_payment: bool,
    pub contract_id: ContractId,
    pub gateway_id: Option<secp256k1::PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningOperationMeta {
    pub variant: LightningOperationMetaVariant,
    pub extra_meta: serde_json::Value,
}

pub use deprecated_variant_hack::LightningOperationMetaVariant;

/// This is a hack to allow us to use the deprecated variant in the database
/// without the serde derived implementation throwing warnings.
///
/// See <https://github.com/serde-rs/serde/issues/2195>
#[allow(deprecated)]
mod deprecated_variant_hack {
    use super::{
        Bolt11Invoice, Deserialize, LightningOperationMetaPay, OperationId, OutPoint, Serialize,
        secp256k1,
    };
    use crate::recurring::ReurringPaymentReceiveMeta;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum LightningOperationMetaVariant {
        Pay(LightningOperationMetaPay),
        Receive {
            out_point: OutPoint,
            invoice: Bolt11Invoice,
            gateway_id: Option<secp256k1::PublicKey>,
        },
        ReceiveReclaim {
            original_operation_id: OperationId,
            invoice: Bolt11Invoice,
            gateway_id: Option<secp256k1::PublicKey>,
        },
        #[deprecated(
            since = "0.7.0",
            note = "Use recurring payment functionality instead instead"
        )]
        Claim {
            out_points: Vec<OutPoint>,
        },
        RecurringPaymentReceive(ReurringPaymentReceiveMeta),
    }
}

#[derive(Debug, Clone, Default)]
pub struct LightningClientInit {
    pub gateway_conn: Option<Arc<dyn GatewayConnection + Send + Sync>>,
}

impl ModuleInit for LightningClientInit {
    type Common = LightningCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut ln_client_items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            #[allow(clippy::match_same_arms)]
            match table {
                DbKeyPrefix::ActiveGateway | DbKeyPrefix::MetaOverridesDeprecated => {
                    // Deprecated
                }
                DbKeyPrefix::PaymentResult => {
                    push_db_pair_items!(
                        dbtx,
                        PaymentResultPrefix,
                        PaymentResultKey,
                        PaymentResult,
                        ln_client_items,
                        "Payment Result"
                    );
                }
                DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        dbtx,
                        LightningGatewayKeyPrefix,
                        LightningGatewayKey,
                        LightningGatewayRegistration,
                        ln_client_items,
                        "Lightning Gateways"
                    );
                }
                DbKeyPrefix::RecurringPaymentKey => {
                    push_db_pair_items!(
                        dbtx,
                        RecurringPaymentCodeKeyPrefix,
                        RecurringPaymentCodeKey,
                        RecurringPaymentCodeEntry,
                        ln_client_items,
                        "Recurring Payment Code"
                    );
                }
                DbKeyPrefix::ExternalReservedStart
                | DbKeyPrefix::CoreInternalReservedStart
                | DbKeyPrefix::CoreInternalReservedEnd => {}
            }
        }

        Box::new(ln_client_items.into_iter())
    }
}

#[derive(Debug)]
#[repr(u64)]
pub enum LightningChildKeys {
    RedeemKey = 0,
    PreimageAuthentication = 1,
    RecurringPaymentCodeSecret = 2,
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for LightningClientInit {
    type Module = LightningClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        let gateway_conn = if let Some(gateway_conn) = self.gateway_conn.clone() {
            gateway_conn
        } else {
            let api = GatewayApi::new(None, args.connector_registry.clone());
            Arc::new(RealGatewayConnection { api })
        };
        Ok(LightningClientModule::new(args, gateway_conn))
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        let mut migrations: BTreeMap<DatabaseVersion, ClientModuleMigrationFn> = BTreeMap::new();
        migrations.insert(DatabaseVersion(0), |dbtx, _, _| {
            Box::pin(async {
                dbtx.remove_entry(&crate::db::ActiveGatewayKey).await;
                Ok(None)
            })
        });

        migrations.insert(DatabaseVersion(1), |_, active_states, inactive_states| {
            Box::pin(async {
                migrate_state(active_states, inactive_states, db::get_v1_migrated_state)
            })
        });

        migrations.insert(DatabaseVersion(2), |_, active_states, inactive_states| {
            Box::pin(async {
                migrate_state(active_states, inactive_states, db::get_v2_migrated_state)
            })
        });

        migrations.insert(DatabaseVersion(3), |_, active_states, inactive_states| {
            Box::pin(async {
                migrate_state(active_states, inactive_states, db::get_v3_migrated_state)
            })
        });

        migrations
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(
            DbKeyPrefix::iter()
                .map(|p| p as u8)
                .chain(
                    DbKeyPrefix::ExternalReservedStart as u8
                        ..=DbKeyPrefix::CoreInternalReservedEnd as u8,
                )
                .collect(),
        )
    }
}

/// Client side lightning module
///
/// Note that lightning gateways use a different version
/// of client side module.
#[derive(Debug)]
pub struct LightningClientModule {
    pub cfg: LightningClientConfig,
    notifier: ModuleNotifier<LightningClientStateMachines>,
    redeem_key: Keypair,
    recurring_payment_code_secret: DerivableSecret,
    secp: Secp256k1<All>,
    module_api: DynModuleApi,
    preimage_auth: Keypair,
    client_ctx: ClientContext<Self>,
    update_gateway_cache_merge: UpdateMerge,
    gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
    new_recurring_payment_code: Arc<Notify>,
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for LightningClientModule {
    type Init = LightningClientInit;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = LightningClientContext;
    type States = LightningClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        LightningClientContext {
            ln_decoder: self.decoder(),
            redeem_key: self.redeem_key,
            gateway_conn: self.gateway_conn.clone(),
            client_ctx: Some(self.client_ctx.clone()),
        }
    }

    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(self.cfg.fee_consensus.contract_input))
    }

    fn input_fees(
        &self,
        amount: &Amounts,
        input: &<Self::Common as ModuleCommon>::Input,
        fee_consensus: &[CurrentFeeConsensus],
    ) -> Option<TransactionItemFees> {
        let legacy_fee = <Self as ClientModule>::input_fee(self, amount, input)?.get_bitcoin();
        let amount = input
            .maybe_v0_ref()
            .map(|input| input.amount)
            .unwrap_or_else(|| amount.get_bitcoin());
        let Some(fee_consensus) = decode_current_fee_consensus::<LightningFeeConsensus>(
            fee_consensus,
            &ModuleDecoderRegistry::default(),
        ) else {
            return Some(TransactionItemFees::from_legacy_amounts(
                Amounts::new_bitcoin(legacy_fee),
            ));
        };
        let fee_rate = [
            fee_consensus.incoming_contract_input,
            fee_consensus.outgoing_contract_input,
        ]
        .into_iter()
        .max_by_key(|fee_rate| fee_rate.total_fee(amount))
        .unwrap_or_else(FeeRate::zero);

        Some(TransactionItemFees::from_bitcoin_rate(
            [fee_rate],
            amount,
            LN_FEE_PRIORITY,
            legacy_fee,
        ))
    }

    fn output_fee(
        &self,
        _amount: &Amounts,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        match output.maybe_v0_ref()? {
            LightningOutputV0::Contract(_) => {
                Some(Amounts::new_bitcoin(self.cfg.fee_consensus.contract_output))
            }
            LightningOutputV0::Offer(_) | LightningOutputV0::CancelOutgoing { .. } => {
                Some(Amounts::ZERO)
            }
        }
    }

    fn output_fees(
        &self,
        amount: &Amounts,
        output: &<Self::Common as ModuleCommon>::Output,
        fee_consensus: &[CurrentFeeConsensus],
    ) -> Option<TransactionItemFees> {
        let legacy_fee = <Self as ClientModule>::output_fee(self, amount, output)?.get_bitcoin();
        let Some(fee_consensus) = decode_current_fee_consensus::<LightningFeeConsensus>(
            fee_consensus,
            &ModuleDecoderRegistry::default(),
        ) else {
            return Some(TransactionItemFees::from_legacy_amounts(
                Amounts::new_bitcoin(legacy_fee),
            ));
        };

        let output = output.maybe_v0_ref()?;
        match output {
            LightningOutputV0::Contract(contract_output) => {
                let fee_rate = match &contract_output.contract {
                    Contract::Incoming(_) => fee_consensus.incoming_contract_output,
                    Contract::Outgoing(_) => fee_consensus.outgoing_contract_output,
                };

                Some(TransactionItemFees::from_bitcoin_rate(
                    [fee_rate],
                    contract_output.amount,
                    LN_FEE_PRIORITY,
                    legacy_fee,
                ))
            }
            LightningOutputV0::Offer(_) => Some(TransactionItemFees::with_legacy_floor(
                vec![FeeComponent {
                    fees: Amounts::new_bitcoin(fee_consensus.offer),
                    charge: FeeCharge::Always,
                }],
                Amounts::ZERO,
            )),
            LightningOutputV0::CancelOutgoing { .. } => Some(TransactionItemFees::ZERO),
        }
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }

    async fn handle_rpc(
        &self,
        method: String,
        payload: serde_json::Value,
    ) -> BoxStream<'_, anyhow::Result<serde_json::Value>> {
        Box::pin(try_stream! {
            match method.as_str() {
                "create_bolt11_invoice" => {
                    let req: CreateBolt11InvoiceRequest = serde_json::from_value(payload)?;
                    let (op, invoice, _) = self
                        .create_bolt11_invoice(
                            req.amount,
                            lightning_invoice::Bolt11InvoiceDescription::Direct(
                                lightning_invoice::Description::new(req.description)?,
                            ),
                            req.expiry_time,
                            req.extra_meta,
                            req.gateway,
                        )
                        .await?;
                    yield serde_json::json!({
                        "operation_id": op,
                        "invoice": invoice,
                    });
                }
                "pay_bolt11_invoice" => {
                    let req: PayBolt11InvoiceRequest = serde_json::from_value(payload)?;
                    let outgoing_payment = self
                        .pay_bolt11_invoice(req.maybe_gateway, req.invoice, req.extra_meta)
                        .await?;
                    yield serde_json::to_value(outgoing_payment)?;
                }
                "select_available_gateway" => {
                    let req: SelectAvailableGatewayRequest = serde_json::from_value(payload)?;
                    let gateway = self.select_available_gateway(req.maybe_gateway,req.maybe_invoice).await?;
                    yield serde_json::to_value(gateway)?;
                }
                "subscribe_ln_pay" => {
                    let req: SubscribeLnPayRequest = serde_json::from_value(payload)?;
                    for await state in self.subscribe_ln_pay(req.operation_id).await?.into_stream() {
                        yield serde_json::to_value(state)?;
                    }
                }
                "subscribe_internal_pay" => {
                    let req: SubscribeInternalPayRequest = serde_json::from_value(payload)?;
                    for await state in self.subscribe_internal_pay(req.operation_id).await?.into_stream() {
                        yield serde_json::to_value(state)?;
                    }
                }
                "subscribe_ln_receive" => {
                    let req: SubscribeLnReceiveRequest = serde_json::from_value(payload)?;
                    for await state in self.subscribe_ln_receive(req.operation_id).await?.into_stream()
                    {
                        yield serde_json::to_value(state)?;
                    }
                }
                "reclaim_ln_receive" => {
                    let req: ReclaimLnReceiveRequest = serde_json::from_value(payload)?;
                    let operation_id = self.reclaim_ln_receive(req.original_operation_id).await?;
                    yield serde_json::json!({
                        "operation_id": operation_id,
                    });
                }
                "create_bolt11_invoice_for_user_tweaked" => {
                    let req: CreateBolt11InvoiceForUserTweakedRequest = serde_json::from_value(payload)?;
                    let (op, invoice, _) = self
                        .create_bolt11_invoice_for_user_tweaked(
                            req.amount,
                            lightning_invoice::Bolt11InvoiceDescription::Direct(
                                lightning_invoice::Description::new(req.description)?,
                            ),
                            req.expiry_time,
                            req.user_key,
                            req.index,
                            req.extra_meta,
                            req.gateway,
                        )
                        .await?;
                    yield serde_json::json!({
                        "operation_id": op,
                        "invoice": invoice,
                    });
                }
                #[allow(deprecated)]
                "scan_receive_for_user_tweaked" => {
                    let req: ScanReceiveForUserTweakedRequest = serde_json::from_value(payload)?;
                    let keypair = Keypair::from_secret_key(&self.secp, &req.user_key);
                    let operation_ids = self.scan_receive_for_user_tweaked(keypair, req.indices, req.extra_meta).await;
                    yield serde_json::to_value(operation_ids)?;
                }
                #[allow(deprecated)]
                "subscribe_ln_claim" => {
                    let req: SubscribeLnClaimRequest = serde_json::from_value(payload)?;
                    for await state in self.subscribe_ln_claim(req.operation_id).await?.into_stream() {
                        yield serde_json::to_value(state)?;
                    }
                }
                "get_gateway" => {
                    let req: GetGatewayRequest = serde_json::from_value(payload)?;
                    let gateway = self.get_gateway(req.gateway_id, req.force_internal).await?;
                    yield serde_json::to_value(gateway)?;
                }
                "list_gateways" => {
                    let gateways = self.list_gateways().await;
                    yield serde_json::to_value(gateways)?;
                }
                "update_gateway_cache" => {
                    self.update_gateway_cache().await?;
                    yield serde_json::Value::Null;
                }
                "pay_lightning_address" => {
                    let req: PayLightningAddressRequest = serde_json::from_value(payload)?;
                    let invoice = get_invoice(&req.address, Some(Amount::from_msats(req.amount)), None).await?;
                    let gateway = self.get_gateway(None, false).await?;
                    let output = self.pay_bolt11_invoice(gateway, invoice, ()).await?;

                    yield serde_json::to_value(output)?;
                }
                _ => {
                    Err(anyhow::format_err!("Unknown method: {method}"))?;
                    unreachable!()
                },
            }
        })
    }
}

#[derive(Deserialize)]
struct CreateBolt11InvoiceRequest {
    amount: Amount,
    description: String,
    expiry_time: Option<u64>,
    extra_meta: serde_json::Value,
    gateway: Option<LightningGateway>,
}

#[derive(Deserialize)]
struct PayBolt11InvoiceRequest {
    maybe_gateway: Option<LightningGateway>,
    invoice: Bolt11Invoice,
    extra_meta: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct SubscribeLnPayRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct SubscribeInternalPayRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct SubscribeLnReceiveRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct ReclaimLnReceiveRequest {
    original_operation_id: OperationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelectAvailableGatewayRequest {
    maybe_gateway: Option<LightningGateway>,
    maybe_invoice: Option<Bolt11Invoice>,
}

#[derive(Deserialize)]
struct CreateBolt11InvoiceForUserTweakedRequest {
    amount: Amount,
    description: String,
    expiry_time: Option<u64>,
    user_key: PublicKey,
    index: u64,
    extra_meta: serde_json::Value,
    gateway: Option<LightningGateway>,
}

#[derive(Deserialize)]
struct ScanReceiveForUserTweakedRequest {
    user_key: SecretKey,
    indices: Vec<u64>,
    extra_meta: serde_json::Value,
}

#[derive(Deserialize)]
struct SubscribeLnClaimRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct GetGatewayRequest {
    gateway_id: Option<secp256k1::PublicKey>,
    force_internal: bool,
}

#[derive(Deserialize)]
struct PayLightningAddressRequest {
    address: String,
    amount: u64,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum GatewayStatus {
    OnlineVetted,
    OnlineNonVetted,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum PayBolt11InvoiceError {
    #[error("Previous payment attempt({}) still in progress", .operation_id.fmt_full())]
    PreviousPaymentAttemptStillInProgress { operation_id: OperationId },
    #[error("No LN gateway available")]
    NoLnGatewayAvailable,
    #[error("Funded contract already exists: {}", .contract_id)]
    FundedContractAlreadyExists { contract_id: ContractId },
}

impl LightningClientModule {
    fn new(
        args: &ClientModuleInitArgs<LightningClientInit>,
        gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
    ) -> Self {
        let secp = Secp256k1::new();

        let new_recurring_payment_code = Arc::new(Notify::new());
        args.spawn_cancellable(
            "Recurring payment sync",
            Self::scan_recurring_payment_code_invoices(
                args.context(),
                new_recurring_payment_code.clone(),
            ),
        );

        Self {
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            redeem_key: args
                .module_root_secret()
                .child_key(ChildId(LightningChildKeys::RedeemKey as u64))
                .to_secp_key(&secp),
            recurring_payment_code_secret: args.module_root_secret().child_key(ChildId(
                LightningChildKeys::RecurringPaymentCodeSecret as u64,
            )),
            module_api: args.module_api().clone(),
            preimage_auth: args
                .module_root_secret()
                .child_key(ChildId(LightningChildKeys::PreimageAuthentication as u64))
                .to_secp_key(&secp),
            secp,
            client_ctx: args.context(),
            update_gateway_cache_merge: UpdateMerge::default(),
            gateway_conn,
            new_recurring_payment_code,
        }
    }

    pub async fn get_prev_payment_result(
        &self,
        payment_hash: &sha256::Hash,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> PaymentResult {
        let prev_result = dbtx
            .get_value(&PaymentResultKey {
                payment_hash: *payment_hash,
            })
            .await;
        prev_result.unwrap_or(PaymentResult {
            index: 0,
            completed_payment: None,
        })
    }

    fn get_payment_operation_id(payment_hash: &sha256::Hash, index: u16) -> OperationId {
        // Copy the 32 byte payment hash and a 2 byte index to make every payment
        // attempt have a unique `OperationId`
        let mut bytes = [0; 34];
        bytes[0..32].copy_from_slice(&payment_hash.to_byte_array());
        bytes[32..34].copy_from_slice(&index.to_le_bytes());
        let hash: sha256::Hash = Hash::hash(&bytes);
        OperationId(hash.to_byte_array())
    }

    /// Hashes the client's preimage authentication secret with the provided
    /// `payment_hash`. The resulting hash is used when contacting the
    /// gateway to determine if this client is allowed to be shown the
    /// preimage.
    fn get_preimage_authentication(&self, payment_hash: &sha256::Hash) -> sha256::Hash {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&payment_hash.to_byte_array());
        bytes[32..64].copy_from_slice(&self.preimage_auth.secret_bytes());
        Hash::hash(&bytes)
    }

    /// Create an output that incentivizes a Lightning gateway to pay an invoice
    /// for us. It has time till the block height defined by `timelock`,
    /// after that we can claim our money back.
    async fn create_outgoing_output<'a, 'b>(
        &'a self,
        operation_id: OperationId,
        invoice: Bolt11Invoice,
        gateway: LightningGateway,
        fed_id: FederationId,
        mut rng: impl RngCore + CryptoRng + 'a,
    ) -> anyhow::Result<(
        ClientOutput<LightningOutputV0>,
        ClientOutputSM<LightningClientStateMachines>,
        ContractId,
    )> {
        let federation_currency: Currency = self.cfg.network.0.into();
        let invoice_currency = invoice.currency();
        ensure!(
            federation_currency == invoice_currency,
            "Invalid invoice currency: expected={federation_currency:?}, got={invoice_currency:?}"
        );

        // Do not create the funding transaction if the gateway is not currently
        // available
        self.gateway_conn
            .verify_gateway_availability(&gateway)
            .await?;

        let consensus_count = self
            .module_api
            .fetch_consensus_block_count()
            .await?
            .ok_or(format_err!("Cannot get consensus block count"))?;

        // Add the timelock to the current block count and the invoice's
        // `min_cltv_delta`
        let min_final_cltv = invoice.min_final_cltv_expiry_delta();
        let absolute_timelock =
            consensus_count + min_final_cltv + OUTGOING_LN_CONTRACT_TIMELOCK - 1;

        // Compute amount to lock in the outgoing contract
        let invoice_amount = Amount::from_msats(
            invoice
                .amount_milli_satoshis()
                .context("MissingInvoiceAmount")?,
        );

        let gateway_fee = gateway.fees.to_amount(&invoice_amount);
        let contract_amount = invoice_amount + gateway_fee;

        let user_sk = Keypair::new(&self.secp, &mut rng);

        let payment_hash = *invoice.payment_hash();
        let preimage_auth = self.get_preimage_authentication(&payment_hash);
        let contract = OutgoingContract {
            hash: payment_hash,
            gateway_key: gateway.gateway_redeem_key,
            timelock: absolute_timelock as u32,
            user_key: user_sk.public_key(),
            cancelled: false,
        };

        let outgoing_payment = OutgoingContractData {
            recovery_key: user_sk,
            contract_account: OutgoingContractAccount {
                amount: contract_amount,
                contract: contract.clone(),
            },
        };

        let contract_id = contract.contract_id();
        let sm_gen = Arc::new(move |out_point_range: OutPointRange| {
            vec![LightningClientStateMachines::LightningPay(
                LightningPayStateMachine {
                    common: LightningPayCommon {
                        operation_id,
                        federation_id: fed_id,
                        contract: outgoing_payment.clone(),
                        gateway_fee,
                        preimage_auth,
                        invoice: invoice.clone(),
                    },
                    state: LightningPayStates::CreatedOutgoingLnContract(
                        LightningPayCreatedOutgoingLnContract {
                            funding_txid: out_point_range.txid(),
                            contract_id,
                            gateway: gateway.clone(),
                        },
                    ),
                },
            )]
        });

        let ln_output = LightningOutputV0::Contract(ContractOutput {
            amount: contract_amount,
            contract: Contract::Outgoing(contract),
        });

        Ok((
            ClientOutput {
                output: ln_output,
                amounts: Amounts::new_bitcoin(contract_amount),
            },
            ClientOutputSM {
                state_machines: sm_gen,
            },
            contract_id,
        ))
    }

    /// Create an output that funds an incoming contract within the federation
    /// This directly completes a transaction between users, without involving a
    /// gateway
    async fn create_incoming_output(
        &self,
        operation_id: OperationId,
        invoice: Bolt11Invoice,
    ) -> anyhow::Result<(
        ClientOutput<LightningOutputV0>,
        ClientOutputSM<LightningClientStateMachines>,
        ContractId,
    )> {
        let payment_hash = *invoice.payment_hash();
        let invoice_amount = Amount {
            msats: invoice
                .amount_milli_satoshis()
                .ok_or(IncomingSmError::AmountError {
                    invoice: invoice.clone(),
                })?,
        };

        let (incoming_output, amount, contract_id) = create_incoming_contract_output(
            &self.module_api,
            payment_hash,
            invoice_amount,
            &self.redeem_key,
        )
        .await?;

        let client_output = ClientOutput::<LightningOutputV0> {
            output: incoming_output,
            amounts: Amounts::new_bitcoin(amount),
        };

        let client_output_sm = ClientOutputSM::<LightningClientStateMachines> {
            state_machines: Arc::new(move |out_point_range| {
                vec![LightningClientStateMachines::InternalPay(
                    IncomingStateMachine {
                        common: IncomingSmCommon {
                            operation_id,
                            contract_id,
                            payment_hash,
                        },
                        state: IncomingSmStates::FundingOffer(FundingOfferState {
                            txid: out_point_range.txid(),
                        }),
                    },
                )]
            }),
        };

        Ok((client_output, client_output_sm, contract_id))
    }

    async fn await_receive_success(
        &self,
        operation_id: OperationId,
    ) -> Result<(), LightningReceiveError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            if let Some(LightningClientStateMachines::Receive(state)) = stream.next().await {
                match state.state {
                    LightningReceiveStates::Success(_) => return Ok(()),
                    LightningReceiveStates::Canceled(e) => {
                        return Err(e);
                    }
                    _ => {}
                }
            }
        }
    }

    async fn await_claim_acceptance(
        &self,
        operation_id: OperationId,
    ) -> Result<Vec<OutPoint>, LightningReceiveError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            if let Some(LightningClientStateMachines::Receive(state)) = stream.next().await {
                match state.state {
                    LightningReceiveStates::Success(out_points) => return Ok(out_points),
                    LightningReceiveStates::Canceled(e) => {
                        return Err(e);
                    }
                    _ => {}
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn create_lightning_receive_output<'a>(
        &'a self,
        amount: Amount,
        description: lightning_invoice::Bolt11InvoiceDescription,
        receiving_key: ReceivingKey,
        mut rng: impl RngCore + CryptoRng + 'a,
        expiry_time: Option<u64>,
        src_node_id: secp256k1::PublicKey,
        short_channel_id: u64,
        route_hints: &[fedimint_ln_common::route_hints::RouteHint],
        network: Network,
    ) -> anyhow::Result<(
        OperationId,
        Bolt11Invoice,
        ClientOutputBundle<LightningOutput, LightningClientStateMachines>,
        [u8; 32],
    )> {
        let preimage_key: [u8; 33] = receiving_key.public_key().serialize();
        let preimage = sha256::Hash::hash(&preimage_key);
        let payment_hash = sha256::Hash::hash(&preimage.to_byte_array());

        // Temporary lightning node pubkey
        let (node_secret_key, node_public_key) = self.secp.generate_keypair(&mut rng);

        // Route hint instructing payer how to route to gateway
        let route_hint_last_hop = RouteHintHop {
            src_node_id,
            short_channel_id,
            fees: RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            cltv_expiry_delta: 30,
            htlc_minimum_msat: None,
            htlc_maximum_msat: None,
        };
        let mut final_route_hints = vec![RouteHint(vec![route_hint_last_hop.clone()])];
        if !route_hints.is_empty() {
            let mut two_hop_route_hints: Vec<RouteHint> = route_hints
                .iter()
                .map(|rh| {
                    RouteHint(
                        rh.to_ldk_route_hint()
                            .0
                            .iter()
                            .cloned()
                            .chain(once(route_hint_last_hop.clone()))
                            .collect(),
                    )
                })
                .collect();
            final_route_hints.append(&mut two_hop_route_hints);
        }

        let duration_since_epoch = fedimint_core::time::duration_since_epoch();

        let mut invoice_builder = InvoiceBuilder::new(network.into())
            .amount_milli_satoshis(amount.msats)
            .invoice_description(description)
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret(rng.r#gen()))
            .duration_since_epoch(duration_since_epoch)
            .min_final_cltv_expiry_delta(18)
            .payee_pub_key(node_public_key)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_INVOICE_EXPIRY_TIME.as_secs()),
            ));

        for rh in final_route_hints {
            invoice_builder = invoice_builder.private_route(rh);
        }

        let invoice = invoice_builder
            .build_signed(|msg| self.secp.sign_ecdsa_recoverable(msg, &node_secret_key))?;

        let operation_id = OperationId(*invoice.payment_hash().as_ref());

        let sm_invoice = invoice.clone();
        let sm_gen = Arc::new(move |out_point_range: OutPointRange| {
            vec![LightningClientStateMachines::Receive(
                LightningReceiveStateMachine {
                    operation_id,
                    state: LightningReceiveStates::SubmittedOffer(LightningReceiveSubmittedOffer {
                        offer_txid: out_point_range.txid(),
                        invoice: sm_invoice.clone(),
                        receiving_key,
                    }),
                },
            )]
        });

        let ln_output = LightningOutput::new_v0_offer(IncomingContractOffer {
            amount,
            hash: payment_hash,
            encrypted_preimage: EncryptedPreimage::new(
                &PreimageKey(preimage_key),
                &self.cfg.threshold_pub_key,
            ),
            expiry_time,
        });

        Ok((
            operation_id,
            invoice,
            ClientOutputBundle::new(
                vec![ClientOutput {
                    output: ln_output,
                    amounts: Amounts::ZERO,
                }],
                vec![ClientOutputSM {
                    state_machines: sm_gen,
                }],
            ),
            *preimage.as_ref(),
        ))
    }

    pub async fn select_available_gateway(
        &self,
        maybe_gateway: Option<LightningGateway>,
        maybe_invoice: Option<Bolt11Invoice>,
    ) -> anyhow::Result<LightningGateway> {
        if let Some(gw) = maybe_gateway {
            let gw_id = gw.gateway_id;
            if self
                .gateway_conn
                .verify_gateway_availability(&gw)
                .await
                .is_ok()
            {
                return Ok(gw);
            }
            return Err(anyhow::anyhow!("Specified gateway is offline: {gw_id}"));
        }

        let gateways: Vec<LightningGatewayAnnouncement> = self.list_gateways().await;
        if gateways.is_empty() {
            return Err(anyhow::anyhow!("No gateways available"));
        }

        let gateways_with_status =
            futures::future::join_all(gateways.into_iter().map(|gw| async {
                let online = self
                    .gateway_conn
                    .verify_gateway_availability(&gw.info)
                    .await
                    .is_ok();
                (gw, online)
            }))
            .await;

        let sorted_gateways: Vec<(LightningGatewayAnnouncement, GatewayStatus)> =
            gateways_with_status
                .into_iter()
                .filter_map(|(ann, online)| {
                    if online {
                        let status = if ann.vetted {
                            GatewayStatus::OnlineVetted
                        } else {
                            GatewayStatus::OnlineNonVetted
                        };
                        Some((ann, status))
                    } else {
                        None
                    }
                })
                .collect();

        if sorted_gateways.is_empty() {
            return Err(anyhow::anyhow!("No Lightning Gateway was reachable"));
        }

        let amount_msat = maybe_invoice.and_then(|inv| inv.amount_milli_satoshis());
        let sorted_gateways = sorted_gateways
            .into_iter()
            .sorted_by_key(|(ann, status)| {
                let total_fee_msat: u64 =
                    amount_msat.map_or(u64::from(ann.info.fees.base_msat), |amt| {
                        u64::from(ann.info.fees.base_msat)
                            + ((u128::from(amt)
                                * u128::from(ann.info.fees.proportional_millionths))
                                / 1_000_000) as u64
                    });
                (status.clone(), total_fee_msat)
            })
            .collect::<Vec<_>>();

        Ok(sorted_gateways[0].0.info.clone())
    }

    /// Selects a Lightning Gateway from a given `gateway_id` from the gateway
    /// cache.
    pub async fn select_gateway(
        &self,
        gateway_id: &secp256k1::PublicKey,
    ) -> Option<LightningGateway> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;
        let gateways = dbtx
            .find_by_prefix(&LightningGatewayKeyPrefix)
            .await
            .map(|(_, gw)| gw.info)
            .collect::<Vec<_>>()
            .await;
        gateways.into_iter().find(|g| &g.gateway_id == gateway_id)
    }

    /// Updates the gateway cache by fetching the latest registered gateways
    /// from the federation.
    ///
    /// See also [`Self::update_gateway_cache_continuously`].
    pub async fn update_gateway_cache(&self) -> anyhow::Result<()> {
        self.update_gateway_cache_merge
            .merge(async {
                let gateways = self.module_api.fetch_gateways().await?;
                let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

                // Remove all previous gateway entries
                dbtx.remove_by_prefix(&LightningGatewayKeyPrefix).await;

                for gw in &gateways {
                    dbtx.insert_entry(
                        &LightningGatewayKey(gw.info.gateway_id),
                        &gw.clone().anchor(),
                    )
                    .await;
                }

                dbtx.commit_tx().await;

                Ok(())
            })
            .await
    }

    /// Continuously update the gateway cache whenever a gateway expires.
    ///
    /// The gateways returned by `gateway_filters` are checked for expiry.
    /// Client integrators are expected to call this function in a spawned task.
    pub async fn update_gateway_cache_continuously<Fut>(
        &self,
        gateways_filter: impl Fn(Vec<LightningGatewayAnnouncement>) -> Fut,
    ) -> !
    where
        Fut: Future<Output = Vec<LightningGatewayAnnouncement>>,
    {
        const ABOUT_TO_EXPIRE: Duration = Duration::from_secs(30);
        const EMPTY_GATEWAY_SLEEP: Duration = Duration::from_mins(10);

        let mut first_time = true;

        loop {
            let gateways = self.list_gateways().await;
            let sleep_time = gateways_filter(gateways)
                .await
                .into_iter()
                .map(|x| x.ttl.saturating_sub(ABOUT_TO_EXPIRE))
                .min()
                .unwrap_or(if first_time {
                    // retry immediately first time
                    Duration::ZERO
                } else {
                    EMPTY_GATEWAY_SLEEP
                });
            runtime::sleep(sleep_time).await;

            // should never fail with usize::MAX attempts.
            let _ = retry(
                "update_gateway_cache",
                backoff_util::background_backoff(),
                || self.update_gateway_cache(),
            )
            .await;
            first_time = false;
        }
    }

    /// Returns all gateways that are currently in the gateway cache.
    pub async fn list_gateways(&self) -> Vec<LightningGatewayAnnouncement> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;
        dbtx.find_by_prefix(&LightningGatewayKeyPrefix)
            .await
            .map(|(_, gw)| gw.unanchor())
            .collect::<Vec<_>>()
            .await
    }

    /// Pays a LN invoice with our available funds using the supplied `gateway`
    /// if one was provided and the invoice is not an internal one. If none is
    /// supplied only internal payments are possible.
    ///
    /// The `gateway` can be acquired by calling
    /// [`LightningClientModule::select_gateway`].
    ///
    /// Can return error of type [`PayBolt11InvoiceError`]
    pub async fn pay_bolt11_invoice<M: Serialize + MaybeSend + MaybeSync>(
        &self,
        maybe_gateway: Option<LightningGateway>,
        invoice: Bolt11Invoice,
        extra_meta: M,
    ) -> anyhow::Result<OutgoingLightningPayment> {
        if let Some(expires_at) = invoice.expires_at() {
            ensure!(
                expires_at.as_secs() > fedimint_core::time::duration_since_epoch().as_secs(),
                "Invoice has expired"
            );
        }

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        let maybe_gateway_id = maybe_gateway.as_ref().map(|g| g.gateway_id);
        let prev_payment_result = self
            .get_prev_payment_result(invoice.payment_hash(), &mut dbtx.to_ref_nc())
            .await;

        if let Some(completed_payment) = prev_payment_result.completed_payment {
            return Ok(completed_payment);
        }

        // Verify that no previous payment attempt is still running
        let prev_operation_id = LightningClientModule::get_payment_operation_id(
            invoice.payment_hash(),
            prev_payment_result.index,
        );
        if self.client_ctx.has_active_states(prev_operation_id).await {
            bail!(
                PayBolt11InvoiceError::PreviousPaymentAttemptStillInProgress {
                    operation_id: prev_operation_id
                }
            )
        }

        let next_index = prev_payment_result.index + 1;
        let operation_id =
            LightningClientModule::get_payment_operation_id(invoice.payment_hash(), next_index);

        let new_payment_result = PaymentResult {
            index: next_index,
            completed_payment: None,
        };

        dbtx.insert_entry(
            &PaymentResultKey {
                payment_hash: *invoice.payment_hash(),
            },
            &new_payment_result,
        )
        .await;

        let markers = self.client_ctx.get_internal_payment_markers()?;

        let mut is_internal_payment = invoice_has_internal_payment_markers(&invoice, markers);
        if !is_internal_payment {
            let gateways = dbtx
                .find_by_prefix(&LightningGatewayKeyPrefix)
                .await
                .map(|(_, gw)| gw.info)
                .collect::<Vec<_>>()
                .await;
            is_internal_payment = invoice_routes_back_to_federation(&invoice, gateways);
        }

        let (pay_type, client_output, client_output_sm, contract_id) = if is_internal_payment {
            let (output, output_sm, contract_id) = self
                .create_incoming_output(operation_id, invoice.clone())
                .await?;
            (
                PayType::Internal(operation_id),
                output,
                output_sm,
                contract_id,
            )
        } else {
            let gateway = maybe_gateway.context(PayBolt11InvoiceError::NoLnGatewayAvailable)?;
            let (output, output_sm, contract_id) = self
                .create_outgoing_output(
                    operation_id,
                    invoice.clone(),
                    gateway,
                    self.client_ctx
                        .get_config()
                        .await
                        .global
                        .calculate_federation_id(),
                    rand::rngs::OsRng,
                )
                .await?;
            (
                PayType::Lightning(operation_id),
                output,
                output_sm,
                contract_id,
            )
        };

        // Verify that no other outgoing contract exists or the value is empty
        if let Ok(Some(contract)) = self.module_api.fetch_contract(contract_id).await
            && contract.amount.msats != 0
        {
            bail!(PayBolt11InvoiceError::FundedContractAlreadyExists { contract_id });
        }

        let amount_msat = invoice
            .amount_milli_satoshis()
            .ok_or(anyhow!("MissingInvoiceAmount"))?;

        // TODO: return fee from create_outgoing_output or even let user supply
        // it/bounds for it
        let fee = match &client_output.output {
            LightningOutputV0::Contract(contract) => {
                let fee_msat = contract
                    .amount
                    .msats
                    .checked_sub(amount_msat)
                    .expect("Contract amount should be greater or equal than invoice amount");
                Amount::from_msats(fee_msat)
            }
            _ => unreachable!("User client will only create contract outputs on spend"),
        };

        let output = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
            vec![ClientOutput {
                output: LightningOutput::V0(client_output.output),
                amounts: client_output.amounts,
            }],
            vec![client_output_sm],
        ));

        let tx = TransactionBuilder::new().with_outputs(output);
        let extra_meta =
            serde_json::to_value(extra_meta).context("Failed to serialize extra meta")?;
        let operation_meta_gen = move |change_range: OutPointRange| LightningOperationMeta {
            variant: LightningOperationMetaVariant::Pay(LightningOperationMetaPay {
                out_point: OutPoint {
                    txid: change_range.txid(),
                    out_idx: 0,
                },
                invoice: invoice.clone(),
                fee,
                change: change_range.into_iter().collect(),
                is_internal_payment,
                contract_id,
                gateway_id: maybe_gateway_id,
            }),
            extra_meta: extra_meta.clone(),
        };

        // Write the new payment index into the database, fail the payment if the commit
        // to the database fails.
        dbtx.commit_tx_result().await?;

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                operation_meta_gen,
                tx,
            )
            .await?;

        let mut event_dbtx = self.client_ctx.module_db().begin_transaction().await;

        self.client_ctx
            .log_event(
                &mut event_dbtx,
                events::SendPaymentEvent {
                    operation_id,
                    amount: Amount::from_msats(amount_msat),
                    fee,
                },
            )
            .await;

        event_dbtx.commit_tx().await;

        Ok(OutgoingLightningPayment {
            payment_type: pay_type,
            contract_id,
            fee,
        })
    }

    pub async fn get_ln_pay_details_for(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<LightningOperationMetaPay> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let LightningOperationMetaVariant::Pay(pay) =
            operation.meta::<LightningOperationMeta>().variant
        else {
            anyhow::bail!("Operation is not a lightning payment")
        };
        Ok(pay)
    }

    pub async fn subscribe_internal_pay(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<InternalPayState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;

        let LightningOperationMetaVariant::Pay(LightningOperationMetaPay {
            out_point: _,
            invoice: _,
            change: _, // FIXME: why isn't this used here?
            is_internal_payment,
            ..
        }) = operation.meta::<LightningOperationMeta>().variant
        else {
            bail!("Operation is not a lightning payment")
        };

        ensure!(
            is_internal_payment,
            "Subscribing to an external LN payment, expected internal LN payment"
        );

        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                yield InternalPayState::Funding;

                let state = loop {
                    match stream.next().await { Some(LightningClientStateMachines::InternalPay(state)) => {
                        match state.state {
                            IncomingSmStates::Preimage(preimage) => break InternalPayState::Preimage(preimage),
                            IncomingSmStates::RefundSubmitted{ out_points, error } => {
                                match client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await {
                                    Ok(()) => break InternalPayState::RefundSuccess { out_points, error },
                                    Err(e) => break InternalPayState::RefundError{ error_message: e.to_string(), error },
                                }
                            },
                            IncomingSmStates::FundingFailed { error } => break InternalPayState::FundingFailed{ error },
                            _ => {}
                        }
                    } _ => {
                        break InternalPayState::UnexpectedError("Unexpected State! Expected an InternalPay state".to_string())
                    }}
                };
                yield state;
            }
        }))
    }

    /// Subscribes to a stream of updates about a particular external Lightning
    /// payment operation specified by the `operation_id`.
    pub async fn subscribe_ln_pay(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<LnPayState>> {
        async fn get_next_pay_state(
            stream: &mut BoxStream<'_, LightningClientStateMachines>,
        ) -> Option<LightningPayStates> {
            match stream.next().await {
                Some(LightningClientStateMachines::LightningPay(state)) => Some(state.state),
                Some(event) => {
                    // nosemgrep: use-err-formatting
                    error!(event = ?event, "Operation is not a lightning payment");
                    debug_assert!(false, "Operation is not a lightning payment: {event:?}");
                    None
                }
                None => None,
            }
        }

        let operation = self.client_ctx.get_operation(operation_id).await?;
        let LightningOperationMetaVariant::Pay(LightningOperationMetaPay {
            out_point: _,
            invoice: _,
            change,
            is_internal_payment,
            ..
        }) = operation.meta::<LightningOperationMeta>().variant
        else {
            bail!("Operation is not a lightning payment")
        };

        ensure!(
            !is_internal_payment,
            "Subscribing to an internal LN payment, expected external LN payment"
        );

        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                let self_ref = client_ctx.self_ref();

                let mut stream = self_ref.notifier.subscribe(operation_id).await;
                let state = get_next_pay_state(&mut stream).await;
                match state {
                    Some(LightningPayStates::CreatedOutgoingLnContract(_)) => {
                        yield LnPayState::Created;
                    }
                    Some(LightningPayStates::FundingRejected) => {
                        yield LnPayState::Canceled;
                        return;
                    }
                    Some(state) => {
                        yield LnPayState::UnexpectedError { error_message: format!("Found unexpected state during lightning payment: {state:?}") };
                        return;
                    }
                    None => {
                        error!("Unexpected end of lightning pay state machine");
                        return;
                    }
                }

                let state = get_next_pay_state(&mut stream).await;
                match state {
                    Some(LightningPayStates::Funded(funded)) => {
                        yield LnPayState::Funded { block_height: funded.timelock }
                    }
                    Some(state) => {
                        yield LnPayState::UnexpectedError { error_message: format!("Found unexpected state during lightning payment: {state:?}") };
                        return;
                    }
                    _ => {
                        error!("Unexpected end of lightning pay state machine");
                        return;
                    }
                }

                let state = get_next_pay_state(&mut stream).await;
                match state {
                    Some(LightningPayStates::Success(preimage)) => {
                        if change.is_empty() {
                            yield LnPayState::Success { preimage };
                        } else {
                            yield LnPayState::AwaitingChange;
                            match client_ctx.await_primary_module_outputs(operation_id, change.clone()).await {
                                Ok(()) => {
                                    yield LnPayState::Success { preimage };
                                }
                                Err(e) => {
                                    yield LnPayState::UnexpectedError { error_message: format!("Error occurred while waiting for the change: {e:?}") };
                                }
                            }
                        }
                    }
                    Some(LightningPayStates::Refund(refund)) => {
                        yield LnPayState::WaitingForRefund {
                            error_reason: refund.error_reason.clone(),
                        };

                        match client_ctx.await_primary_module_outputs(operation_id, refund.out_points).await {
                            Ok(()) => {
                                let gateway_error = GatewayPayError::GatewayInternalError { error_code: Some(500), error_message: refund.error_reason };
                                yield LnPayState::Refunded { gateway_error };
                            }
                            Err(e) => {
                                yield LnPayState::UnexpectedError {
                                    error_message: format!("Error occurred trying to get refund. Refund was not successful: {e:?}"),
                                };
                            }
                        }
                    }
                    Some(state) => {
                        yield LnPayState::UnexpectedError { error_message: format!("Found unexpected state during lightning payment: {state:?}") };
                    }
                    None => {
                        error!("Unexpected end of lightning pay state machine");
                        yield LnPayState::UnexpectedError { error_message: "Unexpected end of lightning pay state machine".to_string() };
                    }
                }
            }
        }))
    }

    /// Scan unspent incoming contracts for a payment hash that matches a
    /// tweaked keys in the `indices` vector
    #[deprecated(since = "0.7.0", note = "Use recurring payment functionality instead")]
    #[allow(deprecated)]
    pub async fn scan_receive_for_user_tweaked<M: Serialize + Send + Sync + Clone>(
        &self,
        key_pair: Keypair,
        indices: Vec<u64>,
        extra_meta: M,
    ) -> Vec<OperationId> {
        let mut claims = Vec::new();
        for i in indices {
            let key_pair_tweaked = tweak_user_secret_key(&self.secp, key_pair, i);
            match self
                .scan_receive_for_user(key_pair_tweaked, extra_meta.clone())
                .await
            {
                Ok(operation_id) => claims.push(operation_id),
                Err(err) => {
                    error!(err = %err.fmt_compact_anyhow(), %i, "Failed to scan tweaked key at index i");
                }
            }
        }

        claims
    }

    /// Scan unspent incoming contracts for a payment hash that matches a public
    /// key and claim the incoming contract
    #[deprecated(since = "0.7.0", note = "Use recurring payment functionality instead")]
    #[allow(deprecated)]
    pub async fn scan_receive_for_user<M: Serialize + Send + Sync>(
        &self,
        key_pair: Keypair,
        extra_meta: M,
    ) -> anyhow::Result<OperationId> {
        let preimage_key: [u8; 33] = key_pair.public_key().serialize();
        let preimage = sha256::Hash::hash(&preimage_key);
        let contract_id = ContractId::from_raw_hash(sha256::Hash::hash(&preimage.to_byte_array()));
        self.claim_funded_incoming_contract(key_pair, contract_id, extra_meta)
            .await
    }

    /// Claim the funded, unspent incoming contract by submitting a transaction
    /// to the federation and awaiting the primary module's outputs
    #[deprecated(since = "0.7.0", note = "Use recurring payment functionality instead")]
    #[allow(deprecated)]
    pub async fn claim_funded_incoming_contract<M: Serialize + Send + Sync>(
        &self,
        key_pair: Keypair,
        contract_id: ContractId,
        extra_meta: M,
    ) -> anyhow::Result<OperationId> {
        let incoming_contract_account = get_incoming_contract(self.module_api.clone(), contract_id)
            .await?
            .ok_or(anyhow!("No contract account found"))
            .with_context(|| format!("No contract found for {contract_id:?}"))?;

        let input = incoming_contract_account.claim();
        let client_input = ClientInput::<LightningInput> {
            input,
            amounts: Amounts::new_bitcoin(incoming_contract_account.amount),
            keys: vec![key_pair],
        };

        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_client_inputs(ClientInputBundle::new_no_sm(vec![client_input])),
        );
        let extra_meta = serde_json::to_value(extra_meta).expect("extra_meta is serializable");
        let operation_meta_gen = move |change_range: OutPointRange| LightningOperationMeta {
            variant: LightningOperationMetaVariant::Claim {
                out_points: change_range.into_iter().collect(),
            },
            extra_meta: extra_meta.clone(),
        };
        let operation_id = OperationId::new_random();
        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                operation_meta_gen,
                tx,
            )
            .await?;
        Ok(operation_id)
    }

    /// Receive over LN with a new invoice
    /// Computes the federation fee receiving `amount` over Lightning would
    /// incur, without submitting anything.
    ///
    /// When the incoming contract is claimed, the client submits a transaction
    /// with a single Lightning input worth the contract amount; the primary
    /// module balances it by minting the change credited to the wallet. This
    /// quotes the fee of that transaction — the Lightning input fee, the mint
    /// output fees, and any sub-denomination dust — via the shared,
    /// module-agnostic fee quote.
    ///
    /// The gateway's off-chain Lightning fee is deliberately excluded: this is
    /// only the fee of the on-federation transaction. For that reason the quote
    /// is taken on `amount` directly (rather than the gateway-reduced contract
    /// amount), and no gateway round-trip is needed.
    pub async fn receive_fee_quote(&self, amount: Amount) -> anyhow::Result<FeeQuote> {
        self.client_ctx
            .fee_quote(
                OperationId::new_random(),
                FeeQuoteRequest {
                    input_amount: Amounts::new_bitcoin(amount),
                    output_amount: Amounts::ZERO,
                    input_fee: Amounts::new_bitcoin(self.cfg.fee_consensus.contract_input),
                    output_fee: Amounts::ZERO,
                },
            )
            .await
    }

    /// Computes the federation fee a `pay` funding an outgoing contract worth
    /// `amount` would incur, without submitting anything.
    ///
    /// When a payment is sent, the client submits a transaction with a single
    /// Lightning output (the outgoing contract) worth `amount`; the primary
    /// module balances it by spending ecash to fund the contract and minting
    /// any change. This quotes the fee of that transaction — the Lightning
    /// output fee, the mint input fees on the funding notes, any mint change
    /// output fees, and sub-denomination dust — via the shared, module-agnostic
    /// fee quote.
    ///
    /// The gateway's off-chain Lightning fee is deliberately excluded: it is
    /// part of the contract `amount` the gateway claims, not the on-federation
    /// transaction fee. So `amount` is the full outgoing contract value.
    pub async fn send_fee_quote(&self, amount: Amount) -> anyhow::Result<FeeQuote> {
        self.client_ctx
            .fee_quote(
                OperationId::new_random(),
                FeeQuoteRequest {
                    input_amount: Amounts::ZERO,
                    output_amount: Amounts::new_bitcoin(amount),
                    input_fee: Amounts::ZERO,
                    output_fee: Amounts::new_bitcoin(self.cfg.fee_consensus.contract_output),
                },
            )
            .await
    }

    pub async fn create_bolt11_invoice<M: Serialize + Send + Sync>(
        &self,
        amount: Amount,
        description: lightning_invoice::Bolt11InvoiceDescription,
        expiry_time: Option<u64>,
        extra_meta: M,
        gateway: Option<LightningGateway>,
    ) -> anyhow::Result<(OperationId, Bolt11Invoice, [u8; 32])> {
        let receiving_key =
            ReceivingKey::Personal(Keypair::new(&self.secp, &mut rand::rngs::OsRng));
        self.create_bolt11_invoice_internal(
            amount,
            description,
            expiry_time,
            receiving_key,
            extra_meta,
            gateway,
        )
        .await
    }

    /// Receive over LN with a new invoice for another user, tweaking their key
    /// by the given index
    #[allow(clippy::too_many_arguments)]
    pub async fn create_bolt11_invoice_for_user_tweaked<M: Serialize + Send + Sync>(
        &self,
        amount: Amount,
        description: lightning_invoice::Bolt11InvoiceDescription,
        expiry_time: Option<u64>,
        user_key: PublicKey,
        index: u64,
        extra_meta: M,
        gateway: Option<LightningGateway>,
    ) -> anyhow::Result<(OperationId, Bolt11Invoice, [u8; 32])> {
        let tweaked_key = tweak_user_key(&self.secp, user_key, index);
        self.create_bolt11_invoice_for_user(
            amount,
            description,
            expiry_time,
            tweaked_key,
            extra_meta,
            gateway,
        )
        .await
    }

    /// Receive over LN with a new invoice for another user
    pub async fn create_bolt11_invoice_for_user<M: Serialize + Send + Sync>(
        &self,
        amount: Amount,
        description: lightning_invoice::Bolt11InvoiceDescription,
        expiry_time: Option<u64>,
        user_key: PublicKey,
        extra_meta: M,
        gateway: Option<LightningGateway>,
    ) -> anyhow::Result<(OperationId, Bolt11Invoice, [u8; 32])> {
        let receiving_key = ReceivingKey::External(user_key);
        self.create_bolt11_invoice_internal(
            amount,
            description,
            expiry_time,
            receiving_key,
            extra_meta,
            gateway,
        )
        .await
    }

    /// Receive over LN with a new invoice
    async fn create_bolt11_invoice_internal<M: Serialize + Send + Sync>(
        &self,
        amount: Amount,
        description: lightning_invoice::Bolt11InvoiceDescription,
        expiry_time: Option<u64>,
        receiving_key: ReceivingKey,
        extra_meta: M,
        gateway: Option<LightningGateway>,
    ) -> anyhow::Result<(OperationId, Bolt11Invoice, [u8; 32])> {
        let gateway_id = gateway.as_ref().map(|g| g.gateway_id);
        let (src_node_id, short_channel_id, route_hints) = if let Some(current_gateway) = gateway {
            (
                current_gateway.node_pub_key,
                current_gateway.federation_index,
                current_gateway.route_hints,
            )
        } else {
            // If no gateway is provided, this is assumed to be an internal payment.
            let markers = self.client_ctx.get_internal_payment_markers()?;
            (markers.0, markers.1, vec![])
        };

        debug!(target: LOG_CLIENT_MODULE_LN, ?gateway_id, %amount, "Selected LN gateway for invoice generation");

        let (operation_id, invoice, output, preimage) = self.create_lightning_receive_output(
            amount,
            description,
            receiving_key,
            rand::rngs::OsRng,
            expiry_time,
            src_node_id,
            short_channel_id,
            &route_hints,
            self.cfg.network.0,
        )?;

        let tx =
            TransactionBuilder::new().with_outputs(self.client_ctx.make_client_outputs(output));
        let extra_meta = serde_json::to_value(extra_meta).expect("extra_meta is serializable");
        let operation_meta_gen = {
            let invoice = invoice.clone();
            move |change_range: OutPointRange| LightningOperationMeta {
                variant: LightningOperationMetaVariant::Receive {
                    out_point: OutPoint {
                        txid: change_range.txid(),
                        out_idx: 0,
                    },
                    invoice: invoice.clone(),
                    gateway_id,
                },
                extra_meta: extra_meta.clone(),
            }
        };
        let change_range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                operation_meta_gen,
                tx,
            )
            .await?;

        debug!(target: LOG_CLIENT_MODULE_LN, txid = ?change_range.txid(), ?operation_id, "Waiting for LN invoice to be confirmed");

        // Wait for the transaction to be accepted by the federation, otherwise the
        // invoice will not be able to be paid
        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(change_range.txid())
            .await
            .map_err(|e| anyhow!("Offer transaction was not accepted: {e:?}"))?;

        debug!(target: LOG_CLIENT_MODULE_LN, %invoice, "Invoice confirmed");

        Ok((operation_id, invoice, preimage))
    }

    /// Starts a new state machine that retries claiming a previously paid
    /// invoice.
    ///
    /// This is a local state-history recovery tool: it requires the client DB
    /// to still contain a historical `SubmittedOffer` or `ConfirmedInvoice`
    /// state for the original operation. It does not recover seed-only
    /// restores where that local state-machine history is unavailable.
    ///
    /// Repeated calls start independent reclaim attempts. This is intentional:
    /// this is a manual break-glass recovery path, and concurrent attempts race
    /// through the normal federation transaction validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the original operation is not a reclaimable
    /// lightning receive, if it is still active, or if the original receiving
    /// key cannot be recovered from state history.
    pub async fn reclaim_ln_receive(
        &self,
        original_operation_id: OperationId,
    ) -> anyhow::Result<OperationId> {
        let operation = self.client_ctx.get_operation(original_operation_id).await?;
        let LightningOperationMeta {
            variant,
            extra_meta,
        } = operation
            .try_meta::<LightningOperationMeta>()
            .context("Invalid lightning operation metadata")?;

        let (invoice, gateway_id) = match variant {
            LightningOperationMetaVariant::Receive {
                invoice,
                gateway_id,
                ..
            } => (invoice, gateway_id),
            LightningOperationMetaVariant::RecurringPaymentReceive(meta) => (meta.invoice, None),
            _ => bail!("Operation is not a reclaimable lightning receive"),
        };

        let active_states = self
            .client_ctx
            .get_own_operation_active_states(original_operation_id)
            .await;
        ensure!(
            !active_states
                .iter()
                .any(|(state, _)| matches!(state, LightningClientStateMachines::Receive(_))),
            "Cannot reclaim an active lightning receive"
        );

        let inactive_states = self
            .client_ctx
            .get_own_operation_inactive_states(original_operation_id)
            .await;

        let receiving_key = inactive_states
            .iter()
            .find_map(|(state, _)| Self::ln_receive_key_from_state(state))
            .ok_or_else(|| {
                anyhow!("Cannot reclaim LN receive because the original receive key is unavailable")
            })?;
        let db = self.client_ctx.module_db();
        let mut dbtx = db.begin_transaction().await;
        let reclaim_operation_id = OperationId::new_random();
        let operation_meta = LightningOperationMeta {
            variant: LightningOperationMetaVariant::ReceiveReclaim {
                original_operation_id,
                invoice: invoice.clone(),
                gateway_id,
            },
            extra_meta,
        };
        let state = LightningClientStateMachines::Receive(LightningReceiveStateMachine {
            operation_id: reclaim_operation_id,
            state: LightningReceiveStates::ConfirmedInvoice(LightningReceiveConfirmedInvoice {
                invoice,
                receiving_key,
            }),
        });

        self.client_ctx
            .manual_operation_start_dbtx(
                &mut dbtx.to_ref_nc(),
                reclaim_operation_id,
                LightningCommonInit::KIND.as_str(),
                operation_meta,
                vec![self.client_ctx.make_dyn_state(state)],
            )
            .await?;

        dbtx.commit_tx().await;

        Ok(reclaim_operation_id)
    }

    fn ln_receive_key_from_state(state: &LightningClientStateMachines) -> Option<ReceivingKey> {
        match state {
            LightningClientStateMachines::Receive(receive) => match &receive.state {
                LightningReceiveStates::SubmittedOffer(submitted_offer) => {
                    Some(submitted_offer.receiving_key)
                }
                LightningReceiveStates::ConfirmedInvoice(confirmed_invoice) => {
                    Some(confirmed_invoice.receiving_key)
                }
                LightningReceiveStates::Canceled(_)
                | LightningReceiveStates::Funded(_)
                | LightningReceiveStates::Success(_) => None,
            },
            LightningClientStateMachines::InternalPay(_)
            | LightningClientStateMachines::LightningPay(_) => None,
        }
    }

    #[deprecated(since = "0.7.0", note = "Use recurring payment functionality instead")]
    #[allow(deprecated)]
    pub async fn subscribe_ln_claim(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<LnReceiveState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let LightningOperationMetaVariant::Claim { out_points } =
            operation.meta::<LightningOperationMeta>().variant
        else {
            bail!("Operation is not a lightning claim")
        };

        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                yield LnReceiveState::AwaitingFunds;

                if client_ctx.await_primary_module_outputs(operation_id, out_points).await.is_ok() {
                    yield LnReceiveState::Claimed;
                } else {
                    yield LnReceiveState::Canceled { reason: LightningReceiveError::ClaimRejected }
                }
            }
        }))
    }

    pub async fn subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<LnReceiveState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let (invoice, tx_accepted_future) = match operation.meta::<LightningOperationMeta>().variant
        {
            LightningOperationMetaVariant::Receive {
                out_point, invoice, ..
            } => {
                let tx_accepted_future = self
                    .client_ctx
                    .transaction_updates(operation_id)
                    .await
                    .await_tx_accepted(out_point.txid);
                (invoice, Some(tx_accepted_future))
            }
            LightningOperationMetaVariant::ReceiveReclaim { invoice, .. } => (invoice, None),
            _ => bail!("Operation is not a lightning receive"),
        };

        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {

                let self_ref = client_ctx.self_ref();

                yield LnReceiveState::Created;

                let tx_rejected = match tx_accepted_future {
                    Some(tx_accepted_future) => tx_accepted_future.await.is_err(),
                    None => false,
                };
                if tx_rejected {
                    yield LnReceiveState::Canceled { reason: LightningReceiveError::Rejected };
                    return;
                }
                yield LnReceiveState::WaitingForPayment { invoice: invoice.to_string(), timeout: invoice.expiry_time() };

                match self_ref.await_receive_success(operation_id).await {
                    Ok(()) => {

                        yield LnReceiveState::Funded;

                        match self_ref.await_claim_acceptance(operation_id).await {
                            Ok(out_points) => {
                                yield LnReceiveState::AwaitingFunds;

                                if client_ctx.await_primary_module_outputs(operation_id, out_points).await.is_ok() {
                                    yield LnReceiveState::Claimed;
                                    return;
                                }

                                // The claim transaction was accepted, but its outputs were not
                                // confirmed by the primary module. The incoming contract is already
                                // spent, so this is not reclaimable as a rejected claim.
                                yield LnReceiveState::Canceled { reason: LightningReceiveError::Rejected };
                            }
                            Err(e) => {
                                yield LnReceiveState::Canceled { reason: e };
                            }
                        }
                    }
                    Err(e) => {
                        yield LnReceiveState::Canceled { reason: e };
                    }
                }
            }
        }))
    }

    /// Returns a gateway to be used for a lightning operation. If
    /// `force_internal` is true and no `gateway_id` is specified, no
    /// gateway will be selected.
    pub async fn get_gateway(
        &self,
        gateway_id: Option<secp256k1::PublicKey>,
        force_internal: bool,
    ) -> anyhow::Result<Option<LightningGateway>> {
        match gateway_id {
            Some(gateway_id) => {
                if let Some(gw) = self.select_gateway(&gateway_id).await {
                    Ok(Some(gw))
                } else {
                    // Refresh the gateway cache in case the target gateway was registered since the
                    // last update.
                    self.update_gateway_cache().await?;
                    Ok(self.select_gateway(&gateway_id).await)
                }
            }
            None if !force_internal => {
                // Refresh the gateway cache to find a random gateway to select from.
                self.update_gateway_cache().await?;
                let gateways = self.list_gateways().await;
                let gw = gateways.into_iter().choose(&mut OsRng).map(|gw| gw.info);
                if let Some(gw) = gw {
                    let gw_id = gw.gateway_id;
                    info!(%gw_id, "Using random gateway");
                    Ok(Some(gw))
                } else {
                    Err(anyhow!(
                        "No gateways exist in gateway cache and `force_internal` is false"
                    ))
                }
            }
            None => Ok(None),
        }
    }

    /// Subscribes to either a internal or external lightning payment and
    /// returns `LightningPaymentOutcome` that indicates if the payment was
    /// successful or not.
    pub async fn await_outgoing_payment(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<LightningPaymentOutcome> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let variant = operation.meta::<LightningOperationMeta>().variant;
        let LightningOperationMetaVariant::Pay(LightningOperationMetaPay {
            is_internal_payment,
            ..
        }) = variant
        else {
            bail!("Operation is not a lightning payment")
        };

        let mut final_state = None;

        // First check if the outgoing payment is an internal payment
        if is_internal_payment {
            let updates = self.subscribe_internal_pay(operation_id).await?;
            let mut stream = updates.into_stream();
            while let Some(update) = stream.next().await {
                match update {
                    InternalPayState::Preimage(preimage) => {
                        final_state = Some(LightningPaymentOutcome::Success {
                            preimage: preimage.0.consensus_encode_to_hex(),
                        });
                    }
                    InternalPayState::RefundSuccess {
                        out_points: _,
                        error,
                    } => {
                        final_state = Some(LightningPaymentOutcome::Failure {
                            error_message: format!("LNv1 internal payment was refunded: {error:?}"),
                        });
                    }
                    InternalPayState::FundingFailed { error } => {
                        final_state = Some(LightningPaymentOutcome::Failure {
                            error_message: format!(
                                "LNv1 internal payment funding failed: {error:?}"
                            ),
                        });
                    }
                    InternalPayState::RefundError {
                        error_message,
                        error,
                    } => {
                        final_state = Some(LightningPaymentOutcome::Failure {
                            error_message: format!(
                                "LNv1 refund failed: {error_message}: {error:?}"
                            ),
                        });
                    }
                    InternalPayState::UnexpectedError(error) => {
                        final_state = Some(LightningPaymentOutcome::Failure {
                            error_message: error,
                        });
                    }
                    InternalPayState::Funding => {}
                }
            }
        } else {
            let updates = self.subscribe_ln_pay(operation_id).await?;
            let mut stream = updates.into_stream();
            while let Some(update) = stream.next().await {
                match update {
                    LnPayState::Success { preimage } => {
                        final_state = Some(LightningPaymentOutcome::Success { preimage });
                    }
                    LnPayState::Refunded { gateway_error } => {
                        final_state = Some(LightningPaymentOutcome::Failure {
                            error_message: format!(
                                "LNv1 external payment was refunded: {gateway_error:?}"
                            ),
                        });
                    }
                    LnPayState::UnexpectedError { error_message } => {
                        final_state = Some(LightningPaymentOutcome::Failure { error_message });
                    }
                    _ => {}
                }
            }
        }

        final_state.ok_or(anyhow!(
            "Internal or external outgoing lightning payment did not reach a final state"
        ))
    }
}

// TODO: move to appropriate module (cli?)
// some refactoring here needed
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PayInvoiceResponse {
    operation_id: OperationId,
    contract_id: ContractId,
    preimage: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum LightningClientStateMachines {
    InternalPay(IncomingStateMachine),
    LightningPay(LightningPayStateMachine),
    Receive(LightningReceiveStateMachine),
}

impl IntoDynInstance for LightningClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for LightningClientStateMachines {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            LightningClientStateMachines::InternalPay(internal_pay_state) => {
                sm_enum_variant_translation!(
                    internal_pay_state.transitions(context, global_context),
                    LightningClientStateMachines::InternalPay
                )
            }
            LightningClientStateMachines::LightningPay(lightning_pay_state) => {
                sm_enum_variant_translation!(
                    lightning_pay_state.transitions(context, global_context),
                    LightningClientStateMachines::LightningPay
                )
            }
            LightningClientStateMachines::Receive(receive_state) => {
                sm_enum_variant_translation!(
                    receive_state.transitions(context, global_context),
                    LightningClientStateMachines::Receive
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            LightningClientStateMachines::InternalPay(internal_pay_state) => {
                internal_pay_state.operation_id()
            }
            LightningClientStateMachines::LightningPay(lightning_pay_state) => {
                lightning_pay_state.operation_id()
            }
            LightningClientStateMachines::Receive(receive_state) => receive_state.operation_id(),
        }
    }
}

async fn fetch_and_validate_offer(
    module_api: &DynModuleApi,
    payment_hash: sha256::Hash,
    amount_msat: Amount,
) -> anyhow::Result<IncomingContractOffer, IncomingSmError> {
    let offer = timeout(Duration::from_secs(5), module_api.fetch_offer(payment_hash))
        .await
        .map_err(|_| IncomingSmError::TimeoutFetchingOffer { payment_hash })?
        .map_err(|e| IncomingSmError::FetchContractError {
            payment_hash,
            error_message: e.to_string(),
        })?;

    if offer.amount > amount_msat {
        return Err(IncomingSmError::ViolatedFeePolicy {
            offer_amount: offer.amount,
            payment_amount: amount_msat,
        });
    }
    if offer.hash != payment_hash {
        return Err(IncomingSmError::InvalidOffer {
            offer_hash: offer.hash,
            payment_hash,
        });
    }
    Ok(offer)
}

pub async fn create_incoming_contract_output(
    module_api: &DynModuleApi,
    payment_hash: sha256::Hash,
    amount_msat: Amount,
    redeem_key: &Keypair,
) -> Result<(LightningOutputV0, Amount, ContractId), IncomingSmError> {
    let offer = fetch_and_validate_offer(module_api, payment_hash, amount_msat).await?;
    let our_pub_key = secp256k1::PublicKey::from_keypair(redeem_key);
    let contract = IncomingContract {
        hash: offer.hash,
        encrypted_preimage: offer.encrypted_preimage.clone(),
        decrypted_preimage: DecryptedPreimage::Pending,
        gateway_key: our_pub_key,
    };
    let contract_id = contract.contract_id();
    let incoming_output = LightningOutputV0::Contract(ContractOutput {
        amount: offer.amount,
        contract: Contract::Incoming(contract),
    });

    Ok((incoming_output, offer.amount, contract_id))
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingLightningPayment {
    pub payment_type: PayType,
    pub contract_id: ContractId,
    pub fee: Amount,
}

async fn set_payment_result(
    dbtx: &mut DatabaseTransaction<'_>,
    payment_hash: sha256::Hash,
    payment_type: PayType,
    contract_id: ContractId,
    fee: Amount,
) {
    if let Some(mut payment_result) = dbtx.get_value(&PaymentResultKey { payment_hash }).await {
        payment_result.completed_payment = Some(OutgoingLightningPayment {
            payment_type,
            contract_id,
            fee,
        });
        dbtx.insert_entry(&PaymentResultKey { payment_hash }, &payment_result)
            .await;
    }
}

/// Tweak a user key with an index, this is used to generate a new key for each
/// invoice. This is done to not be able to link invoices to the same user.
pub fn tweak_user_key<Ctx: Verification + Signing>(
    secp: &Secp256k1<Ctx>,
    user_key: PublicKey,
    index: u64,
) -> PublicKey {
    let mut hasher = HmacEngine::<sha256::Hash>::new(&user_key.serialize()[..]);
    hasher.input(&index.to_be_bytes());
    let tweak = Hmac::from_engine(hasher).to_byte_array();

    user_key
        .add_exp_tweak(secp, &Scalar::from_be_bytes(tweak).expect("can't fail"))
        .expect("tweak is always 32 bytes, other failure modes are negligible")
}

/// Tweak a secret key with an index, this is used to claim an unspent incoming
/// contract.
fn tweak_user_secret_key<Ctx: Verification + Signing>(
    secp: &Secp256k1<Ctx>,
    key_pair: Keypair,
    index: u64,
) -> Keypair {
    let public_key = key_pair.public_key();
    let mut hasher = HmacEngine::<sha256::Hash>::new(&public_key.serialize()[..]);
    hasher.input(&index.to_be_bytes());
    let tweak = Hmac::from_engine(hasher).to_byte_array();

    let secret_key = key_pair.secret_key();
    let sk_tweaked = secret_key
        .add_tweak(&Scalar::from_be_bytes(tweak).expect("Cant fail"))
        .expect("Cant fail");
    Keypair::from_secret_key(secp, &sk_tweaked)
}

/// Get LN invoice with given settings
pub async fn get_invoice(
    info: &str,
    amount: Option<Amount>,
    lnurl_comment: Option<String>,
) -> anyhow::Result<Bolt11Invoice> {
    let info = info.trim();
    match lightning_invoice::Bolt11Invoice::from_str(info) {
        Ok(invoice) => {
            debug!("Parsed parameter as bolt11 invoice: {invoice}");
            match (invoice.amount_milli_satoshis(), amount) {
                (Some(_), Some(_)) => {
                    bail!("Amount specified in both invoice and command line")
                }
                (None, _) => {
                    bail!("We don't support invoices without an amount")
                }
                _ => {}
            }
            Ok(invoice)
        }
        Err(e) => {
            let lnurl = if info.to_lowercase().starts_with("lnurl") {
                lnurl::lnurl::LnUrl::from_str(info)?
            } else if info.contains('@') {
                lnurl::lightning_address::LightningAddress::from_str(info)?.lnurl()
            } else {
                bail!("Invalid invoice or lnurl: {e:?}");
            };
            debug!("Parsed parameter as lnurl: {lnurl:?}");
            let amount = amount.context("When using a lnurl, an amount must be specified")?;
            let async_client = lnurl::AsyncClient::from_client(reqwest::Client::new());
            let response = async_client.make_request(&lnurl.url).await?;
            match response {
                lnurl::LnUrlResponse::LnUrlPayResponse(response) => {
                    let invoice = async_client
                        .get_invoice(&response, amount.msats, None, lnurl_comment.as_deref())
                        .await?;
                    let invoice = Bolt11Invoice::from_str(invoice.invoice())?;
                    let invoice_amount = invoice.amount_milli_satoshis();
                    ensure!(
                        invoice_amount == Some(amount.msats),
                        "the amount generated by the lnurl ({invoice_amount:?}) is different from the requested amount ({amount}), try again using a different amount"
                    );
                    Ok(invoice)
                }
                other => {
                    bail!("Unexpected response from lnurl: {other:?}");
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LightningClientContext {
    pub ln_decoder: Decoder,
    pub redeem_key: Keypair,
    pub gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
    /// Set to `None` for the gateway since it does not emit the client events.
    pub client_ctx: Option<ClientContext<LightningClientModule>>,
}

impl fedimint_client_module::sm::Context for LightningClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[apply(async_trait_maybe_send!)]
pub trait GatewayConnection: std::fmt::Debug {
    // Ping gateway endpoint to verify that it is available before locking funds in
    // OutgoingContract
    async fn verify_gateway_availability(
        &self,
        gateway: &LightningGateway,
    ) -> Result<(), ServerError>;

    // Request the gateway to pay a BOLT11 invoice
    async fn pay_invoice(
        &self,
        gateway: LightningGateway,
        payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError>;
}

#[derive(Debug)]
pub struct RealGatewayConnection {
    pub api: GatewayApi,
}

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for RealGatewayConnection {
    async fn verify_gateway_availability(
        &self,
        gateway: &LightningGateway,
    ) -> Result<(), ServerError> {
        self.api
            .request::<PublicKey, serde_json::Value>(
                &gateway.api,
                Method::GET,
                GET_GATEWAY_ID_ENDPOINT,
                None,
            )
            .await?;
        Ok(())
    }

    async fn pay_invoice(
        &self,
        gateway: LightningGateway,
        payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError> {
        let preimage: String = self
            .api
            .request(
                &gateway.api,
                Method::POST,
                PAY_INVOICE_ENDPOINT,
                Some(payload),
            )
            .await
            .map_err(|e| GatewayPayError::GatewayInternalError {
                error_code: None,
                error_message: e.to_string(),
            })?;
        let length = preimage.len();
        Ok(preimage[1..length - 1].to_string())
    }
}

#[derive(Debug)]
pub struct MockGatewayConnection;

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for MockGatewayConnection {
    async fn verify_gateway_availability(
        &self,
        _gateway: &LightningGateway,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    async fn pay_invoice(
        &self,
        _gateway: LightningGateway,
        _payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError> {
        // Just return a fake preimage to indicate success
        Ok("00000000".to_string())
    }
}
