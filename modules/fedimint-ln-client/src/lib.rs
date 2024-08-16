#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::wildcard_imports)]

pub mod api;
#[cfg(feature = "cli")]
pub mod cli;
pub mod db;
pub mod incoming;
pub mod pay;
pub mod receive;

use std::collections::BTreeMap;
use std::iter::once;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, format_err, Context};
use api::LnFederationApi;
use async_stream::{stream, try_stream};
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::key::KeyPair;
use bitcoin::Network;
use db::{
    DbKeyPrefix, LightningGatewayKey, LightningGatewayKeyPrefix, PaymentResult, PaymentResultKey,
};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::db::{migrate_state, ClientMigrationFn};
use fedimint_client::derivable_secret::ChildId;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::{timeout, MaybeSend, MaybeSync};
use fedimint_core::util::update_merge::UpdateMerge;
use fedimint_core::util::{backoff_util, retry, BoxStream};
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_pair_items, runtime, Amount, OutPoint, TransactionId,
};
use fedimint_ln_common::config::{FeeToAmount, LightningClientConfig};
use fedimint_ln_common::contracts::incoming::{IncomingContract, IncomingContractOffer};
use fedimint_ln_common::contracts::outgoing::{
    OutgoingContract, OutgoingContractAccount, OutgoingContractData,
};
use fedimint_ln_common::contracts::{
    Contract, ContractId, DecryptedPreimage, EncryptedPreimage, IdentifiableContract, Preimage,
    PreimageKey,
};
use fedimint_ln_common::{
    ContractOutput, LightningCommonInit, LightningGateway, LightningGatewayAnnouncement,
    LightningGatewayRegistration, LightningInput, LightningModuleTypes, LightningOutput,
    LightningOutputV0,
};
use fedimint_logging::LOG_CLIENT_MODULE_LN;
use futures::{Future, StreamExt};
use incoming::IncomingSmError;
use lightning_invoice::{
    Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret, RouteHint, RouteHintHop, RoutingFees,
};
use pay::PayInvoicePayload;
use rand::rngs::OsRng;
use rand::seq::IteratorRandom as _;
use rand::{CryptoRng, Rng, RngCore};
use secp256k1::{All, PublicKey, Scalar, Secp256k1, Signing, ThirtyTwoByteHash, Verification};
use serde::{Deserialize, Serialize};
use serde_json::json;
use strum::IntoEnumIterator;
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
    get_incoming_contract, LightningReceiveError, LightningReceiveStateMachine,
    LightningReceiveStates, LightningReceiveSubmittedOffer,
};

/// Number of blocks until outgoing lightning contracts times out and user
/// client can get refund
const OUTGOING_LN_CONTRACT_TIMELOCK: u64 = 500;

// 24 hours. Many wallets default to 1 hour, but it's a bad user experience if
// invoices expire too quickly
const DEFAULT_INVOICE_EXPIRY_TIME: Duration = Duration::from_secs(60 * 60 * 24);

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
    Personal(KeyPair),
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
    markers: (secp256k1::PublicKey, u64),
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
            == Some((gateway.node_pub_key, gateway.mint_channel_id))
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightningOperationMetaVariant {
    Pay(LightningOperationMetaPay),
    Receive {
        out_point: OutPoint,
        invoice: Bolt11Invoice,
        gateway_id: Option<secp256k1::PublicKey>,
    },
    Claim {
        out_points: Vec<OutPoint>,
    },
}

#[derive(Debug, Clone)]
pub struct LightningClientInit {
    pub gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
}

impl Default for LightningClientInit {
    fn default() -> Self {
        LightningClientInit {
            gateway_conn: Arc::new(RealGatewayConnection::default()),
        }
    }
}

impl ModuleInit for LightningClientInit {
    type Common = LightningCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(4);

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
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for LightningClientInit {
    type Module = LightningClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(LightningClientModule::new(args, self.gateway_conn.clone()).await?)
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientMigrationFn> {
        let mut migrations: BTreeMap<DatabaseVersion, ClientMigrationFn> = BTreeMap::new();
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
}

/// Client side lightning module
///
/// Note that lightning gateways use a different version
/// of client side module.
#[derive(Debug)]
pub struct LightningClientModule {
    pub cfg: LightningClientConfig,
    notifier: ModuleNotifier<LightningClientStateMachines>,
    redeem_key: KeyPair,
    secp: Secp256k1<All>,
    module_api: DynModuleApi,
    preimage_auth: KeyPair,
    client_ctx: ClientContext<Self>,
    update_gateway_cache_merge: UpdateMerge,
    gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
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
        }
    }

    fn input_fee(&self, _input: &<Self::Common as ModuleCommon>::Input) -> Option<Amount> {
        Some(self.cfg.fee_consensus.contract_input)
    }

    fn output_fee(&self, output: &<Self::Common as ModuleCommon>::Output) -> Option<Amount> {
        match output.maybe_v0_ref()? {
            LightningOutputV0::Contract(_) => Some(self.cfg.fee_consensus.contract_output),
            LightningOutputV0::Offer(_) | LightningOutputV0::CancelOutgoing { .. } => {
                Some(Amount::ZERO)
            }
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
                                &lightning_invoice::Description::new(req.description)?,
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
                "subscribe_ln_pay" => {
                    let req: SubscribeLnPayRequest = serde_json::from_value(payload)?;
                    for await state in self.subscribe_ln_pay(req.operation_id).await?.into_stream() {
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
                _ => {
                    Err(anyhow::format_err!("Unknown method: {}", method))?;
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
struct SubscribeLnReceiveRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct GetGatewayRequest {
    gateway_id: Option<secp256k1::PublicKey>,
    force_internal: bool,
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
    async fn new(
        args: &ClientModuleInitArgs<LightningClientInit>,
        gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
    ) -> anyhow::Result<LightningClientModule> {
        let secp = Secp256k1::new();
        let ln_module = LightningClientModule {
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            redeem_key: args
                .module_root_secret()
                .child_key(ChildId(LightningChildKeys::RedeemKey as u64))
                .to_secp_key(&secp),
            module_api: args.module_api().clone(),
            preimage_auth: args
                .module_root_secret()
                .child_key(ChildId(LightningChildKeys::PreimageAuthentication as u64))
                .to_secp_key(&secp),
            secp,
            client_ctx: args.context(),
            update_gateway_cache_merge: UpdateMerge::default(),
            gateway_conn: gateway_conn.clone(),
        };

        // Only initialize the gateway cache if it is empty
        let gateways = ln_module.list_gateways().await;
        if gateways.is_empty() {
            ln_module.update_gateway_cache().await?;
        }

        Ok(ln_module)
    }

    async fn get_prev_payment_result(
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
        ClientOutput<LightningOutputV0, LightningClientStateMachines>,
        ContractId,
    )> {
        let federation_currency: Currency = self.cfg.network.into();
        let invoice_currency = invoice.currency();
        ensure!(
            federation_currency == invoice_currency,
            "Invalid invoice currency: expected={:?}, got={:?}",
            federation_currency,
            invoice_currency
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
        let absolute_timelock = consensus_count + OUTGOING_LN_CONTRACT_TIMELOCK - 1;

        // Compute amount to lock in the outgoing contract
        let invoice_amount = Amount::from_msats(
            invoice
                .amount_milli_satoshis()
                .context("MissingInvoiceAmount")?,
        );

        let gateway_fee = gateway.fees.to_amount(&invoice_amount);
        let contract_amount = invoice_amount + gateway_fee;

        let user_sk = KeyPair::new(&self.secp, &mut rng);

        let preimage_auth = self.get_preimage_authentication(invoice.payment_hash());
        let payment_hash = *invoice.payment_hash();
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
        let sm_gen = Arc::new(move |funding_txid: TransactionId, _input_idx: u64| {
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
                            funding_txid,
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
                amount: contract_amount,
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
        ClientOutput<LightningOutputV0, LightningClientStateMachines>,
        ContractId,
    )> {
        let payment_hash = invoice.payment_hash();
        let invoice_amount = Amount {
            msats: invoice
                .amount_milli_satoshis()
                .ok_or(IncomingSmError::AmountError {
                    invoice: invoice.clone(),
                })?,
        };

        let (incoming_output, amount, contract_id) = create_incoming_contract_output(
            &self.module_api,
            *payment_hash,
            invoice_amount,
            self.redeem_key,
        )
        .await?;

        let client_output = ClientOutput::<LightningOutputV0, LightningClientStateMachines> {
            output: incoming_output,
            amount,
            state_machines: Arc::new(move |txid, _| {
                vec![LightningClientStateMachines::InternalPay(
                    IncomingStateMachine {
                        common: IncomingSmCommon {
                            operation_id,
                            contract_id,
                            payment_hash: *invoice.payment_hash(),
                        },
                        state: IncomingSmStates::FundingOffer(FundingOfferState { txid }),
                    },
                )]
            }),
        };

        Ok((client_output, contract_id))
    }

    /// Returns a bool indicating if it was an external receive
    async fn await_receive_success(
        &self,
        operation_id: OperationId,
    ) -> Result<bool, LightningReceiveError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(LightningClientStateMachines::Receive(state)) => match state.state {
                    LightningReceiveStates::Funded(_) => return Ok(false),
                    LightningReceiveStates::Success(outpoints) => return Ok(outpoints.is_empty()), /* if the outpoints are empty, it was an external receive */
                    LightningReceiveStates::Canceled(e) => {
                        return Err(e);
                    }
                    _ => {}
                },
                Some(_) | None => {}
            }
        }
    }

    async fn await_claim_acceptance(
        &self,
        operation_id: OperationId,
    ) -> Result<Vec<OutPoint>, LightningReceiveError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(LightningClientStateMachines::Receive(state)) => match state.state {
                    LightningReceiveStates::Success(out_points) => return Ok(out_points),
                    LightningReceiveStates::Canceled(e) => {
                        return Err(e);
                    }
                    _ => {}
                },
                Some(_) | None => {}
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn create_lightning_receive_output<'a>(
        &'a self,
        amount: Amount,
        description: lightning_invoice::Bolt11InvoiceDescription<'a>,
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
        ClientOutput<LightningOutput, LightningClientStateMachines>,
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
            .payment_secret(PaymentSecret(rng.gen()))
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
            .build_signed(|hash| self.secp.sign_ecdsa_recoverable(hash, &node_secret_key))?;

        let operation_id = OperationId(invoice.payment_hash().to_byte_array());

        let sm_invoice = invoice.clone();
        let sm_gen = Arc::new(move |txid: TransactionId, _input_idx: u64| {
            vec![LightningClientStateMachines::Receive(
                LightningReceiveStateMachine {
                    operation_id,
                    state: LightningReceiveStates::SubmittedOffer(LightningReceiveSubmittedOffer {
                        offer_txid: txid,
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
            ClientOutput {
                output: ln_output,
                amount: Amount::ZERO,
                state_machines: sm_gen,
            },
            preimage.into_32(),
        ))
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
        gateways.into_iter().find(|g| g.gateway_id == *gateway_id)
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
        const EMPTY_GATEWAY_SLEEP: Duration = Duration::from_secs(10 * 60);

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

        let (pay_type, client_output, contract_id) = if is_internal_payment {
            let (output, contract_id) = self
                .create_incoming_output(operation_id, invoice.clone())
                .await?;
            (PayType::Internal(operation_id), output, contract_id)
        } else {
            let gateway = maybe_gateway.context(PayBolt11InvoiceError::NoLnGatewayAvailable)?;
            let (output, contract_id) = self
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
            (PayType::Lightning(operation_id), output, contract_id)
        };

        // Verify that no other outgoing contract exists or the value is empty
        if let Ok(Some(contract)) = self.module_api.fetch_contract(contract_id).await {
            if contract.amount.msats != 0 {
                bail!(PayBolt11InvoiceError::FundedContractAlreadyExists { contract_id });
            }
        }

        // TODO: return fee from create_outgoing_output or even let user supply
        // it/bounds for it
        let fee = match &client_output.output {
            LightningOutputV0::Contract(contract) => {
                let fee_msat = contract
                    .amount
                    .msats
                    .checked_sub(
                        invoice
                            .amount_milli_satoshis()
                            .ok_or(anyhow!("MissingInvoiceAmount"))?,
                    )
                    .expect("Contract amount should be greater or equal than invoice amount");
                Amount::from_msats(fee_msat)
            }
            _ => unreachable!("User client will only create contract outputs on spend"),
        };

        let output = self.client_ctx.make_client_output(ClientOutput {
            output: LightningOutput::V0(client_output.output),
            amount: client_output.amount,
            state_machines: client_output.state_machines,
        });

        let tx = TransactionBuilder::new().with_output(output);
        let extra_meta =
            serde_json::to_value(extra_meta).context("Failed to serialize extra meta")?;
        let operation_meta_gen = |txid, change| LightningOperationMeta {
            variant: LightningOperationMetaVariant::Pay(LightningOperationMetaPay {
                out_point: OutPoint { txid, out_idx: 0 },
                invoice: invoice.clone(),
                fee,
                change,
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
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, || {
            stream! {
                yield InternalPayState::Funding;

                let state = loop {
                    if let Some(LightningClientStateMachines::InternalPay(state)) = stream.next().await {
                        match state.state {
                            IncomingSmStates::Preimage(preimage) => break InternalPayState::Preimage(preimage),
                            IncomingSmStates::RefundSubmitted{ out_points, error } => {
                                match client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await {
                                    Ok(_) => break InternalPayState::RefundSuccess { out_points, error },
                                    Err(e) => break InternalPayState::RefundError{ error_message: e.to_string(), error },
                                }
                            },
                            IncomingSmStates::FundingFailed { error } => break InternalPayState::FundingFailed{ error },
                            _ => {}
                        }
                    } else {
                        break InternalPayState::UnexpectedError("Unexpected State! Expected an InternalPay state".to_string())
                    }
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
                Some(_) => panic!("Operation is not a lightning payment"),
                None => None,
            }
        }

        let operation = self.client_ctx.get_operation(operation_id).await?;
        let LightningOperationMetaVariant::Pay(LightningOperationMetaPay {
            out_point: _,
            invoice: _,
            change,
            ..
        }) = operation.meta::<LightningOperationMeta>().variant
        else {
            bail!("Operation is not a lightning payment")
        };

        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, || {
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
                                Ok(_) => {
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
                            Ok(_) => {
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
    pub async fn scan_receive_for_user_tweaked<M: Serialize + Send + Sync + Clone>(
        &self,
        key_pair: KeyPair,
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
                Err(e) => {
                    error!(?e, ?i, "Failed to scan tweaked key at index i");
                }
            }
        }

        claims
    }

    /// Scan unspent incoming contracts for a payment hash that matches a public
    /// key and claim the incoming contract
    pub async fn scan_receive_for_user<M: Serialize + Send + Sync>(
        &self,
        key_pair: KeyPair,
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
    pub async fn claim_funded_incoming_contract<M: Serialize + Send + Sync>(
        &self,
        key_pair: KeyPair,
        contract_id: ContractId,
        extra_meta: M,
    ) -> anyhow::Result<OperationId> {
        let incoming_contract_account = get_incoming_contract(self.module_api.clone(), contract_id)
            .await?
            .ok_or(anyhow!("No contract account found"))
            .with_context(|| format!("No contract found for {contract_id:?}"))?;

        let input = incoming_contract_account.claim();
        let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
            input,
            amount: incoming_contract_account.amount,
            keys: vec![key_pair],
            state_machines: Arc::new(|_, _| vec![]),
        };

        let tx =
            TransactionBuilder::new().with_input(self.client_ctx.make_client_input(client_input));
        let extra_meta = serde_json::to_value(extra_meta).expect("extra_meta is serializable");
        let operation_meta_gen = |_, out_points| LightningOperationMeta {
            variant: LightningOperationMetaVariant::Claim { out_points },
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
    pub async fn create_bolt11_invoice<M: Serialize + Send + Sync>(
        &self,
        amount: Amount,
        description: lightning_invoice::Bolt11InvoiceDescription<'_>,
        expiry_time: Option<u64>,
        extra_meta: M,
        gateway: Option<LightningGateway>,
    ) -> anyhow::Result<(OperationId, Bolt11Invoice, [u8; 32])> {
        let receiving_key =
            ReceivingKey::Personal(KeyPair::new(&self.secp, &mut rand::rngs::OsRng));
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
        description: lightning_invoice::Bolt11InvoiceDescription<'_>,
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
        description: lightning_invoice::Bolt11InvoiceDescription<'_>,
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
        description: lightning_invoice::Bolt11InvoiceDescription<'_>,
        expiry_time: Option<u64>,
        receiving_key: ReceivingKey,
        extra_meta: M,
        gateway: Option<LightningGateway>,
    ) -> anyhow::Result<(OperationId, Bolt11Invoice, [u8; 32])> {
        let gateway_id = gateway.as_ref().map(|g| g.gateway_id);
        let (src_node_id, short_channel_id, route_hints) = if let Some(current_gateway) = gateway {
            (
                current_gateway.node_pub_key,
                current_gateway.mint_channel_id,
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
            self.cfg.network,
        )?;

        let tx = TransactionBuilder::new().with_output(self.client_ctx.make_client_output(output));
        let extra_meta = serde_json::to_value(extra_meta).expect("extra_meta is serializable");
        let operation_meta_gen = |txid, _| LightningOperationMeta {
            variant: LightningOperationMetaVariant::Receive {
                out_point: OutPoint { txid, out_idx: 0 },
                invoice: invoice.clone(),
                gateway_id,
            },
            extra_meta: extra_meta.clone(),
        };
        let (txid, _) = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                operation_meta_gen,
                tx,
            )
            .await?;

        debug!(target: LOG_CLIENT_MODULE_LN, ?txid, ?operation_id, "Waiting for LN invoice to be confirmed");

        // Wait for the transaction to be accepted by the federation, otherwise the
        // invoice will not be able to be paid
        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(txid)
            .await
            .map_err(|e| anyhow!("Offer transaction was not accepted: {e:?}"))?;

        debug!(target: LOG_CLIENT_MODULE_LN, %invoice, "Invoice confirmed");

        Ok((operation_id, invoice, preimage))
    }

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

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, || {
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
        let LightningOperationMetaVariant::Receive {
            out_point, invoice, ..
        } = operation.meta::<LightningOperationMeta>().variant
        else {
            bail!("Operation is not a lightning payment")
        };

        let tx_accepted_future = self
            .client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(out_point.txid);

        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, || {
            stream! {

                let self_ref = client_ctx.self_ref();

                yield LnReceiveState::Created;

                if tx_accepted_future.await.is_err() {
                    yield LnReceiveState::Canceled { reason: LightningReceiveError::Rejected };
                    return;
                }
                yield LnReceiveState::WaitingForPayment { invoice: invoice.to_string(), timeout: invoice.expiry_time() };

                match self_ref.await_receive_success(operation_id).await {
                    Ok(is_external) if is_external => {
                        // If the payment was external, we can consider it claimed
                        yield LnReceiveState::Claimed;
                        return;
                    }
                    Ok(_) => {

                        yield LnReceiveState::Funded;

                        if let Ok(out_points) = self_ref.await_claim_acceptance(operation_id).await {
                            yield LnReceiveState::AwaitingFunds;

                            if client_ctx.await_primary_module_outputs(operation_id, out_points).await.is_ok() {
                                yield LnReceiveState::Claimed;
                                return;
                            }
                        }

                        yield LnReceiveState::Canceled { reason: LightningReceiveError::Rejected };
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

    pub async fn wait_for_ln_payment(
        &self,
        payment_type: PayType,
        contract_id: ContractId,
        return_on_funding: bool,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        match payment_type {
            PayType::Internal(operation_id) => {
                let mut updates = self
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
                                    preimage: preimage.consensus_encode_to_hex(),
                                })
                                .unwrap(),
                            ));
                        }
                        InternalPayState::RefundSuccess { out_points, error } => {
                            let e = format!(
                            "Internal payment failed. A refund was issued to {out_points:?} Error: {error}"

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
                    debug!(target: LOG_CLIENT_MODULE_LN, ?update, "Wait for ln payment state update");
                }
            }
            PayType::Lightning(operation_id) => {
                let mut updates = self.subscribe_ln_pay(operation_id).await?.into_stream();

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
                            // TODO: what should be the format here?
                            return Ok(Some(json! {
                                {
                                    "status": "refunded",
                                    "gateway_error": gateway_error.to_string(),
                                }
                            }));
                        }
                        LnPayState::Funded { block_height: _ } if return_on_funding => {
                            return Ok(None)
                        }
                        LnPayState::Created
                        | LnPayState::AwaitingChange
                        | LnPayState::WaitingForRefund { .. }
                        | LnPayState::Funded { block_height: _ } => {}
                        LnPayState::UnexpectedError { error_message } => {
                            bail!("UnexpectedError: {error_message}")
                        }
                        LnPayState::Canceled => bail!("Funding transaction was rejected"),
                    }
                    debug!(target: LOG_CLIENT_MODULE_LN, ?update, "Wait for ln payment state update");
                }
            }
        };
        bail!("Lightning Payment failed")
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
    redeem_key: KeyPair,
) -> Result<(LightningOutputV0, Amount, ContractId), IncomingSmError> {
    let offer = fetch_and_validate_offer(module_api, payment_hash, amount_msat).await?;
    let our_pub_key = secp256k1::PublicKey::from_keypair(&redeem_key);
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
    key_pair: KeyPair,
    index: u64,
) -> KeyPair {
    let public_key = key_pair.public_key();
    let mut hasher = HmacEngine::<sha256::Hash>::new(&public_key.serialize()[..]);
    hasher.input(&index.to_be_bytes());
    let tweak = Hmac::from_engine(hasher).to_byte_array();

    let secret_key = key_pair.secret_key();
    let sk_tweaked = secret_key
        .add_tweak(&Scalar::from_be_bytes(tweak).expect("Cant fail"))
        .expect("Cant fail");
    KeyPair::from_secret_key(secp, &sk_tweaked)
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
            };
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
                    assert_eq!(invoice.amount_milli_satoshis(), Some(amount.msats));
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
    pub redeem_key: KeyPair,
    pub gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
}

impl fedimint_client::sm::Context for LightningClientContext {}

#[apply(async_trait_maybe_send!)]
pub trait GatewayConnection: std::fmt::Debug {
    // Ping gateway endpoint to verify that it is available before locking funds in
    // OutgoingContract
    async fn verify_gateway_availability(&self, gateway: &LightningGateway) -> anyhow::Result<()>;

    // Send a POST request to the gateway to request it to pay a BOLT11 invoice.
    async fn pay_invoice(
        &self,
        gateway: LightningGateway,
        payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError>;
}

#[derive(Debug, Default)]
pub struct RealGatewayConnection {
    client: reqwest::Client,
}

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for RealGatewayConnection {
    async fn verify_gateway_availability(&self, gateway: &LightningGateway) -> anyhow::Result<()> {
        let response = self
            .client
            .get(
                gateway
                    .api
                    .join("id")
                    .expect("id contains no invalid characters for a URL")
                    .as_str(),
            )
            .send()
            .await
            .context("Gateway is not available")?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "Gateway is not available. Returned error code: {}",
                response.status()
            ));
        }

        let text_gateway_id = response.text().await?;
        let gateway_id = PublicKey::from_str(&text_gateway_id[1..text_gateway_id.len() - 1])?;
        if gateway_id != gateway.gateway_id {
            return Err(anyhow!("Unexpected gateway id returned: {gateway_id}"));
        }

        Ok(())
    }

    async fn pay_invoice(
        &self,
        gateway: LightningGateway,
        payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError> {
        let response = self
            .client
            .post(
                gateway
                    .api
                    .join("pay_invoice")
                    .expect("'pay_invoice' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&payload)
            .send()
            .await
            .map_err(|e| GatewayPayError::GatewayInternalError {
                error_code: None,
                error_message: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(GatewayPayError::GatewayInternalError {
                error_code: Some(response.status().as_u16()),
                error_message: response
                    .text()
                    .await
                    .expect("Could not retrieve text from response"),
            });
        }

        let preimage =
            response
                .text()
                .await
                .map_err(|_| GatewayPayError::GatewayInternalError {
                    error_code: None,
                    error_message: "Error retrieving preimage from response".to_string(),
                })?;
        let length = preimage.len();
        Ok(preimage[1..length - 1].to_string())
    }
}

#[derive(Debug)]
pub struct MockGatewayConnection;

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for MockGatewayConnection {
    async fn verify_gateway_availability(&self, _gateway: &LightningGateway) -> anyhow::Result<()> {
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
