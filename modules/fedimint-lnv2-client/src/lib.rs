#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod api;
#[cfg(feature = "cli")]
mod cli;
mod db;
mod receive_sm;
mod send_sm;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use api::{GatewayConnection, RealGatewayConnection};
use async_stream::stream;
use bitcoin30::hashes::{sha256, Hash};
use bitcoin30::secp256k1;
use db::GatewayKey;
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiAuth, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::sleep;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, PeerId, TransactionId};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract, PaymentImage};
use fedimint_lnv2_common::{
    LightningCommonInit, LightningModuleTypes, LightningOutput, LightningOutputV0, KIND,
};
use futures::StreamExt;
use lightning_invoice::{Bolt11Invoice, Currency};
use secp256k1::schnorr::Signature;
use secp256k1::{ecdh, KeyPair, PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tpe::{derive_agg_decryption_key, AggregateDecryptionKey, AggregatePublicKey, PublicKeyShare};

use crate::api::LnFederationApi;
use crate::receive_sm::{ReceiveSMCommon, ReceiveSMState, ReceiveStateMachine};
use crate::send_sm::{SendSMCommon, SendSMState, SendStateMachine};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightningOperationMeta {
    Send(SendOperationMeta),
    Receive(ReceiveOperationMeta),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendOperationMeta {
    pub funding_txid: TransactionId,
    pub funding_change_outpoints: Vec<OutPoint>,
    pub gateway: SafeUrl,
    pub contract: OutgoingContract,
    pub invoice: LightningInvoice,
    pub custom_meta: Value,
}

impl SendOperationMeta {
    /// Calculate the absolute fee paid to the gateway on success.
    pub fn gateway_fee(&self) -> Amount {
        match &self.invoice {
            LightningInvoice::Bolt11(invoice) => {
                self.contract.amount
                    - Amount::from_msats(
                        invoice.amount_milli_satoshis().expect("Invoice has amount"),
                    )
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveOperationMeta {
    pub gateway: SafeUrl,
    pub contract: IncomingContract,
    pub invoice: LightningInvoice,
    pub custom_meta: Value,
}

impl ReceiveOperationMeta {
    /// Calculate the absolute fee paid to the gateway on success.
    pub fn gateway_fee(&self) -> Amount {
        match &self.invoice {
            LightningInvoice::Bolt11(invoice) => {
                Amount::from_msats(invoice.amount_milli_satoshis().expect("Invoice has amount"))
                    - self.contract.commitment.amount
            }
        }
    }
}

/// Number of blocks until outgoing lightning contracts times out and user
/// client can refund it unilaterally
pub const EXPIRATION_DELTA_LIMIT_DEFAULT: u64 = 1008;

/// A two hour buffer in case either the client or gateway go offline
pub const CONTRACT_CONFIRMATION_BUFFER: u64 = 12;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// The high-level state of sending a payment over lightning.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Funding -- funding transaction is rejected --> Rejected
///     Funding -- funding transaction is accepted --> Funded
///     Funded -- payment is confirmed  --> Success
///     Funded -- payment attempt expires --> Refunding
///     Funded -- gateway cancels payment attempt --> Refunding
///     Refunding -- payment is confirmed --> Success
///     Refunding -- ecash is minted --> Refunded
///     Refunding -- minting ecash fails --> Failure
/// ```
/// The transition from Refunding to Success is only possible if the gateway
/// misbehaves.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SendState {
    /// We are funding the outgoing contract.
    Funding,
    /// We are waiting for the gateway to complete the payment.
    Funded,
    /// The payment was successful.
    Success,
    /// The payment has failed. We are refunding the outgoing contract.
    Refunding,
    /// The outgoing contract has been refunded.
    Refunded,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FinalSendState {
    /// The payment was successful.
    Success,
    /// The outgoing contract has been refunded.
    Refunded,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

pub type SendResult = Result<OperationId, SendPaymentError>;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// The high-level state of receiving a payment over lightning.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Pending -- payment is confirmed --> Claiming
///     Pending -- invoice expires --> Expired
///     Claiming -- ecash is minted --> Claimed
///     Claiming -- minting ecash fails --> Failure
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReceiveState {
    /// We are waititng for the gateway to fund the incoming contract.
    Pending,
    /// The incoming contract has expired.
    Expired,
    /// The gateway has funded the incoming contract.
    Claiming,
    /// The payment was successful.
    Claimed,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FinalReceiveState {
    /// The incoming contract has expired.
    Expired,
    /// The payment was successful.
    Claimed,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

pub type ReceiveResult = Result<(Bolt11Invoice, OperationId), ReceiveError>;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateBolt11InvoicePayload {
    pub federation_id: FederationId,
    pub contract: IncomingContract,
    pub amount: Amount,
    pub description: Bolt11InvoiceDescription,
    pub expiry_secs: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Bolt11InvoiceDescription {
    Direct(String),
    Hash(sha256::Hash),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SendPaymentPayload {
    pub federation_id: FederationId,
    pub contract: OutgoingContract,
    pub invoice: LightningInvoice,
    pub auth: Signature,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub enum LightningInvoice {
    Bolt11(Bolt11Invoice),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct RoutingInfo {
    /// The public key of the gateways lightning node. Since this key signs the
    /// gateways invoices the senders client uses it to differentiate between a
    /// direct swap between fedimints and a lightning swap.
    pub lightning_public_key: PublicKey,
    /// The public key of the gateways client module. This key is used to claim
    /// or cancel outgoing contracts and refund incoming contracts.
    pub module_public_key: PublicKey,
    /// This is the fee the gateway charges for an outgoing payment. The senders
    /// client will use this fee in case of a direct swap.
    pub send_fee_minimum: PaymentFee,
    /// This is the default total fee the gateway recommends for an outgoing
    /// payment in case of a lightning swap. It accounts for the additional fee
    /// required to reliably route this payment over lightning.
    pub send_fee_default: PaymentFee,
    /// This is the minimum expiration delta in block the gateway requires for
    /// an outgoing payment. The senders client will use this expiration delta
    /// in case of a direct swap.
    pub expiration_delta_minimum: u64,
    /// This is the default total expiration the gateway recommends for an
    /// outgoing payment in case of a lightning swap. It accounts for the
    /// additional expiration delta required to successfully route this payment
    /// over lightning.
    pub expiration_delta_default: u64,
    /// This is the fee the gateway charges for an incoming payment.
    pub receive_fee: PaymentFee,
}

impl RoutingInfo {
    pub fn send_parameters(&self, invoice: &Bolt11Invoice) -> (PaymentFee, u64) {
        if invoice.recover_payee_pub_key() == self.lightning_public_key {
            (self.send_fee_minimum.clone(), self.expiration_delta_minimum)
        } else {
            (self.send_fee_default.clone(), self.expiration_delta_default)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PaymentFee {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl PaymentFee {
    /// This is the maximum send fee of one and a half percent plus one hundred
    /// satoshis a correct gateway may recommend as a default. It accounts for
    /// the fee required to reliably route this payment over lightning.
    pub const SEND_FEE_LIMIT_DEFAULT: PaymentFee = PaymentFee {
        base: Amount::from_sats(100),
        parts_per_million: 15_000,
    };

    /// This is the maximum receive fee of half of one percent plus fifty
    /// satoshis a correct gateway may recommend as a default.
    pub const RECEIVE_FEE_LIMIT_DEFAULT: PaymentFee = PaymentFee {
        base: Amount::from_sats(50),
        parts_per_million: 5_000,
    };

    pub fn add_to(&self, msats: u64) -> Amount {
        Amount::from_msats(msats.saturating_add(self.absolute_fee(msats)))
    }

    pub fn subtract_from(&self, msats: u64) -> Amount {
        Amount::from_msats(msats.saturating_sub(self.absolute_fee(msats)))
    }

    fn absolute_fee(&self, msats: u64) -> u64 {
        self.base.msats
            + msats
                .saturating_mul(self.parts_per_million)
                .saturating_div(1_000_000)
    }
}

#[derive(Debug, Clone)]
pub struct LightningClientInit {
    pub gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
}

impl Default for LightningClientInit {
    fn default() -> Self {
        LightningClientInit {
            gateway_conn: Arc::new(RealGatewayConnection),
        }
    }
}

impl ModuleInit for LightningClientInit {
    type Common = LightningCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for LightningClientInit {
    type Module = LightningClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(LightningClientModule {
            federation_id: *args.federation_id(),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            module_api: args.module_api().clone(),
            keypair: args
                .module_root_secret()
                .clone()
                .to_secp_key(secp256k1::SECP256K1),
            admin_auth: args.admin_auth().cloned(),
            gateway_conn: self.gateway_conn.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LightningClientContext {
    pub decoder: Decoder,
    pub federation_id: FederationId,
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
}

impl Context for LightningClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

/// Client side lightning module
///
/// Note that lightning gateways use a different version
/// of client side module.
#[derive(Debug)]
pub struct LightningClientModule {
    pub federation_id: FederationId,
    pub cfg: LightningClientConfig,
    pub notifier: ModuleNotifier<LightningClientStateMachines>,
    pub client_ctx: ClientContext<Self>,
    pub module_api: DynModuleApi,
    pub keypair: KeyPair,
    pub admin_auth: Option<ApiAuth>,
    pub gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
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
            decoder: self.decoder(),
            federation_id: self.federation_id,
            tpe_agg_pk: self.cfg.tpe_agg_pk,
            tpe_pks: self.cfg.tpe_pks.clone(),
            gateway_conn: self.gateway_conn.clone(),
        }
    }

    fn input_fee(
        &self,
        amount: Amount,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amount> {
        Some(self.cfg.fee_consensus.fee(amount))
    }

    fn output_fee(&self, output: &<Self::Common as ModuleCommon>::Output) -> Option<Amount> {
        let amount = match output.ensure_v0_ref().ok()? {
            LightningOutputV0::Outgoing(contract) => contract.amount,
            LightningOutputV0::Incoming(contract) => contract.commitment.amount,
        };

        Some(self.cfg.fee_consensus.fee(amount))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

fn generate_ephemeral_tweak(static_pk: PublicKey) -> ([u8; 32], PublicKey) {
    let keypair = KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng());

    let tweak = ecdh::SharedSecret::new(&static_pk, &keypair.secret_key());

    (tweak.secret_bytes(), keypair.public_key())
}

impl LightningClientModule {
    /// This method updates the mapping from lightning node public keys to
    /// gateway api endpoints maintained in the module database once a day. When
    /// paying an invoice this enables the client to select the gateway that has
    /// created the invoice, if possible, such that the payment does not go
    /// over lightning, reducing fees and latency.
    ///
    /// Client integrators are expected to call this function in a spawned task.
    pub async fn update_gateway_map(&self) -> ! {
        loop {
            if let Ok(gateways) = self.module_api.gateways().await {
                let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

                for gateway in gateways {
                    if let Ok(Some(routing_info)) = self.routing_info(&gateway).await {
                        dbtx.insert_entry(&GatewayKey(routing_info.lightning_public_key), &gateway)
                            .await;
                    }
                }

                dbtx.commit_tx().await;
            }

            sleep(Duration::from_secs(24 * 60 * 60)).await;
        }
    }

    async fn select_gateway(
        &self,
        invoice: Option<Bolt11Invoice>,
    ) -> Result<(SafeUrl, RoutingInfo), SelectGatewayError> {
        let gateways = self
            .module_api
            .gateways()
            .await
            .map_err(|e| SelectGatewayError::FederationError(e.to_string()))?;

        if gateways.is_empty() {
            return Err(SelectGatewayError::NoVettedGateways);
        }

        if let Some(invoice) = invoice {
            if let Some(gateway) = self
                .client_ctx
                .module_db()
                .begin_transaction_nc()
                .await
                .get_value(&GatewayKey(invoice.recover_payee_pub_key()))
                .await
                .filter(|gateway| gateways.contains(gateway))
            {
                if let Ok(Some(routing_info)) = self.routing_info(&gateway).await {
                    return Ok((gateway, routing_info));
                }
            }
        }

        for gateway in gateways {
            if let Ok(Some(routing_info)) = self.routing_info(&gateway).await {
                return Ok((gateway, routing_info));
            }
        }

        Err(SelectGatewayError::FailedToFetchRoutingInfo)
    }

    async fn routing_info(
        &self,
        gateway: &SafeUrl,
    ) -> Result<Option<RoutingInfo>, GatewayConnectionError> {
        self.gateway_conn
            .routing_info(gateway.clone(), &self.federation_id)
            .await
    }

    /// Pay an invoice. For  testing  you can optionally specify a gateway to
    /// route with, otherwise a gateway will be selected automatically.
    pub async fn send(
        &self,
        invoice: Bolt11Invoice,
        gateway: Option<SafeUrl>,
        custom_meta: Value,
    ) -> Result<OperationId, SendPaymentError> {
        let amount = invoice
            .amount_milli_satoshis()
            .ok_or(SendPaymentError::InvoiceMissingAmount)?;

        if invoice.is_expired() {
            return Err(SendPaymentError::InvoiceExpired);
        }

        if self.cfg.network != invoice.currency().into() {
            return Err(SendPaymentError::WrongCurrency {
                invoice_currency: invoice.currency(),
                federation_currency: self.cfg.network.into(),
            });
        }

        let operation_id = self.get_next_operation_id(&invoice).await?;

        let (ephemeral_tweak, ephemeral_pk) = generate_ephemeral_tweak(self.keypair.public_key());

        let refund_keypair = SecretKey::from_slice(&ephemeral_tweak)
            .expect("32 bytes, within curve order")
            .keypair(secp256k1::SECP256K1);

        let (gateway_api, routing_info) = match gateway {
            Some(gateway_api) => (
                gateway_api.clone(),
                self.routing_info(&gateway_api)
                    .await
                    .map_err(SendPaymentError::GatewayConnectionError)?
                    .ok_or(SendPaymentError::UnknownFederation)?,
            ),
            None => self
                .select_gateway(Some(invoice.clone()))
                .await
                .map_err(SendPaymentError::FailedToSelectGateway)?,
        };

        let (send_fee, expiration_delta) = routing_info.send_parameters(&invoice);

        if !send_fee.le(&PaymentFee::SEND_FEE_LIMIT_DEFAULT) {
            return Err(SendPaymentError::PaymentFeeExceedsLimit(send_fee));
        }

        if EXPIRATION_DELTA_LIMIT_DEFAULT < expiration_delta {
            return Err(SendPaymentError::ExpirationDeltaExceedsLimit(
                expiration_delta,
            ));
        }

        let consensus_block_count = self
            .module_api
            .consensus_block_count()
            .await
            .map_err(|e| SendPaymentError::FederationError(e.to_string()))?;

        let contract = OutgoingContract {
            payment_image: PaymentImage::Hash(*invoice.payment_hash()),
            amount: send_fee.add_to(amount),
            expiration: consensus_block_count + expiration_delta + CONTRACT_CONFIRMATION_BUFFER,
            claim_pk: routing_info.module_public_key,
            refund_pk: refund_keypair.public_key(),
            ephemeral_pk,
        };

        let contract_clone = contract.clone();
        let gateway_api_clone = gateway_api.clone();
        let invoice_clone = invoice.clone();

        let client_output = ClientOutput::<LightningOutput, LightningClientStateMachines> {
            output: LightningOutput::V0(LightningOutputV0::Outgoing(contract.clone())),
            amount: contract.amount,
            state_machines: Arc::new(move |funding_txid, _| {
                vec![LightningClientStateMachines::Send(SendStateMachine {
                    common: SendSMCommon {
                        operation_id,
                        funding_txid,
                        gateway_api: gateway_api_clone.clone(),
                        contract: contract_clone.clone(),
                        invoice: LightningInvoice::Bolt11(invoice_clone.clone()),
                        refund_keypair,
                    },
                    state: SendSMState::Funding,
                })]
            }),
        };

        let client_output = self.client_ctx.make_client_output(client_output);
        let transaction = TransactionBuilder::new().with_output(client_output);

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                |funding_txid, funding_change_outpoints| {
                    LightningOperationMeta::Send(SendOperationMeta {
                        funding_txid,
                        funding_change_outpoints,
                        gateway: gateway_api.clone(),
                        contract: contract.clone(),
                        invoice: LightningInvoice::Bolt11(invoice.clone()),
                        custom_meta: custom_meta.clone(),
                    })
                },
                transaction,
            )
            .await
            .map_err(|e| SendPaymentError::FinalizationError(e.to_string()))?;

        Ok(operation_id)
    }

    async fn get_next_operation_id(
        &self,
        invoice: &Bolt11Invoice,
    ) -> Result<OperationId, SendPaymentError> {
        for payment_attempt in 0..u64::MAX {
            let operation_id = OperationId::from_encodable(&(invoice.clone(), payment_attempt));

            if !self.client_ctx.operation_exists(operation_id).await {
                return Ok(operation_id);
            }

            if self.client_ctx.has_active_states(operation_id).await {
                return Err(SendPaymentError::PendingPreviousPayment(operation_id));
            }

            let mut stream = self
                .subscribe_send(operation_id)
                .await
                .expect("operation_id exists")
                .into_stream();

            // This will not block since we checked for active states and there were none,
            // so by definition a final state has to have been assumed already.
            while let Some(state) = stream.next().await {
                if let SendState::Success = state {
                    return Err(SendPaymentError::SuccessfulPreviousPayment(operation_id));
                }
            }
        }

        panic!("We could not find an unused operation id for sending a lightning payment");
    }

    /// Subscribe to all updates of the send operation.
    pub async fn subscribe_send(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<SendState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();
        let module_api = self.module_api.clone();

        Ok(self.client_ctx.outcome_or_updates(&operation, operation_id, || {
            stream! {
                loop {
                    if let Some(LightningClientStateMachines::Send(state)) = stream.next().await {
                        match state.state {
                            SendSMState::Funding => yield SendState::Funding,
                            SendSMState::Funded => yield SendState::Funded,
                            SendSMState::Success(preimage) => {
                                // the preimage has been verified by the state machine previously
                                assert!(state.common.contract.verify_preimage(&preimage));

                                yield SendState::Success;
                                return;
                            },
                            SendSMState::Refunding(out_points) => {
                                yield SendState::Refunding;

                                if client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await.is_ok() {
                                    yield SendState::Refunded;
                                    return;
                                }

                                // The gateway may have incorrectly claimed the outgoing contract thereby causing
                                // our refund transaction to be rejected. Therefore, we check one last time if
                                // the preimage is available before we enter the failure state.
                                if let Some(preimage) = module_api.await_preimage(
                                    &state.common.contract.contract_id(),
                                    0
                                ).await {
                                    if state.common.contract.verify_preimage(&preimage) {
                                        yield SendState::Success;
                                        return;
                                    }
                                }

                                yield SendState::Failure;
                                return;
                            },
                            SendSMState::Rejected(..) => {
                                yield SendState::Failure;
                                return;
                            },
                        }
                    }
                }
            }
        }))
    }

    /// Await the final state of the send operation.
    pub async fn await_send(&self, operation_id: OperationId) -> anyhow::Result<FinalSendState> {
        let state = self
            .subscribe_send(operation_id)
            .await?
            .into_stream()
            .filter_map(|state| {
                futures::future::ready(match state {
                    SendState::Success => Some(FinalSendState::Success),
                    SendState::Refunded => Some(FinalSendState::Refunded),
                    SendState::Failure => Some(FinalSendState::Failure),
                    _ => None,
                })
            })
            .next()
            .await
            .expect("Stream contains one final state");

        Ok(state)
    }

    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a gateway will be selected
    /// automatically.
    pub async fn receive(
        &self,
        amount: Amount,
        expiry_secs: u32,
        description: Bolt11InvoiceDescription,
        gateway: Option<SafeUrl>,
        custom_meta: Value,
    ) -> Result<(Bolt11Invoice, OperationId), ReceiveError> {
        let (gateway, contract, invoice) = self
            .create_contract_and_fetch_invoice(
                self.keypair.public_key(),
                amount,
                expiry_secs,
                description,
                gateway,
            )
            .await?;

        let operation_id = self
            .receive_incoming_contract(gateway, contract, invoice.clone(), custom_meta)
            .await
            .expect("The contract has been generated with our public key");

        Ok((invoice, operation_id))
    }

    /// Create an incoming contract locked to a public key derived from the
    /// recipient's static module public key and fetches the corresponding
    /// invoice.
    async fn create_contract_and_fetch_invoice(
        &self,
        recipient_static_pk: PublicKey,
        amount: Amount,
        expiry_secs: u32,
        description: Bolt11InvoiceDescription,
        gateway: Option<SafeUrl>,
    ) -> Result<(SafeUrl, IncomingContract, Bolt11Invoice), ReceiveError> {
        let (ephemeral_tweak, ephemeral_pk) = generate_ephemeral_tweak(recipient_static_pk);

        let encryption_seed = ephemeral_tweak
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let preimage = encryption_seed
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let (gateway, routing_info) = match gateway {
            Some(gateway) => (
                gateway.clone(),
                self.routing_info(&gateway)
                    .await
                    .map_err(ReceiveError::GatewayConnectionError)?
                    .ok_or(ReceiveError::UnknownFederation)?,
            ),
            None => self
                .select_gateway(None)
                .await
                .map_err(ReceiveError::FailedToSelectGateway)?,
        };

        if !routing_info
            .receive_fee
            .le(&PaymentFee::RECEIVE_FEE_LIMIT_DEFAULT)
        {
            return Err(ReceiveError::PaymentFeeExceedsLimit(
                routing_info.receive_fee,
            ));
        }

        let contract_amount = routing_info.receive_fee.subtract_from(amount.msats);

        // The dust limit ensures that the incoming contract can be claimed without
        // additional funds as the contracts amount is sufficient to cover the fees
        if contract_amount < Amount::from_sats(50) {
            return Err(ReceiveError::DustAmount);
        }

        let expiration = duration_since_epoch()
            .as_secs()
            .saturating_add(u64::from(expiry_secs));

        let claim_pk = recipient_static_pk
            .mul_tweak(
                secp256k1::SECP256K1,
                &Scalar::from_be_bytes(ephemeral_tweak).expect("Within curve order"),
            )
            .expect("Tweak is valid");

        let contract = IncomingContract::new(
            self.cfg.tpe_agg_pk,
            encryption_seed,
            preimage,
            PaymentImage::Hash(preimage.consensus_hash()),
            contract_amount,
            expiration,
            claim_pk,
            routing_info.module_public_key,
            ephemeral_pk,
        );

        let invoice = self
            .gateway_conn
            .bolt11_invoice(
                gateway.clone(),
                self.federation_id,
                contract.clone(),
                amount,
                description,
                expiry_secs,
            )
            .await
            .map_err(ReceiveError::GatewayConnectionError)?;

        if invoice.payment_hash() != &preimage.consensus_hash() {
            return Err(ReceiveError::InvalidInvoicePaymentHash);
        }

        if invoice.amount_milli_satoshis() != Some(amount.msats) {
            return Err(ReceiveError::InvalidInvoiceAmount);
        }

        Ok((gateway, contract, invoice))
    }

    // Receive an incoming contract locked to a public key derived from our
    // static module public key.
    async fn receive_incoming_contract(
        &self,
        gateway: SafeUrl,
        contract: IncomingContract,
        invoice: Bolt11Invoice,
        custom_meta: Value,
    ) -> Option<OperationId> {
        let operation_id = OperationId::from_encodable(&contract.clone());

        let (claim_keypair, agg_decryption_key) = self.recover_contract_keys(&contract)?;

        let receive_sm = LightningClientStateMachines::Receive(ReceiveStateMachine {
            common: ReceiveSMCommon {
                operation_id,
                contract: contract.clone(),
                claim_keypair,
                agg_decryption_key,
            },
            state: ReceiveSMState::Pending,
        });

        // this may only fail if the operation id is already in use, in which case we
        // ignore the error such that the method is idempotent
        self.client_ctx
            .manual_operation_start(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                LightningOperationMeta::Receive(ReceiveOperationMeta {
                    gateway,
                    contract,
                    invoice: LightningInvoice::Bolt11(invoice),
                    custom_meta,
                }),
                vec![self.client_ctx.make_dyn_state(receive_sm)],
            )
            .await
            .ok();

        Some(operation_id)
    }

    fn recover_contract_keys(
        &self,
        contract: &IncomingContract,
    ) -> Option<(KeyPair, AggregateDecryptionKey)> {
        let ephemeral_tweak = ecdh::SharedSecret::new(
            &contract.commitment.ephemeral_pk,
            &self.keypair.secret_key(),
        )
        .secret_bytes();

        let encryption_seed = ephemeral_tweak
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let claim_keypair = self
            .keypair
            .secret_key()
            .mul_tweak(&Scalar::from_be_bytes(ephemeral_tweak).expect("Within curve order"))
            .expect("Tweak is valid")
            .keypair(secp256k1::SECP256K1);

        if claim_keypair.public_key() != contract.commitment.claim_pk {
            return None; // The claim key is not derived from our pk
        }

        let agg_decryption_key = derive_agg_decryption_key(&self.cfg.tpe_agg_pk, &encryption_seed);

        if !contract.verify_agg_decryption_key(&self.cfg.tpe_agg_pk, &agg_decryption_key) {
            return None; // The decryption key is not derived from our pk
        }

        contract.decrypt_preimage(&agg_decryption_key)?;

        Some((claim_keypair, agg_decryption_key))
    }

    /// Subscribe to all updates of the receive operation.
    pub async fn subscribe_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<ReceiveState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(&operation, operation_id, || {
            stream! {
                loop {
                    if let Some(LightningClientStateMachines::Receive(state)) = stream.next().await {
                        match state.state {
                            ReceiveSMState::Pending => yield ReceiveState::Pending,
                            ReceiveSMState::Claiming(out_points) => {
                                yield ReceiveState::Claiming;

                                if client_ctx.await_primary_module_outputs(operation_id, out_points).await.is_ok() {
                                    yield ReceiveState::Claimed;
                                } else {
                                    yield ReceiveState::Failure;
                                }
                                return;
                            },
                            ReceiveSMState::Expired => {
                                yield ReceiveState::Expired;
                                return;
                            }
                        }
                    }
                }
            }
        }))
    }

    /// Await the final state of the receive operation.
    pub async fn await_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<FinalReceiveState> {
        let state = self
            .subscribe_receive(operation_id)
            .await?
            .into_stream()
            .filter_map(|state| {
                futures::future::ready(match state {
                    ReceiveState::Expired => Some(FinalReceiveState::Expired),
                    ReceiveState::Claimed => Some(FinalReceiveState::Claimed),
                    ReceiveState::Failure => Some(FinalReceiveState::Failure),
                    _ => None,
                })
            })
            .next()
            .await
            .expect("Stream contains one final state");

        Ok(state)
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum GatewayConnectionError {
    #[error("The gateway is unreachable: {0}")]
    Unreachable(String),
    #[error("The gateway returned an error for this request: {0}")]
    Request(String),
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SelectGatewayError {
    #[error("Federation returned an error: {0}")]
    FederationError(String),
    #[error("The federation has no vetted gateways")]
    NoVettedGateways,
    #[error("All vetted gateways failed to respond on request of the routing info")]
    FailedToFetchRoutingInfo,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SendPaymentError {
    #[error("The invoice has not amount")]
    InvoiceMissingAmount,
    #[error("The invoice has expired")]
    InvoiceExpired,
    #[error("A previous payment for the same invoice is still pending: {}", .0.fmt_full())]
    PendingPreviousPayment(OperationId),
    #[error("A previous payment for the same invoice was successful: {}", .0.fmt_full())]
    SuccessfulPreviousPayment(OperationId),
    #[error("Failed to select gateway: {0}")]
    FailedToSelectGateway(SelectGatewayError),
    #[error("Gateway connection error: {0}")]
    GatewayConnectionError(GatewayConnectionError),
    #[error("The gateway does not support our federation")]
    UnknownFederation,
    #[error("The gateways fee of {0:?} exceeds the supplied limit")]
    PaymentFeeExceedsLimit(PaymentFee),
    #[error("The gateways expiration delta of {0:?} exceeds the supplied limit")]
    ExpirationDeltaExceedsLimit(u64),
    #[error("Federation returned an error: {0}")]
    FederationError(String),
    #[error("We failed to finalize the funding transaction")]
    FinalizationError(String),
    #[error("The invoice was for the wrong currency. Invoice currency={invoice_currency} Federation Currency={federation_currency}")]
    WrongCurrency {
        invoice_currency: Currency,
        federation_currency: Currency,
    },
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ReceiveError {
    #[error("Failed to select gateway: {0}")]
    FailedToSelectGateway(SelectGatewayError),
    #[error("Gateway connection error: {0}")]
    GatewayConnectionError(GatewayConnectionError),
    #[error("The gateway does not support our federation")]
    UnknownFederation,
    #[error("The gateways fee of {0:?} exceeds the supplied limit")]
    PaymentFeeExceedsLimit(PaymentFee),
    #[error("The total fees required to complete this payment exceed its amount")]
    DustAmount,
    #[error("The invoice's payment hash is incorrect")]
    InvalidInvoicePaymentHash,
    #[error("The invoice's amount is incorrect")]
    InvalidInvoiceAmount,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum LightningClientStateMachines {
    Send(SendStateMachine),
    Receive(ReceiveStateMachine),
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
            LightningClientStateMachines::Send(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    LightningClientStateMachines::Send
                )
            }
            LightningClientStateMachines::Receive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    LightningClientStateMachines::Receive
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            LightningClientStateMachines::Send(state) => state.operation_id(),
            LightningClientStateMachines::Receive(state) => state.operation_id(),
        }
    }
}
