#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub use fedimint_lnv2_common as common;

mod api;
#[cfg(feature = "cli")]
mod cli;
mod db;
pub mod events;
mod receive_sm;
mod send_sm;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_stream::stream;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1;
use db::{DbKeyPrefix, GatewayKey, IncomingContractStreamIndexKey};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, OutPointRange};
use fedimint_client_module::oplog::UpdateStreamOrOutcome;
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    Amounts, ApiAuth, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::SECP256K1;
use fedimint_core::task::TaskGroup;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId, apply, async_trait_maybe_send};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{
    IncomingContract, LightningContract, OutgoingContract, PaymentImage,
};
use fedimint_lnv2_common::gateway_api::{
    GatewayConnection, PaymentFee, RealGatewayConnection, RoutingInfo,
};
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, GatewayApi, KIND, LightningCommonInit, LightningInputV0,
    LightningInvoice, LightningModuleTypes, LightningOutput, LightningOutputV0,
    MINIMUM_INCOMING_CONTRACT_AMOUNT, lnurl, tweak,
};
use futures::StreamExt;
use lightning_invoice::{Bolt11Invoice, Currency};
use secp256k1::{Keypair, PublicKey, Scalar, SecretKey, ecdh};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::IntoEnumIterator as _;
use thiserror::Error;
use tpe::{AggregateDecryptionKey, derive_agg_dk};
use tracing::warn;

use crate::api::LightningFederationApi;
use crate::db::OutpointContractKey;
use crate::events::SendPaymentEvent;
use crate::receive_sm::{ReceiveSMCommon, ReceiveSMState, ReceiveStateMachine};
use crate::send_sm::{SendSMCommon, SendSMState, SendStateMachine};

/// Number of blocks until outgoing lightning contracts times out and user
/// client can refund it unilaterally
const EXPIRATION_DELTA_LIMIT: u64 = 1440;

/// A two hour buffer in case either the client or gateway go offline
const CONTRACT_CONFIRMATION_BUFFER: u64 = 12;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightningOperationMeta {
    Send(SendOperationMeta),
    Receive(ReceiveOperationMeta),
    LnurlReceive(LnurlReceiveOperationMeta),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendOperationMeta {
    pub change_outpoint_range: OutPointRange,
    pub gateway: SafeUrl,
    pub contract: OutgoingContract,
    pub invoice: LightningInvoice,
    pub custom_meta: Value,
}

impl SendOperationMeta {
    /// Calculate the absolute fee paid to the gateway on success.
    pub fn gateway_fee(&self) -> Amount {
        match &self.invoice {
            LightningInvoice::Bolt11(invoice) => self.contract.amount.saturating_sub(
                Amount::from_msats(invoice.amount_milli_satoshis().expect("Invoice has amount")),
            ),
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
                    .saturating_sub(self.contract.commitment.amount)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnurlReceiveOperationMeta {
    pub contract: IncomingContract,
    pub custom_meta: Value,
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// The state of an operation sending a payment over lightning.
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
pub enum SendOperationState {
    /// We are funding the contract to incentivize the gateway.
    Funding,
    /// We are waiting for the gateway to complete the payment.
    Funded,
    /// The payment was successful.
    Success([u8; 32]),
    /// The payment has failed and we are refunding the contract.
    Refunding,
    /// The payment has been refunded.
    Refunded,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

/// The final state of an operation sending a payment over lightning.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FinalSendOperationState {
    /// The payment was successful.
    Success,
    /// The payment has been refunded.
    Refunded,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

pub type SendResult = Result<OperationId, SendPaymentError>;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// The state of an operation receiving a payment over lightning.
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
pub enum ReceiveOperationState {
    /// We are waiting for the payment.
    Pending,
    /// The payment request has expired.
    Expired,
    /// The payment has been confirmed and we are issuing the ecash.
    Claiming,
    /// The payment has been successful.
    Claimed,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

/// The final state of an operation receiving a payment over lightning.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FinalReceiveOperationState {
    /// The payment request has expired.
    Expired,
    /// The payment has been successful.
    Claimed,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

pub type ReceiveResult = Result<(Bolt11Invoice, OperationId), ReceiveError>;

#[derive(Clone)]
pub struct LightningClientInit {
    pub gateway_conn: Option<Arc<dyn GatewayConnection + Send + Sync>>,
    pub custom_meta_fn: Arc<dyn Fn() -> Value + Send + Sync>,
}

impl std::fmt::Debug for LightningClientInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightningClientInit")
            .field("gateway_conn", &self.gateway_conn)
            .field("custom_meta_fn", &"<function>")
            .finish()
    }
}

impl Default for LightningClientInit {
    fn default() -> Self {
        LightningClientInit {
            gateway_conn: None,
            custom_meta_fn: Arc::new(|| Value::Null),
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
        let gateway_conn = if let Some(gateway_conn) = self.gateway_conn.clone() {
            gateway_conn
        } else {
            let api = GatewayApi::new(None, args.connector_registry.clone());
            Arc::new(RealGatewayConnection { api })
        };
        Ok(LightningClientModule::new(
            *args.federation_id(),
            args.cfg().clone(),
            args.notifier().clone(),
            args.context(),
            args.module_api().clone(),
            args.module_root_secret(),
            gateway_conn,
            self.custom_meta_fn.clone(),
            args.admin_auth().cloned(),
            args.task_group(),
        ))
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

#[derive(Debug, Clone)]
pub struct LightningClientContext {
    federation_id: FederationId,
    gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
    pub(crate) client_ctx: ClientContext<LightningClientModule>,
}

impl Context for LightningClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[derive(Debug, Clone)]
pub struct LightningClientModule {
    federation_id: FederationId,
    cfg: LightningClientConfig,
    notifier: ModuleNotifier<LightningClientStateMachines>,
    client_ctx: ClientContext<Self>,
    module_api: DynModuleApi,
    keypair: Keypair,
    lnurl_keypair: Keypair,
    gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
    #[allow(unused)] // The field is only used by the cli feature
    admin_auth: Option<ApiAuth>,
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
            federation_id: self.federation_id,
            gateway_conn: self.gateway_conn.clone(),
            client_ctx: self.client_ctx.clone(),
        }
    }

    fn input_fee(
        &self,
        amounts: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(
            self.cfg.fee_consensus.fee(amounts.expect_only_bitcoin()),
        ))
    }

    async fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> Option<Amounts> {
        let input_v0 = input.maybe_v0_ref()?;

        let outpoint = match input_v0 {
            LightningInputV0::Outgoing(out_point, ..)
            | LightningInputV0::Incoming(out_point, ..) => *out_point,
        };

        let contract = self
            .client_ctx
            .module_db()
            .begin_transaction_nc()
            .await
            .get_value(&OutpointContractKey(outpoint))
            .await?;

        assert!(
            matches!(
                (input_v0, &contract),
                (
                    LightningInputV0::Outgoing(_, _),
                    LightningContract::Outgoing(_)
                ) | (
                    LightningInputV0::Incoming(_, _),
                    LightningContract::Incoming(_)
                )
            ),
            "Mismatched contract types"
        );

        Some(Amounts::new_bitcoin(contract.amount()))
    }

    fn output_fee(
        &self,
        amounts: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(
            self.cfg.fee_consensus.fee(amounts.expect_only_bitcoin()),
        ))
    }

    async fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        let amount_btc = match output.maybe_v0_ref()? {
            LightningOutputV0::Outgoing(outgoing_contract) => outgoing_contract.amount,
            LightningOutputV0::Incoming(incoming_contract) => incoming_contract.commitment.amount,
        };
        Some(Amounts::new_bitcoin(amount_btc))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

impl LightningClientModule {
    #[allow(clippy::too_many_arguments)]
    fn new(
        federation_id: FederationId,
        cfg: LightningClientConfig,
        notifier: ModuleNotifier<LightningClientStateMachines>,
        client_ctx: ClientContext<Self>,
        module_api: DynModuleApi,
        module_root_secret: &DerivableSecret,
        gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
        custom_meta_fn: Arc<dyn Fn() -> Value + Send + Sync>,
        admin_auth: Option<ApiAuth>,
        task_group: &TaskGroup,
    ) -> Self {
        let module = Self {
            federation_id,
            cfg,
            notifier,
            client_ctx,
            module_api,
            keypair: module_root_secret
                .child_key(ChildId(0))
                .to_secp_key(SECP256K1),
            lnurl_keypair: module_root_secret
                .child_key(ChildId(1))
                .to_secp_key(SECP256K1),
            gateway_conn,
            admin_auth,
        };

        module.spawn_receive_lnurl_task(custom_meta_fn, task_group);

        module.spawn_gateway_map_update_task(task_group);

        module
    }

    fn spawn_gateway_map_update_task(&self, task_group: &TaskGroup) {
        let module = self.clone();
        let api = self.module_api.clone();

        task_group.spawn_cancellable("gateway_map_update_task", async move {
            api.wait_for_initialized_connections().await;
            module.update_gateway_map().await;
        });
    }

    async fn update_gateway_map(&self) {
        // Update the mapping from lightning node public keys to gateway api
        // endpoints maintained in the module database. When paying an invoice this
        // enables the client to select the gateway that has created the invoice,
        // if possible, such that the payment does not go over lightning, reducing
        // fees and latency.

        if let Ok(gateways) = self.module_api.gateways().await {
            let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

            for gateway in gateways {
                if let Ok(Some(routing_info)) = self
                    .gateway_conn
                    .routing_info(gateway.clone(), &self.federation_id)
                    .await
                {
                    dbtx.insert_entry(&GatewayKey(routing_info.lightning_public_key), &gateway)
                        .await;
                }
            }

            if let Err(e) = dbtx.commit_tx_result().await {
                warn!("Failed to commit the updated gateway mapping to the database: {e}");
            }
        }
    }

    /// Selects an available gateway by querying the federation's registered
    /// gateways, checking if one of them match the invoice's payee public
    /// key, then queries the gateway for `RoutingInfo` to determine if it is
    /// online.
    pub async fn select_gateway(
        &self,
        invoice: Option<Bolt11Invoice>,
    ) -> Result<(SafeUrl, RoutingInfo), SelectGatewayError> {
        let gateways = self
            .module_api
            .gateways()
            .await
            .map_err(|e| SelectGatewayError::FailedToRequestGateways(e.to_string()))?;

        if gateways.is_empty() {
            return Err(SelectGatewayError::NoGatewaysAvailable);
        }

        if let Some(invoice) = invoice
            && let Some(gateway) = self
                .client_ctx
                .module_db()
                .begin_transaction_nc()
                .await
                .get_value(&GatewayKey(invoice.recover_payee_pub_key()))
                .await
                .filter(|gateway| gateways.contains(gateway))
            && let Ok(Some(routing_info)) = self.routing_info(&gateway).await
        {
            return Ok((gateway, routing_info));
        }

        for gateway in gateways {
            if let Ok(Some(routing_info)) = self.routing_info(&gateway).await {
                return Ok((gateway, routing_info));
            }
        }

        Err(SelectGatewayError::GatewaysUnresponsive)
    }

    /// Sends a request to each peer for their registered gateway list and
    /// returns a `Vec<SafeUrl` of all registered gateways to the client.
    pub async fn list_gateways(
        &self,
        peer: Option<PeerId>,
    ) -> Result<Vec<SafeUrl>, ListGatewaysError> {
        if let Some(peer) = peer {
            self.module_api
                .gateways_from_peer(peer)
                .await
                .map_err(|_| ListGatewaysError::FailedToListGateways)
        } else {
            self.module_api
                .gateways()
                .await
                .map_err(|_| ListGatewaysError::FailedToListGateways)
        }
    }

    /// Requests the `RoutingInfo`, including fee information, from the gateway
    /// available at the `SafeUrl`.
    pub async fn routing_info(
        &self,
        gateway: &SafeUrl,
    ) -> Result<Option<RoutingInfo>, RoutingInfoError> {
        self.gateway_conn
            .routing_info(gateway.clone(), &self.federation_id)
            .await
            .map_err(|_| RoutingInfoError::FailedToRequestRoutingInfo)
    }

    /// Pay an invoice. For testing you can optionally specify a gateway to
    /// route with, otherwise a gateway will be selected automatically. If the
    /// invoice was created by a gateway connected to our federation, the same
    /// gateway will be selected to allow for a direct ecash swap. Otherwise we
    /// select a random online gateway.
    ///
    /// The fee for this payment may depend on the selected gateway but
    /// will be limited to one and a half percent plus one hundred satoshis.
    /// This fee accounts for the fee charged by the gateway as well as
    /// the additional fee required to reliably route this payment over
    /// lightning if necessary. Since the gateway has been vetted by at least
    /// one guardian we trust it to set a reasonable fee and only enforce a
    /// rather high limit.
    ///
    /// The absolute fee for a payment can be calculated from the operation meta
    /// to be shown to the user in the transaction history.
    #[allow(clippy::too_many_lines)]
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

        let (ephemeral_tweak, ephemeral_pk) = tweak::generate(self.keypair.public_key());

        let refund_keypair = SecretKey::from_slice(&ephemeral_tweak)
            .expect("32 bytes, within curve order")
            .keypair(secp256k1::SECP256K1);

        let (gateway_api, routing_info) = match gateway {
            Some(gateway_api) => (
                gateway_api.clone(),
                self.routing_info(&gateway_api)
                    .await
                    .map_err(|e| SendPaymentError::FailedToConnectToGateway(e.to_string()))?
                    .ok_or(SendPaymentError::FederationNotSupported)?,
            ),
            None => self
                .select_gateway(Some(invoice.clone()))
                .await
                .map_err(SendPaymentError::SelectGateway)?,
        };

        let (send_fee, expiration_delta) = routing_info.send_parameters(&invoice);

        if !send_fee.le(&PaymentFee::SEND_FEE_LIMIT) {
            return Err(SendPaymentError::GatewayFeeExceedsLimit);
        }

        if EXPIRATION_DELTA_LIMIT < expiration_delta {
            return Err(SendPaymentError::GatewayExpirationExceedsLimit);
        }

        let consensus_block_count = self
            .module_api
            .consensus_block_count()
            .await
            .map_err(|e| SendPaymentError::FailedToRequestBlockCount(e.to_string()))?;

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

        let client_output = ClientOutput::<LightningOutput> {
            output: LightningOutput::V0(LightningOutputV0::Outgoing(contract.clone())),
            amounts: Amounts::new_bitcoin(contract.amount),
        };

        let client_output_sm = ClientOutputSM::<LightningClientStateMachines> {
            state_machines: Arc::new(move |range: OutPointRange| {
                vec![LightningClientStateMachines::Send(SendStateMachine {
                    common: SendSMCommon {
                        operation_id,
                        outpoint: range.into_iter().next().unwrap(),
                        contract: contract_clone.clone(),
                        gateway_api: Some(gateway_api_clone.clone()),
                        invoice: Some(LightningInvoice::Bolt11(invoice_clone.clone())),
                        refund_keypair,
                    },
                    state: SendSMState::Funding,
                })]
            }),
        };

        let client_output = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
            vec![client_output],
            vec![client_output_sm],
        ));

        let transaction = TransactionBuilder::new().with_outputs(client_output);

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    LightningOperationMeta::Send(SendOperationMeta {
                        change_outpoint_range,
                        gateway: gateway_api.clone(),
                        contract: contract.clone(),
                        invoice: LightningInvoice::Bolt11(invoice.clone()),
                        custom_meta: custom_meta.clone(),
                    })
                },
                transaction,
            )
            .await
            .map_err(|e| SendPaymentError::FailedToFundPayment(e.to_string()))?;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        self.client_ctx
            .log_event(
                &mut dbtx,
                SendPaymentEvent {
                    operation_id,
                    amount: send_fee.add_to(amount),
                    fee: Some(send_fee.fee(amount)),
                },
            )
            .await;

        dbtx.commit_tx().await;

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
                return Err(SendPaymentError::PaymentInProgress(operation_id));
            }

            let mut stream = self
                .subscribe_send_operation_state_updates(operation_id)
                .await
                .expect("operation_id exists")
                .into_stream();

            // This will not block since we checked for active states and there were none,
            // so by definition a final state has to have been assumed already.
            while let Some(state) = stream.next().await {
                if let SendOperationState::Success(_) = state {
                    return Err(SendPaymentError::InvoiceAlreadyPaid(operation_id));
                }
            }
        }

        panic!("We could not find an unused operation id for sending a lightning payment");
    }

    /// Subscribe to all state updates of the send operation.
    pub async fn subscribe_send_operation_state_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<SendOperationState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();
        let module_api = self.module_api.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                loop {
                    if let Some(LightningClientStateMachines::Send(state)) = stream.next().await {
                        match state.state {
                            SendSMState::Funding => yield SendOperationState::Funding,
                            SendSMState::Funded => yield SendOperationState::Funded,
                            SendSMState::Success(preimage) => {
                                // the preimage has been verified by the state machine previously
                                assert!(state.common.contract.verify_preimage(&preimage));

                                yield SendOperationState::Success(preimage);
                                return;
                            },
                            SendSMState::Refunding(out_points) => {
                                yield SendOperationState::Refunding;

                                if client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await.is_ok() {
                                    yield SendOperationState::Refunded;
                                    return;
                                }

                                // The gateway may have incorrectly claimed the outgoing contract thereby causing
                                // our refund transaction to be rejected. Therefore, we check one last time if
                                // the preimage is available before we enter the failure state.
                                if let Some(preimage) = module_api.await_preimage(
                                    state.common.outpoint,
                                    0
                                ).await
                                    && state.common.contract.verify_preimage(&preimage) {
                                        yield SendOperationState::Success(preimage);
                                        return;
                                    }

                                yield SendOperationState::Failure;
                                return;
                            },
                            SendSMState::Rejected(..) => {
                                yield SendOperationState::Failure;
                                return;
                            },
                        }
                    }
                }
            }
        }))
    }

    /// Await the final state of the send operation.
    pub async fn await_final_send_operation_state(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<FinalSendOperationState> {
        let state = self
            .subscribe_send_operation_state_updates(operation_id)
            .await?
            .into_stream()
            .filter_map(|state| {
                futures::future::ready(match state {
                    SendOperationState::Success(_) => Some(FinalSendOperationState::Success),
                    SendOperationState::Refunded => Some(FinalSendOperationState::Refunded),
                    SendOperationState::Failure => Some(FinalSendOperationState::Failure),
                    _ => None,
                })
            })
            .next()
            .await
            .expect("Stream contains one final state");

        Ok(state)
    }

    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a random online gateway will be selected
    /// automatically.
    ///
    /// The total fee for this payment may depend on the chosen gateway but
    /// will be limited to half of one percent plus fifty satoshis. Since the
    /// selected gateway has been vetted by at least one guardian we trust it to
    /// set a reasonable fee and only enforce a rather high limit.
    ///
    /// The absolute fee for a payment can be calculated from the operation meta
    /// to be shown to the user in the transaction history.
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
            .receive_incoming_contract(
                self.keypair.secret_key(),
                contract.clone(),
                LightningOperationMeta::Receive(ReceiveOperationMeta {
                    gateway,
                    contract,
                    invoice: LightningInvoice::Bolt11(invoice.clone()),
                    custom_meta,
                }),
            )
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
        let (ephemeral_tweak, ephemeral_pk) = tweak::generate(recipient_static_pk);

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
                    .map_err(|e| ReceiveError::FailedToConnectToGateway(e.to_string()))?
                    .ok_or(ReceiveError::FederationNotSupported)?,
            ),
            None => self
                .select_gateway(None)
                .await
                .map_err(ReceiveError::SelectGateway)?,
        };

        if !routing_info.receive_fee.le(&PaymentFee::RECEIVE_FEE_LIMIT) {
            return Err(ReceiveError::GatewayFeeExceedsLimit);
        }

        let contract_amount = routing_info.receive_fee.subtract_from(amount.msats);

        if contract_amount < MINIMUM_INCOMING_CONTRACT_AMOUNT {
            return Err(ReceiveError::AmountTooSmall);
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
            .map_err(|e| ReceiveError::FailedToConnectToGateway(e.to_string()))?;

        if invoice.payment_hash() != &preimage.consensus_hash() {
            return Err(ReceiveError::InvalidInvoice);
        }

        if invoice.amount_milli_satoshis() != Some(amount.msats) {
            return Err(ReceiveError::IncorrectInvoiceAmount);
        }

        Ok((gateway, contract, invoice))
    }

    // Receive an incoming contract locked to a public key derived from our
    // static module public key.
    async fn receive_incoming_contract(
        &self,
        sk: SecretKey,
        contract: IncomingContract,
        operation_meta: LightningOperationMeta,
    ) -> Option<OperationId> {
        let operation_id = OperationId::from_encodable(&contract.clone());

        let (claim_keypair, agg_decryption_key) = self.recover_contract_keys(sk, &contract)?;

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
                operation_meta,
                vec![self.client_ctx.make_dyn_state(receive_sm)],
            )
            .await
            .ok();

        Some(operation_id)
    }

    fn recover_contract_keys(
        &self,
        sk: SecretKey,
        contract: &IncomingContract,
    ) -> Option<(Keypair, AggregateDecryptionKey)> {
        let tweak = ecdh::SharedSecret::new(&contract.commitment.ephemeral_pk, &sk);

        let encryption_seed = tweak
            .secret_bytes()
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let claim_keypair = sk
            .mul_tweak(&Scalar::from_be_bytes(tweak.secret_bytes()).expect("Within curve order"))
            .expect("Tweak is valid")
            .keypair(secp256k1::SECP256K1);

        if claim_keypair.public_key() != contract.commitment.claim_pk {
            return None; // The claim key is not derived from our pk
        }

        let agg_decryption_key = derive_agg_dk(&self.cfg.tpe_agg_pk, &encryption_seed);

        if !contract.verify_agg_decryption_key(&self.cfg.tpe_agg_pk, &agg_decryption_key) {
            return None; // The decryption key is not derived from our pk
        }

        contract.decrypt_preimage(&agg_decryption_key)?;

        Some((claim_keypair, agg_decryption_key))
    }

    /// Subscribe to all state updates of the receive operation.
    pub async fn subscribe_receive_operation_state_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<ReceiveOperationState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                loop {
                    if let Some(LightningClientStateMachines::Receive(state)) = stream.next().await {
                        match state.state {
                            ReceiveSMState::Pending => yield ReceiveOperationState::Pending,
                            ReceiveSMState::Claiming(out_points) => {
                                yield ReceiveOperationState::Claiming;

                                if client_ctx.await_primary_module_outputs(operation_id, out_points).await.is_ok() {
                                    yield ReceiveOperationState::Claimed;
                                } else {
                                    yield ReceiveOperationState::Failure;
                                }
                                return;
                            },
                            ReceiveSMState::Expired => {
                                yield ReceiveOperationState::Expired;
                                return;
                            }
                        }
                    }
                }
            }
        }))
    }

    /// Await the final state of the receive operation.
    pub async fn await_final_receive_operation_state(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<FinalReceiveOperationState> {
        let state = self
            .subscribe_receive_operation_state_updates(operation_id)
            .await?
            .into_stream()
            .filter_map(|state| {
                futures::future::ready(match state {
                    ReceiveOperationState::Expired => Some(FinalReceiveOperationState::Expired),
                    ReceiveOperationState::Claimed => Some(FinalReceiveOperationState::Claimed),
                    ReceiveOperationState::Failure => Some(FinalReceiveOperationState::Failure),
                    _ => None,
                })
            })
            .next()
            .await
            .expect("Stream contains one final state");

        Ok(state)
    }

    /// Generate an lnurl for the client. You can optionally specify a gateway
    /// to use for testing purposes.
    pub async fn generate_lnurl(
        &self,
        recurringd: SafeUrl,
        gateway: Option<SafeUrl>,
    ) -> Result<String, GenerateLnurlError> {
        let gateways = if let Some(gateway) = gateway {
            vec![gateway]
        } else {
            let gateways = self
                .module_api
                .gateways()
                .await
                .map_err(|e| GenerateLnurlError::FailedToRequestGateways(e.to_string()))?;

            if gateways.is_empty() {
                return Err(GenerateLnurlError::NoGatewaysAvailable);
            }

            gateways
        };

        let lnurl = lnurl::generate_lnurl(
            &recurringd,
            self.federation_id,
            self.lnurl_keypair.public_key(),
            self.cfg.tpe_agg_pk,
            gateways,
        );

        Ok(lnurl)
    }

    fn spawn_receive_lnurl_task(
        &self,
        custom_meta_fn: Arc<dyn Fn() -> Value + Send + Sync>,
        task_group: &TaskGroup,
    ) {
        let module = self.clone();
        let api = self.module_api.clone();

        task_group.spawn_cancellable("receive_lnurl_task", async move {
            api.wait_for_initialized_connections().await;
            loop {
                module.receive_lnurl(custom_meta_fn()).await;
            }
        });
    }

    async fn receive_lnurl(&self, custom_meta: Value) {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let stream_index = dbtx
            .get_value(&IncomingContractStreamIndexKey)
            .await
            .unwrap_or(0);

        let (contracts, next_index) = self
            .module_api
            .await_incoming_contracts(stream_index, 128)
            .await;

        for contract in &contracts {
            if let Some(operation_id) = self
                .receive_incoming_contract(
                    self.lnurl_keypair.secret_key(),
                    contract.clone(),
                    LightningOperationMeta::LnurlReceive(LnurlReceiveOperationMeta {
                        contract: contract.clone(),
                        custom_meta: custom_meta.clone(),
                    }),
                )
                .await
            {
                self.await_final_receive_operation_state(operation_id)
                    .await
                    .ok();
            }
        }

        dbtx.insert_entry(&IncomingContractStreamIndexKey, &next_index)
            .await;

        dbtx.commit_tx().await;
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SelectGatewayError {
    #[error("Failed to request gateways")]
    FailedToRequestGateways(String),
    #[error("No gateways are available")]
    NoGatewaysAvailable,
    #[error("All gateways failed to respond")]
    GatewaysUnresponsive,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SendPaymentError {
    #[error("Invoice is missing an amount")]
    InvoiceMissingAmount,
    #[error("Invoice has expired")]
    InvoiceExpired,
    #[error("A payment for this invoice is already in progress")]
    PaymentInProgress(OperationId),
    #[error("This invoice has already been paid")]
    InvoiceAlreadyPaid(OperationId),
    #[error(transparent)]
    SelectGateway(SelectGatewayError),
    #[error("Failed to connect to gateway")]
    FailedToConnectToGateway(String),
    #[error("Gateway does not support this federation")]
    FederationNotSupported,
    #[error("Gateway fee exceeds the allowed limit")]
    GatewayFeeExceedsLimit,
    #[error("Gateway expiration time exceeds the allowed limit")]
    GatewayExpirationExceedsLimit,
    #[error("Failed to request block count")]
    FailedToRequestBlockCount(String),
    #[error("Failed to fund the payment")]
    FailedToFundPayment(String),
    #[error("Invoice is for a different currency")]
    WrongCurrency {
        invoice_currency: Currency,
        federation_currency: Currency,
    },
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ReceiveError {
    #[error(transparent)]
    SelectGateway(SelectGatewayError),
    #[error("Failed to connect to gateway")]
    FailedToConnectToGateway(String),
    #[error("Gateway does not support this federation")]
    FederationNotSupported,
    #[error("Gateway fee exceeds the allowed limit")]
    GatewayFeeExceedsLimit,
    #[error("Amount is too small to cover fees")]
    AmountTooSmall,
    #[error("Gateway returned an invalid invoice")]
    InvalidInvoice,
    #[error("Gateway returned an invoice with incorrect amount")]
    IncorrectInvoiceAmount,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum GenerateLnurlError {
    #[error("No gateways are available")]
    NoGatewaysAvailable,
    #[error("Failed to request gateways")]
    FailedToRequestGateways(String),
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ListGatewaysError {
    #[error("Failed to request gateways")]
    FailedToListGateways,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum RoutingInfoError {
    #[error("Failed to request routing info")]
    FailedToRequestRoutingInfo,
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
