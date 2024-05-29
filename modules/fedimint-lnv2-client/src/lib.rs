#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::unused_async)]

pub mod api;
#[cfg(feature = "cli")]
mod cli;
mod receive_sm;
mod send_sm;

use std::sync::Arc;

use async_stream::stream;
use bitcoin::hashes::{sha256, Hash};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiAuth, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, TransactionId};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::{
    LightningClientContext, LightningCommonInit, LightningModuleTypes, LightningOutput,
    LightningOutputV0,
};
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use secp256k1::{ecdh, KeyPair, PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tpe::{derive_agg_decryption_key, AggregateDecryptionKey};

use crate::api::LnFederationApi;
use crate::receive_sm::{ReceiveSMCommon, ReceiveSMState, ReceiveStateMachine};
use crate::send_sm::{SendSMCommon, SendSMState, SendStateMachine};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightningOperationMeta {
    Send {
        funding_txid: TransactionId,
        funding_change_outpoints: Vec<OutPoint>,
        gateway_api: SafeUrl,
        contract: OutgoingContract,
        invoice: Bolt11Invoice,
    },
    Receive {
        contract: IncomingContract,
    },
}

/// Number of blocks until outgoing lightning contracts time out and user
/// client can refund it unilaterally
const EXPIRATION_DELTA_LIMIT_DEFAULT: u64 = 500;

/// Default expiration time for lightning invoices
const INVOICE_EXPIRATION_SECONDS_DEFAULT: u32 = 3600;

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
    Funding,
    Funded,
    Success([u8; 32]),
    Refunding,
    Refunded,
    FundingRejected,
    Failure,
}

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
    Pending,
    Expired,
    Claiming,
    Claimed,
    Failure,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decodable, Encodable)]
pub struct CreateInvoicePayload {
    pub federation_id: FederationId,
    pub contract: IncomingContract,
    pub invoice_amount: Amount,
    pub description: Bolt11InvoiceDescription,
    pub expiry_time: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decodable, Encodable)]
pub enum Bolt11InvoiceDescription {
    Direct(String),
    Hash(sha256::Hash),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub struct SendPaymentPayload {
    pub federation_id: FederationId,
    pub contract: OutgoingContract,
    pub invoice: Bolt11Invoice,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub struct PaymentInfo {
    pub public_key: PublicKey,
    pub send_fee_minimum: PaymentFee,
    pub send_fee_default: PaymentFee,
    pub receive_fee: PaymentFee,
    pub expiration_delta_default: u64,
    pub expiration_delta_minimum: u64,
}

#[derive(
    Debug, Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Decodable, Encodable,
)]
pub struct PaymentFee {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl PaymentFee {
    pub fn one_percent() -> Self {
        PaymentFee {
            base: Amount::ZERO,
            parts_per_million: 10_000,
        }
    }

    pub fn half_of_one_percent() -> Self {
        PaymentFee {
            base: Amount::ZERO,
            parts_per_million: 5_000,
        }
    }

    pub fn add_fee(&self, msats: u64) -> Amount {
        Amount::from_msats(msats.saturating_add(self.fee(msats)))
    }

    pub fn subtract_fee(&self, msats: u64) -> Amount {
        Amount::from_msats(msats.saturating_sub(self.fee(msats)))
    }

    fn fee(&self, msats: u64) -> u64 {
        self.base.msats
            + msats
                .saturating_mul(self.parts_per_million)
                .saturating_div(1_000_000)
    }
}

#[derive(Debug, Clone)]
pub struct LightningClientInit;

impl ModuleInit for LightningClientInit {
    type Common = LightningCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        todo!()
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
        })
    }
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
        }
    }

    fn input_fee(&self, _input: &<Self::Common as ModuleCommon>::Input) -> Option<Amount> {
        Some(self.cfg.fee_consensus.input)
    }

    fn output_fee(&self, _output: &<Self::Common as ModuleCommon>::Output) -> Option<Amount> {
        Some(self.cfg.fee_consensus.output)
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
    let ephemeral_keypair = KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng());

    let ephemeral_tweak = ecdh::shared_secret_point(&static_pk, &ephemeral_keypair.secret_key())
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

    (ephemeral_tweak, ephemeral_keypair.public_key())
}

impl LightningClientModule {
    pub async fn fetch_payment_info(
        &self,
        gateway_api: SafeUrl,
    ) -> Result<Option<PaymentInfo>, GatewayError> {
        reqwest::Client::new()
            .post(
                gateway_api
                    .join("payment_info")
                    .expect("'payment_info' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&self.federation_id)
            .send()
            .await
            .map_err(|e| GatewayError::Unreachable(e.to_string()))?
            .json::<Option<PaymentInfo>>()
            .await
            .map_err(|e| GatewayError::InvalidJsonResponse(e.to_string()))
    }

    pub async fn send(
        &self,
        gateway_api: SafeUrl,
        invoice: Bolt11Invoice,
    ) -> Result<OperationId, SendPaymentError> {
        self.send_internal(
            gateway_api,
            invoice,
            PaymentFee::one_percent(),
            EXPIRATION_DELTA_LIMIT_DEFAULT,
        )
        .await
    }

    pub async fn send_internal(
        &self,
        gateway_api: SafeUrl,
        invoice: Bolt11Invoice,
        payment_fee_limit: PaymentFee,
        expiration_delta_limit: u64,
    ) -> Result<OperationId, SendPaymentError> {
        let invoice_msats = invoice
            .amount_milli_satoshis()
            .ok_or(SendPaymentError::InvoiceMissingAmount)?;

        if invoice.is_expired() {
            return Err(SendPaymentError::InvoiceExpired);
        }

        let operation_id = self.get_next_operation_id(&invoice).await?;

        let (ephemeral_tweak, ephemeral_pk) = generate_ephemeral_tweak(self.keypair.public_key());

        let refund_keypair = SecretKey::from_slice(&ephemeral_tweak)
            .expect("32 bytes, within curve order")
            .keypair(secp256k1::SECP256K1);

        let payment_info = self
            .fetch_payment_info(gateway_api.clone())
            .await
            .map_err(SendPaymentError::GatewayError)?
            .ok_or(SendPaymentError::UnknownFederation)?;

        if !payment_info.send_fee_default.le(&payment_fee_limit) {
            return Err(SendPaymentError::PaymentFeeExceedsLimit(
                payment_info.send_fee_default,
            ));
        }

        if expiration_delta_limit < payment_info.expiration_delta_default {
            return Err(SendPaymentError::ExpirationDeltaExceedsLimit(
                payment_info.expiration_delta_default,
            ));
        }

        let consensus_block_count = self
            .module_api
            .consensus_block_count()
            .await
            .map_err(|e| SendPaymentError::FederationError(e.to_string()))?;

        let contract = OutgoingContract {
            payment_hash: *invoice.payment_hash(),
            amount: payment_info.send_fee_default.add_fee(invoice_msats),
            expiration: consensus_block_count + payment_info.expiration_delta_default,
            claim_pk: payment_info.public_key,
            refund_pk: refund_keypair.public_key(),
            ephemeral_pk,
            invoice_hash: invoice.consensus_hash(),
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
                        invoice: invoice_clone.clone(),
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
                |funding_txid, funding_change_outpoints| LightningOperationMeta::Send {
                    funding_txid,
                    funding_change_outpoints,
                    gateway_api: gateway_api.clone(),
                    contract: contract.clone(),
                    invoice: invoice.clone(),
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
                if let SendState::Success(..) = state {
                    return Err(SendPaymentError::SuccessfulPreviousPayment(operation_id));
                }
            }
        }

        panic!("We could not find an unused operation id for sending a lightning payment");
    }

    pub async fn subscribe_send(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<SendState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();
        let module_api = self.module_api.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, move || {
            stream! {
                loop {
                    if let Some(LightningClientStateMachines::Send(state)) = stream.next().await {
                        match state.state {
                            SendSMState::Funding => yield SendState::Funding,
                            SendSMState::Funded => yield SendState::Funded,
                            SendSMState::Success(preimage) => {
                                // the preimage has been verified by the state machine previously
                                assert!(state.common.contract.verify_preimage(&preimage));

                                yield SendState::Success(preimage);
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
                                        yield SendState::Success(preimage);
                                        return;
                                    }
                                }

                                yield SendState::Failure;
                                return;
                            },
                            SendSMState::Rejected(..) => {
                                yield SendState::FundingRejected;
                                return;
                            },
                        }
                    }
                }
            }
        }))
    }

    pub async fn receive(
        &self,
        gateway_api: SafeUrl,
        invoice_amount: Amount,
    ) -> Result<(Bolt11Invoice, OperationId), FetchInvoiceError> {
        self.receive_internal(
            gateway_api,
            invoice_amount,
            INVOICE_EXPIRATION_SECONDS_DEFAULT,
            Bolt11InvoiceDescription::Direct(String::new()),
            PaymentFee::one_percent(),
        )
        .await
    }

    pub async fn receive_internal(
        &self,
        gateway_api: SafeUrl,
        invoice_amount: Amount,
        expiry_time: u32,
        description: Bolt11InvoiceDescription,
        payment_fee_limit: PaymentFee,
    ) -> Result<(Bolt11Invoice, OperationId), FetchInvoiceError> {
        let (contract, .., invoice) = self
            .create_contract_and_fetch_invoice_internal(
                self.keypair.public_key(),
                gateway_api,
                invoice_amount,
                expiry_time,
                description,
                payment_fee_limit,
            )
            .await?;

        let operation_id = self
            .receive_external_contract(contract)
            .await
            .expect("The contract has been generated with our public key");

        Ok((invoice, operation_id))
    }

    pub async fn create_contract_and_fetch_invoice(
        &self,
        recipient_static_pk: PublicKey,
        gateway_api: SafeUrl,
        invoice_amount: Amount,
    ) -> Result<(IncomingContract, [u8; 32], Bolt11Invoice), FetchInvoiceError> {
        self.create_contract_and_fetch_invoice_internal(
            recipient_static_pk,
            gateway_api,
            invoice_amount,
            INVOICE_EXPIRATION_SECONDS_DEFAULT,
            Bolt11InvoiceDescription::Direct(String::new()),
            PaymentFee::one_percent(),
        )
        .await
    }

    pub async fn create_contract_and_fetch_invoice_internal(
        &self,
        recipient_static_pk: PublicKey,
        gateway_api: SafeUrl,
        invoice_amount: Amount,
        expiry_time: u32,
        description: Bolt11InvoiceDescription,
        payment_fee_limit: PaymentFee,
    ) -> Result<(IncomingContract, [u8; 32], Bolt11Invoice), FetchInvoiceError> {
        let (ephemeral_tweak, ephemeral_pk) = generate_ephemeral_tweak(recipient_static_pk);

        let encryption_seed = ephemeral_tweak
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let preimage = encryption_seed
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let payment_info = self
            .fetch_payment_info(gateway_api.clone())
            .await
            .map_err(FetchInvoiceError::GatewayError)?
            .ok_or(FetchInvoiceError::UnknownFederation)?;

        if !payment_info.receive_fee.le(&payment_fee_limit) {
            return Err(FetchInvoiceError::PaymentFeeExceedsLimit(
                payment_info.receive_fee,
            ));
        }

        let contract_amount = payment_info.receive_fee.subtract_fee(invoice_amount.msats);

        let expiration = duration_since_epoch()
            .as_secs()
            .saturating_add(u64::from(expiry_time));

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
            contract_amount,
            expiration,
            claim_pk,
            payment_info.public_key,
            ephemeral_pk,
        );

        let payload = CreateInvoicePayload {
            federation_id: self.federation_id,
            contract: contract.clone(),
            invoice_amount,
            description,
            expiry_time,
        };

        let invoice = self
            .fetch_invoice(gateway_api, payload)
            .await
            .map_err(FetchInvoiceError::GatewayError)?
            .map_err(FetchInvoiceError::CreateInvoiceError)?;

        if invoice.payment_hash() != &contract.commitment.payment_hash {
            return Err(FetchInvoiceError::InvalidInvoicePaymentHash);
        }

        if invoice.amount_milli_satoshis() != Some(invoice_amount.msats) {
            return Err(FetchInvoiceError::InvalidInvoiceAmount);
        }

        Ok((contract, preimage, invoice))
    }

    async fn fetch_invoice(
        &self,
        gateway_api: SafeUrl,
        payload: CreateInvoicePayload,
    ) -> Result<Result<Bolt11Invoice, String>, GatewayError> {
        reqwest::Client::new()
            .post(
                gateway_api
                    .join("create_invoice")
                    .expect("'create_invoice' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&payload)
            .send()
            .await
            .map_err(|e| GatewayError::Unreachable(e.to_string()))?
            .json::<Result<Bolt11Invoice, String>>()
            .await
            .map_err(|e| GatewayError::InvalidJsonResponse(e.to_string()))
    }

    pub async fn await_incoming_contract(&self, contract: IncomingContract) -> bool {
        self.module_api
            .await_incoming_contract(&contract.contract_id(), contract.commitment.expiration)
            .await
    }

    pub async fn receive_external_contract(
        &self,
        contract: IncomingContract,
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
                LightningOperationMeta::Receive { contract },
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
        let ephemeral_tweak = ecdh::shared_secret_point(
            &contract.commitment.ephemeral_pk,
            &self.keypair.secret_key(),
        )
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

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

    pub async fn subscribe_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<ReceiveState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, move || {
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
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum GatewayError {
    #[error("The gateway is unreachable: {0}")]
    Unreachable(String),
    #[error("The gateway returned an invalid response: {0}")]
    InvalidJsonResponse(String),
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
    #[error("Gateway error: {0}")]
    GatewayError(GatewayError),
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
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum FetchInvoiceError {
    #[error("Gateway error: {0}")]
    GatewayError(GatewayError),
    #[error("The gateway does not support our federation")]
    UnknownFederation,
    #[error("The gateways fee of {0:?} exceeds the supplied limit")]
    PaymentFeeExceedsLimit(PaymentFee),
    #[error("The gateway considered our request for an invoice invalid: {0}")]
    CreateInvoiceError(String),
    #[error("The invoice's payment hash is incorrect")]
    InvalidInvoicePaymentHash,
    #[error("The invoice's amount is incorrect")]
    InvalidInvoiceAmount,
}

#[allow(clippy::large_enum_variant)]
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
