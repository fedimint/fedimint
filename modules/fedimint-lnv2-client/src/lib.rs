pub mod api;
mod receive_sm;
mod send_sm;

use std::sync::Arc;

use anyhow::{anyhow, ensure, Context};
use async_stream::stream;
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::api::DynModuleApi;
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, TransactionId};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::{
    LightningClientContext, LightningCommonInit, LightningModuleTypes, LightningOutput,
};
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use secp256k1::{ecdh, KeyPair, PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
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
        operation_id: OperationId,
        contract: IncomingContract,
    },
}

/// Number of blocks until outgoing lightning contracts time out and user
/// client can refund it unilaterally
const SEND_EXPIRATION_DELTA_BLOCKS_DEFAULT: u64 = 500;

/// Default expiration time for lightning invoices
const INVOICE_EXPIRATION_SECONDS_DEFAULT: u32 = 3600;

/// The high-level state of an payment operation over lightning
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendState {
    Funding,
    Funded,
    Success([u8; 32]),
    Refunding,
    Refunded,
    FundingRejected,
    Failure,
}

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
    pub description: String,
    pub expiry_time: u32,
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
    pub payment_fees: PaymentFees,
    pub outgoing_cltv_delta: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub struct PaymentFees {
    pub send: PaymentFee,
    pub receive: PaymentFee,
}

#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Decodable, Encodable,
)]
pub struct PaymentFee {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl PaymentFee {
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

impl Default for PaymentFee {
    fn default() -> Self {
        PaymentFee {
            base: Amount::from_sats(50),
            parts_per_million: 10_000,
        }
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
}

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

    fn input_amount(
        &self,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        Some(TransactionItemAmount {
            amount: input.amount,
            fee: self.cfg.fee_consensus.input,
        })
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        Some(TransactionItemAmount {
            amount: output.amount(),
            fee: self.cfg.fee_consensus.output,
        })
    }
}

fn generate_ephemeral_tweak(static_pk: PublicKey) -> ([u8; 32], PublicKey) {
    let ephemeral_keypair = KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng());

    let ephemeral_tweak = ecdh::shared_secret_point(&static_pk, &ephemeral_keypair.secret_key())
        .consensus_hash::<sha256::Hash>()
        .into_inner();

    (ephemeral_tweak, ephemeral_keypair.public_key())
}

impl LightningClientModule {
    pub async fn payment_info(&self, gateway_api: SafeUrl) -> anyhow::Result<PaymentInfo> {
        reqwest::Client::new()
            .post(
                gateway_api
                    .join("payment_info")
                    .expect("'payment_info' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&self.federation_id)
            .send()
            .await?
            .json::<Option<PaymentInfo>>()
            .await?
            .ok_or(anyhow!("The gateway does not support our federation"))
    }

    pub async fn send(
        &self,
        gateway_api: SafeUrl,
        invoice: Bolt11Invoice,
    ) -> anyhow::Result<OperationId> {
        self.send_internal(
            gateway_api,
            invoice,
            PaymentFee::default(),
            SEND_EXPIRATION_DELTA_BLOCKS_DEFAULT,
        )
        .await
    }

    pub async fn send_internal(
        &self,
        gateway_api: SafeUrl,
        invoice: Bolt11Invoice,
        payment_fee: PaymentFee,
        expiration_delta: u64,
    ) -> anyhow::Result<OperationId> {
        let (ephemeral_tweak, ephemeral_pk) = generate_ephemeral_tweak(self.keypair.public_key());

        let refund_keypair = SecretKey::from_slice(&ephemeral_tweak)
            .expect("32 bytes, within curve order")
            .keypair(secp256k1::SECP256K1);

        let payment_info = self
            .payment_info(gateway_api.clone())
            .await
            .context("Gateway is offline")?;

        ensure!(
            payment_fee >= payment_info.payment_fees.send,
            "The gateway send fee is above {payment_fee:?}"
        );

        // we double it to account for cltv expiry deltas along the lightning route
        let min_outgoing_cltv_delta = 2 * payment_info.outgoing_cltv_delta;

        ensure!(
            min_outgoing_cltv_delta <= expiration_delta,
            "The minimum possible expiration delta is {min_outgoing_cltv_delta} blocks"
        );

        let consensus_block_count = self
            .module_api
            .consensus_block_count()
            .await
            .context("Failed to fetch the consensus block count from the federation")?;

        let invoice_msats = invoice
            .amount_milli_satoshis()
            .ok_or(anyhow!("Invoice has no amount"))?;

        let contract = OutgoingContract {
            payment_hash: *invoice.payment_hash(),
            amount: payment_fee.add_fee(invoice_msats),
            expiration: consensus_block_count + expiration_delta,
            claim_pk: payment_info.public_key,
            refund_pk: refund_keypair.public_key(),
            ephemeral_pk,
            invoice_hash: invoice.consensus_hash(),
        };

        let operation_id = OperationId(contract.consensus_hash::<sha256::Hash>().into_inner());

        let contract_clone = contract.clone();
        let gateway_api_clone = gateway_api.clone();
        let invoice_clone = invoice.clone();

        let client_output = ClientOutput::<LightningOutput, LightningClientStateMachines> {
            output: LightningOutput::Outgoing(contract.clone()),
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
            .await?;

        Ok(operation_id)
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

                                match client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await {
                                    Ok(..) => {
                                        yield SendState::Refunded;
                                        return;
                                    },
                                    Err(..) => {
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
                                }
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
    ) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
        self.receive_internal(
            gateway_api,
            invoice_amount,
            INVOICE_EXPIRATION_SECONDS_DEFAULT,
            String::new(),
            PaymentFee::default(),
        )
        .await
    }

    pub async fn receive_internal(
        &self,
        gateway_api: SafeUrl,
        invoice_amount: Amount,
        expiry_time: u32,
        description: String,
        max_payment_fee: PaymentFee,
    ) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
        let (contract, invoice) = self
            .create_contract_and_fetch_invoice_internal(
                self.keypair.public_key(),
                gateway_api,
                invoice_amount,
                expiry_time,
                description,
                max_payment_fee,
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
    ) -> anyhow::Result<(IncomingContract, Bolt11Invoice)> {
        self.create_contract_and_fetch_invoice_internal(
            recipient_static_pk,
            gateway_api,
            invoice_amount,
            INVOICE_EXPIRATION_SECONDS_DEFAULT,
            String::new(),
            PaymentFee::default(),
        )
        .await
    }

    pub async fn create_contract_and_fetch_invoice_internal(
        &self,
        recipient_static_pk: PublicKey,
        gateway_api: SafeUrl,
        invoice_amount: Amount,
        expiry_time: u32,
        description: String,
        max_payment_fee: PaymentFee,
    ) -> anyhow::Result<(IncomingContract, Bolt11Invoice)> {
        let (ephemeral_tweak, ephemeral_pk) = generate_ephemeral_tweak(recipient_static_pk);

        let encryption_seed = ephemeral_tweak
            .consensus_hash::<sha256::Hash>()
            .into_inner();

        let preimage = encryption_seed
            .consensus_hash::<sha256::Hash>()
            .into_inner();

        let payment_info = self.payment_info(gateway_api.clone()).await?;

        ensure!(
            max_payment_fee >= payment_info.payment_fees.receive,
            "The gateways receive fee is above {max_payment_fee:?}"
        );

        let contract_amount = payment_info
            .payment_fees
            .receive
            .subtract_fee(invoice_amount.msats);

        let expiration = duration_since_epoch()
            .as_secs()
            .saturating_add(expiry_time as u64);

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

        let invoice = reqwest::Client::new()
            .post(
                gateway_api
                    .join("create_invoice")
                    .expect("'create_invoice' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&payload)
            .send()
            .await?
            .json::<anyhow::Result<Bolt11Invoice, String>>()
            .await?
            .map_err(|error| anyhow!(error))?;

        ensure!(
            invoice.payment_hash() == &contract.commitment.payment_hash,
            "Invoice's payment hash does not match the contract's payment hash"
        );

        ensure!(
            invoice.amount_milli_satoshis() == Some(invoice_amount.msats),
            "Invoice's amount does not match the requested amount"
        );

        Ok((contract, invoice))
    }

    pub async fn receive_external_contract(
        &self,
        contract: IncomingContract,
    ) -> anyhow::Result<OperationId> {
        let operation_id = OperationId(contract.consensus_hash::<sha256::Hash>().into_inner());

        let (claim_keypair, agg_decryption_key) =
            self.recover_incoming_contract_keys(&contract).await?;

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
                LightningOperationMeta::Receive {
                    operation_id,
                    contract,
                },
                vec![self.client_ctx.make_dyn_state(receive_sm)],
            )
            .await
            .ok();

        Ok(operation_id)
    }

    async fn recover_incoming_contract_keys(
        &self,
        contract: &IncomingContract,
    ) -> anyhow::Result<(KeyPair, AggregateDecryptionKey)> {
        let secret = ecdh::shared_secret_point(
            &contract.commitment.ephemeral_pk,
            &self.keypair.secret_key(),
        );

        let ephemeral_tweak = secret.consensus_hash::<sha256::Hash>().into_inner();
        let encryption_seed = ephemeral_tweak
            .consensus_hash::<sha256::Hash>()
            .into_inner();

        let claim_keypair = self
            .keypair
            .secret_key()
            .mul_tweak(&Scalar::from_be_bytes(ephemeral_tweak).expect("Within curve order"))
            .expect("Tweak is valid")
            .keypair(secp256k1::SECP256K1);

        ensure!(
            claim_keypair.public_key() == contract.commitment.claim_pk,
            "The claim key has not been derived from our public key"
        );

        let agg_decryption_key = derive_agg_decryption_key(&self.cfg.tpe_agg_pk, &encryption_seed);

        ensure!(
            contract.verify_agg_decryption_key(&self.cfg.tpe_agg_pk, &agg_decryption_key),
            "The aggregate decryption key has not been derived correctly"
        );

        Ok((claim_keypair, agg_decryption_key))
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

                                match client_ctx.await_primary_module_outputs(operation_id, out_points).await {
                                    Ok(..) => {
                                        yield ReceiveState::Claimed;
                                        return;
                                    }
                                    Err(..) => {
                                        yield ReceiveState::Failure;
                                        return;
                                    }
                                }
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
