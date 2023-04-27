mod api;
mod db;
pub mod pay;

use std::sync::Arc;

use anyhow::bail;
use api::LnFederationApi;
use async_stream::stream;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::Hash;
use db::LightningGatewayKey;
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::ClientModule;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, OperationId, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, Client, DynGlobalClientContext};
use fedimint_core::api::IFederationApi;
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{Database, ModuleDatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    CommonModuleGen, ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount,
};
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, TransactionId};
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::outgoing::OutgoingContract;
use fedimint_ln_common::contracts::{Contract, ContractId, FundedContract, IdentifiableContract};
pub use fedimint_ln_common::*;
use fedimint_wallet_client::api::WalletFederationApi;
use futures::{pin_mut, StreamExt};
use lightning_invoice::Invoice;
use pay::{LightningPayStateMachine, OutgoingContractAccount, OutgoingContractData};
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{All, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error};

use crate::pay::{LightningPayCommon, LightningPayCreatedOutgoingLnContract, LightningPayStates};

/// Number of blocks until outgoing lightning contracts times out and user
/// client can get refund
const OUTGOING_LN_CONTRACT_TIMELOCK: u64 = 500;

#[apply(async_trait_maybe_send!)]
pub trait LightningClientExt {
    async fn fetch_active_gateway(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> anyhow::Result<LightningGateway>;
    async fn switch_active_gateway(
        &self,
        node_pub_key: Option<secp256k1::PublicKey>,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> anyhow::Result<LightningGateway>;
    async fn fetch_registered_gateways(&self) -> anyhow::Result<Vec<LightningGateway>>;

    async fn pay_bolt11_invoice(
        &self,
        fed_id: FederationId,
        invoice: Invoice,
        active_gateway: LightningGateway,
    ) -> anyhow::Result<OperationId>;

    async fn subscribe_ln_pay_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<BoxStream<LnPayState>>;
}

/// The high-level state of a reissue operation started with
/// [`LightningClientExt::pay_bolt11_invoice`].
#[derive(Debug, Clone)]
pub enum LnPayState {
    Created,
    Canceled,
    Funded,
    WaitingForRefund { block_height: u32 },
    Success { preimage: String },
    Refunded { refund_txid: TransactionId },
    Failed,
}

#[apply(async_trait_maybe_send!)]
impl LightningClientExt for Client {
    async fn fetch_active_gateway(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> anyhow::Result<LightningGateway> {
        // FIXME: forgetting about old gws might not always be ideal. We assume that the
        // gateway stays the same except for route hints for now.
        if let Some(gateway) = dbtx
            .get_value(&LightningGatewayKey)
            .await
            .filter(|gw| gw.valid_until > fedimint_core::time::now())
        {
            return Ok(gateway);
        }

        self.switch_active_gateway(None, dbtx).await
    }

    /// Switches the clients active gateway to a registered gateway with the
    /// given node pubkey. If no pubkey is given (node_pub_key == None) the
    /// first available registered gateway is activated. This behavior is
    /// useful for scenarios where we don't know any registered gateways in
    /// advance.
    async fn switch_active_gateway(
        &self,
        node_pub_key: Option<secp256k1::PublicKey>,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> anyhow::Result<LightningGateway> {
        let gateways = self.fetch_registered_gateways().await?;
        if gateways.is_empty() {
            debug!("Could not find any gateways");
            return Err(anyhow::anyhow!("Could not find any gateways"));
        };
        let gateway = match node_pub_key {
            // If a pubkey was provided, try to select and activate a gateway with that pubkey.
            Some(pub_key) => gateways
                .into_iter()
                .find(|g| g.node_pub_key == pub_key)
                .ok_or_else(|| {
                    debug!("Could not find gateway with public key {:?}", pub_key);
                    anyhow::anyhow!("Could not find gateway with public key {:?}", pub_key)
                })?,
            // Otherwise (no pubkey provided), select and activate the first registered gateway.
            None => {
                debug!("No public key for gateway supplied, using first registered one");
                gateways[0].clone()
            }
        };
        dbtx.insert_entry(&LightningGatewayKey, &gateway).await;
        Ok(gateway)
    }

    async fn fetch_registered_gateways(&self) -> anyhow::Result<Vec<LightningGateway>> {
        Ok(self.api().fetch_gateways().await?)
    }

    async fn pay_bolt11_invoice(
        &self,
        fed_id: FederationId,
        invoice: Invoice,
        active_gateway: LightningGateway,
    ) -> anyhow::Result<OperationId> {
        let operation_id = invoice.payment_hash().into_inner();
        let (ln_client_id, ln_client) = ln_client(self);

        let output = ln_client
            .create_outgoing_output(
                operation_id,
                self.api(),
                invoice,
                active_gateway,
                fed_id,
                rand::rngs::OsRng,
            )
            .await?;

        let tx = TransactionBuilder::new().with_output(output.into_dyn(ln_client_id));
        let operation_meta_gen = |txid| OutPoint { txid, out_idx: 0 };

        let txid = self
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonGen::KIND.as_str(),
                operation_meta_gen,
                tx,
            )
            .await?;

        let mut dbtx = self.db().begin_transaction().await;
        self.add_operation_log_entry(
            &mut dbtx,
            operation_id,
            LightningCommonGen::KIND.as_str(),
            LightningMeta::Pay {
                out_point: OutPoint { txid, out_idx: 0 },
            },
        )
        .await;
        dbtx.commit_tx().await;

        Ok(operation_id)
    }

    async fn subscribe_ln_pay_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<BoxStream<LnPayState>> {
        let out_point = match ln_operation(self, operation_id).await? {
            LightningMeta::Pay { out_point } => out_point,
        };

        let (_, lightning_client) = ln_client(self);

        let tx_accepted_future = self
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(out_point.txid);
        let payment_success = lightning_client.await_payment_success(operation_id);

        let refund_success = lightning_client.await_refund(operation_id);

        Ok(Box::pin(stream! {
            yield LnPayState::Created;

            match tx_accepted_future.await {
                Ok(()) => {
                    yield LnPayState::Funded;

                    // await success or waiting for refund
                    match payment_success.await {
                        Ok(preimage) => {
                            yield LnPayState::Success {preimage };
                        }
                        Err(LightningPayError::Refundable(refundable)) => {
                            yield LnPayState::WaitingForRefund{ block_height: refundable };

                            // in case of refund, await output of refund
                            match refund_success.await {
                                Ok(refund_txid) => {
                                    yield LnPayState::Refunded { refund_txid };
                                }
                                Err(_) => {
                                    yield LnPayState::Failed;
                                }
                            }
                        }
                        Err(_) => {
                            error!("Unexpected error state after funding transaction");
                        }
                    }

                },
                Err(()) => {
                    yield LnPayState::Canceled;
                }
            }
        }))
    }
}

fn ln_client(client: &Client) -> (ModuleInstanceId, &LightningClientModule) {
    let ln_client_instance = client
        .get_first_instance(&LightningCommonGen::KIND)
        .expect("No ln module attached to client");

    let ln_client = client
        .get_module_client::<LightningClientModule>(ln_client_instance)
        .expect("Instance ID exists, we just fetched it");

    (ln_client_instance, ln_client)
}

async fn ln_operation(client: &Client, operation_id: OperationId) -> anyhow::Result<LightningMeta> {
    let operation = client
        .get_operation(operation_id)
        .await
        .ok_or(anyhow::anyhow!("Operation not found"))?;

    if operation.operation_type() != LightningCommonGen::KIND.as_str() {
        bail!("Operation is not a lightning operation");
    }

    Ok(operation.meta())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum LightningMeta {
    Pay { out_point: OutPoint },
}

#[derive(Debug, Clone)]
pub struct LightningClientGen;

impl ExtendsCommonModuleGen for LightningClientGen {
    type Common = LightningCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for LightningClientGen {
    type Module = LightningClientModule;
    type Config = LightningClientConfig;

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        _module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<Self::Module> {
        Ok(LightningClientModule { cfg, notifier })
    }
}
#[derive(Debug, Clone)]
pub struct LightningClientContext {
    secp: Secp256k1<All>,
}

impl Context for LightningClientContext {}

impl LightningClientContext {
    pub async fn get_outgoing_contract(
        id: ContractId,
        global_context: DynGlobalClientContext,
    ) -> anyhow::Result<OutgoingContractAccount> {
        let account = global_context.api().fetch_contract(id).await?;
        match account.contract {
            FundedContract::Outgoing(c) => Ok(OutgoingContractAccount {
                amount: account.amount,
                contract: c,
            }),
            _ => Err(anyhow::anyhow!("WrongAccountType")),
        }
    }
}

#[derive(Debug)]
pub struct LightningClientModule {
    cfg: LightningClientConfig,
    notifier: ModuleNotifier<DynGlobalClientContext, LightningClientStateMachines>,
}

impl ClientModule for LightningClientModule {
    type Common = LightningModuleTypes;
    type ModuleStateMachineContext = LightningClientContext;
    type States = LightningClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        LightningClientContext {
            secp: secp256k1_zkp::Secp256k1::new(),
        }
    }

    fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.amount,
            fee: self.cfg.fee_consensus.contract_input,
        }
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        match output {
            LightningOutput::Contract(account_output) => TransactionItemAmount {
                amount: account_output.amount,
                fee: self.cfg.fee_consensus.contract_output,
            },
            LightningOutput::Offer(_) | LightningOutput::CancelOutgoing { .. } => {
                TransactionItemAmount {
                    amount: Amount::ZERO,
                    fee: Amount::ZERO,
                }
            }
        }
    }
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum LightningPayError {
    #[error("Lightning payment was canceled")]
    Canceled,
    #[error("Lightning payment was refunded")]
    Refunded(TransactionId),
    #[error("Lightning payment waiting for refund")]
    Refundable(u32),
    #[error("Lightning payment failed")]
    Failed(String),
}

impl LightningClientModule {
    /// Create an output that incentivizes a Lighning gateway to pay an invoice
    /// for us. It has time till the block height defined by `timelock`,
    /// after that we can claim our money back.
    pub async fn create_outgoing_output<'a, 'b>(
        &'a self,
        operation_id: OperationId,
        api: &(dyn IFederationApi + 'static),
        invoice: Invoice,
        gateway: LightningGateway,
        fed_id: FederationId,
        mut rng: impl RngCore + CryptoRng + 'a,
    ) -> anyhow::Result<ClientOutput<LightningOutput, LightningClientStateMachines>> {
        let consensus_height = api.fetch_consensus_block_height().await?;
        let absolute_timelock = consensus_height + OUTGOING_LN_CONTRACT_TIMELOCK;

        let contract_amount = {
            let invoice_amount_msat = invoice
                .amount_milli_satoshis()
                .ok_or(anyhow::anyhow!("MissingInvoiceAmount"))?;
            // TODO: better define fee handling
            // Add 1% fee margin
            let contract_amount_msat = invoice_amount_msat + (invoice_amount_msat / 100);
            Amount::from_msats(contract_amount_msat)
        };

        let user_sk = bitcoin::KeyPair::new(&self.context().secp, &mut rng);

        let contract = OutgoingContract {
            hash: *invoice.payment_hash(),
            gateway_key: gateway.mint_pub_key,
            timelock: absolute_timelock as u32,
            user_key: user_sk.x_only_public_key().0,
            invoice,
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
            vec![LightningClientStateMachines::Pay(
                LightningPayStateMachine {
                    common: LightningPayCommon {
                        operation_id,
                        federation_id: fed_id,
                        contract: outgoing_payment.clone(),
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

        let ln_output = LightningOutput::Contract(ContractOutput {
            amount: contract_amount,
            contract: Contract::Outgoing(contract),
        });

        Ok(ClientOutput {
            output: ln_output,
            state_machines: sm_gen,
        })
    }

    // Wait for the Lightning invoice to be paid successfully or waiting for refund
    async fn await_payment_success(
        &self,
        operation_id: OperationId,
    ) -> Result<String, LightningPayError> {
        let stream = self
            .notifier
            .subscribe(operation_id)
            .await
            .filter_map(|state| async move {
                let LightningClientStateMachines::Pay(state) = state;

                match state.state {
                    LightningPayStates::Success(preimage) => Some(Ok(preimage)),
                    LightningPayStates::Refundable(refundable) => Some(Err(
                        LightningPayError::Refundable(refundable.block_timelock),
                    )),
                    _ => None,
                }
            });

        pin_mut!(stream);
        stream.next_or_pending().await
    }

    async fn await_refund(
        &self,
        operation_id: OperationId,
    ) -> Result<TransactionId, LightningPayError> {
        let stream = self
            .notifier
            .subscribe(operation_id)
            .await
            .filter_map(|state| async move {
                let LightningClientStateMachines::Pay(state) = state;

                match state.state {
                    LightningPayStates::Refunded(refund_txid) => Some(Ok(refund_txid)),
                    LightningPayStates::Failure(reason) => {
                        Some(Err(LightningPayError::Failed(reason)))
                    }
                    _ => None,
                }
            });

        pin_mut!(stream);

        stream.next_or_pending().await
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LightningClientStateMachines {
    Pay(LightningPayStateMachine),
}

impl IntoDynInstance for LightningClientStateMachines {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for LightningClientStateMachines {
    type ModuleContext = LightningClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            LightningClientStateMachines::Pay(pay_state) => {
                sm_enum_variant_translation!(
                    pay_state.transitions(context, global_context),
                    LightningClientStateMachines::Pay
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            LightningClientStateMachines::Pay(pay_state) => pay_state.operation_id(),
        }
    }
}
