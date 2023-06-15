mod db;
pub mod pay;
pub mod receive;

use std::iter::once;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, ensure, format_err};
use async_stream::stream;
use bitcoin::{KeyPair, Network};
use bitcoin_hashes::Hash;
use db::LightningGatewayKey;
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::{ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, OperationId, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, Client, DynGlobalClientContext};
use fedimint_core::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    CommonModuleGen, ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount,
};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, TransactionId};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::outgoing::{
    OutgoingContract, OutgoingContractAccount, OutgoingContractData,
};
use fedimint_ln_common::contracts::{
    Contract, ContractId, EncryptedPreimage, IdentifiableContract, Preimage,
};
pub use fedimint_ln_common::*;
use futures::StreamExt;
use itertools::Itertools;
use lightning::ln::PaymentSecret;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning_invoice::{Currency, Invoice, InvoiceBuilder, DEFAULT_EXPIRY_TIME};
use pay::{GatewayPayError, LightningPayStateMachine};
use rand::{CryptoRng, Rng, RngCore};
use receive::{LightningReceiveError, LightningReceiveStateMachine};
use secp256k1_zkp::{All, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error};

use crate::pay::{LightningPayCommon, LightningPayCreatedOutgoingLnContract, LightningPayStates};
use crate::receive::{LightningReceiveStates, LightningReceiveSubmittedOffer};

/// Number of blocks until outgoing lightning contracts times out and user
/// client can get refund
const OUTGOING_LN_CONTRACT_TIMELOCK: u64 = 500;

#[apply(async_trait_maybe_send!)]
pub trait LightningClientExt {
    /// The set active gateway, or a random one if none has been set
    async fn select_active_gateway(&self) -> anyhow::Result<LightningGateway>;

    /// Sets the gateway to be used by all other operations
    async fn set_active_gateway(&self, node_pub_key: &secp256k1::PublicKey) -> anyhow::Result<()>;

    /// Gateways actively registered with the fed
    async fn fetch_registered_gateways(&self) -> anyhow::Result<Vec<LightningGateway>>;

    /// Pays a LN invoice with our available funds
    async fn pay_bolt11_invoice(
        &self,
        invoice: Invoice,
    ) -> anyhow::Result<(OperationId, ContractId)>;

    async fn subscribe_ln_pay(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, LnPayState>>;

    /// Receive over LN with a new invoice
    async fn create_bolt11_invoice(
        &self,
        amount: Amount,
        description: String,
        expiry_time: Option<u64>,
    ) -> anyhow::Result<(OperationId, Invoice)>;

    async fn subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, LnReceiveState>>;
}

/// The high-level state of a reissue operation started with
/// [`LightningClientExt::pay_bolt11_invoice`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum LnPayState {
    Created,
    Canceled,
    Funded,
    WaitingForRefund {
        block_height: u32,
        gateway_error: GatewayPayError,
    },
    AwaitingChange,
    Success {
        preimage: String,
    },
    Refunded {
        gateway_error: GatewayPayError,
    },
    Failed,
}

/// The high-level state of a reissue operation started with
/// [`LightningClientExt::create_bolt11_invoice`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum LnReceiveState {
    Created,
    WaitingForPayment { invoice: String, timeout: Duration },
    Canceled { reason: LightningReceiveError },
    Funded,
    AwaitingFunds,
    Claimed,
}

#[apply(async_trait_maybe_send!)]
impl LightningClientExt for Client {
    async fn select_active_gateway(&self) -> anyhow::Result<LightningGateway> {
        let (_lightning, instance) = self.get_first_module::<LightningClientModule>(&KIND);
        let mut dbtx = instance.db.begin_transaction().await;
        match dbtx.get_value(&LightningGatewayKey).await {
            Some(active_gateway) => Ok(active_gateway),
            None => self
                .fetch_registered_gateways()
                .await?
                .into_iter()
                .find_or_first(|gw| gw.valid_until <= fedimint_core::time::now())
                .ok_or(anyhow::anyhow!("Could not find any gateways")),
        }
    }

    /// Switches the clients active gateway to a registered gateway.
    async fn set_active_gateway(&self, node_pub_key: &secp256k1::PublicKey) -> anyhow::Result<()> {
        let (_lightning, instance) = self.get_first_module::<LightningClientModule>(&KIND);
        let mut dbtx = instance.db.begin_transaction().await;

        let gateways = self.fetch_registered_gateways().await?;
        if gateways.is_empty() {
            debug!("Could not find any gateways");
            return Err(anyhow::anyhow!("Could not find any gateways"));
        };
        let gateway = gateways
            .into_iter()
            .find(|g| &g.node_pub_key == node_pub_key)
            .ok_or_else(|| {
                anyhow::anyhow!("Could not find gateway with public key {:?}", node_pub_key)
            })?;

        dbtx.insert_entry(&LightningGatewayKey, &gateway).await;
        dbtx.commit_tx().await;
        Ok(())
    }

    async fn fetch_registered_gateways(&self) -> anyhow::Result<Vec<LightningGateway>> {
        let (_lightning, instance) = self.get_first_module::<LightningClientModule>(&KIND);
        Ok(instance.api.fetch_gateways().await?)
    }

    async fn pay_bolt11_invoice(
        &self,
        invoice: Invoice,
    ) -> anyhow::Result<(OperationId, ContractId)> {
        let (lightning, instance) = self.get_first_module::<LightningClientModule>(&KIND);
        let operation_id = OperationId(invoice.payment_hash().into_inner());
        let active_gateway = self.select_active_gateway().await?;

        let (output, contract_id) = lightning
            .create_outgoing_output(
                operation_id,
                instance.api,
                invoice.clone(),
                active_gateway,
                self.get_config().await.federation_id,
                rand::rngs::OsRng,
            )
            .await?;

        let tx = TransactionBuilder::new().with_output(output.into_dyn(instance.id));
        let operation_meta_gen = |txid, change_outpoint| LightningMeta::Pay {
            out_point: OutPoint { txid, out_idx: 0 },
            invoice: invoice.clone(),
            change_outpoint,
        };

        self.finalize_and_submit_transaction(
            operation_id,
            LightningCommonGen::KIND.as_str(),
            operation_meta_gen,
            tx,
        )
        .await?;

        Ok((operation_id, contract_id))
    }

    async fn create_bolt11_invoice(
        &self,
        amount: Amount,
        description: String,
        expiry_time: Option<u64>,
    ) -> anyhow::Result<(OperationId, Invoice)> {
        let (lightning, instance) = self.get_first_module::<LightningClientModule>(&KIND);
        let active_gateway = self.select_active_gateway().await?;

        let (operation_id, invoice, output) = lightning
            .create_lightning_receive_output(
                amount,
                description,
                rand::rngs::OsRng,
                expiry_time,
                active_gateway,
                lightning.cfg.network,
            )
            .await?;
        let tx = TransactionBuilder::new().with_output(output.into_dyn(instance.id));
        let operation_meta_gen = |txid, _| LightningMeta::Receive {
            out_point: OutPoint { txid, out_idx: 0 },
            invoice: invoice.clone(),
        };
        let txid = self
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonGen::KIND.as_str(),
                operation_meta_gen,
                tx,
            )
            .await?;

        // Wait for the transaction to be accepted by the federation, otherwise the
        // invoice will not be able to be paid
        self.transaction_updates(operation_id)
            .await
            .await_tx_accepted(txid)
            .await
            .map_err(|e| anyhow::anyhow!("Offer transaction was not accepted: {e:?}"))?;

        Ok((operation_id, invoice))
    }

    async fn subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, LnReceiveState>> {
        let (lightning, _instance) = self.get_first_module::<LightningClientModule>(&KIND);

        let operation = ln_operation(self, operation_id).await?;
        let (out_point, invoice) = match operation.meta::<LightningMeta>() {
            LightningMeta::Receive { out_point, invoice } => (out_point, invoice),
            _ => bail!("Operation is not a lightning payment"),
        };

        let tx_accepted_future = self
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(out_point.txid);

        let receive_success = lightning.await_receive_success(operation_id);
        let claim_acceptance = lightning.await_claim_acceptance(operation_id);

        Ok(operation.outcome_or_updates(self.db(), operation_id, || {
            stream! {
                    yield LnReceiveState::Created;

                    if tx_accepted_future.await.is_err() {
                    yield LnReceiveState::Canceled { reason: LightningReceiveError::Rejected };
                        return;
                }
                            yield LnReceiveState::WaitingForPayment { invoice: invoice.to_string(), timeout: invoice.expiry_time() };

                            match receive_success.await {
                                Ok(()) => {
                                    yield LnReceiveState::Funded;

                        if let Ok(txid) = claim_acceptance.await {
                            yield LnReceiveState::AwaitingFunds;

                            if self.await_primary_module_output(operation_id, OutPoint{ txid, out_idx: 0}).await.is_ok() {
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
            }}
        ))
    }

    async fn subscribe_ln_pay(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, LnPayState>> {
        let (lightning, _instance) = self.get_first_module::<LightningClientModule>(&KIND);

        let operation = ln_operation(self, operation_id).await?;
        let (out_point, _, change_outpoint) = match operation.meta::<LightningMeta>() {
            LightningMeta::Pay {
                out_point,
                invoice,
                change_outpoint,
            } => (out_point, invoice, change_outpoint),
            _ => bail!("Operation is not a lightning payment"),
        };

        let tx_accepted_future = self
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(out_point.txid);
        let payment_success = lightning.await_payment_success(operation_id);

        let refund_success = lightning.await_refund(operation_id);

        Ok(operation.outcome_or_updates(self.db(), operation_id, || {
            stream! {
                    yield LnPayState::Created;

                    if tx_accepted_future.await.is_err() {
                    yield LnPayState::Canceled;
                        return;
                }
                            yield LnPayState::Funded;

                match payment_success.await {
                    Ok(preimage) => {
                        if let Some(change) = change_outpoint {
                            yield LnPayState::AwaitingChange;
                            match self.await_primary_module_output(operation_id, change).await {
                                Ok(_) => {}
                                Err(_) => {
                                    yield LnPayState::Failed;
                                    return;
                                }
                            }
                        }

                        yield LnPayState::Success {preimage};
                        return;
                    }
                    Err(LightningPayError::Refundable(block_height, error)) => {
                        yield LnPayState::WaitingForRefund{ block_height, gateway_error: error.clone() };

                        if let Ok(refund_txid) = refund_success.await {
                            // need to await primary module to get refund
                            if self.await_primary_module_output(operation_id, OutPoint{ txid: refund_txid, out_idx: 0}).await.is_ok() {
                                yield LnPayState::Refunded { gateway_error: error };
                                return;
                            }
                        }
                    }
                    _ => {}
                }

                yield LnPayState::Failed;
            }
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LightningMeta {
    Pay {
        out_point: OutPoint,
        invoice: Invoice,
        change_outpoint: Option<OutPoint>,
    },
    Receive {
        out_point: OutPoint,
        invoice: Invoice,
    },
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
        _api: DynGlobalApi,
        _module_api: DynModuleApi,
    ) -> anyhow::Result<Self::Module> {
        Ok(LightningClientModule {
            cfg,
            notifier,
            secp: secp256k1_zkp::Secp256k1::new(),
        })
    }
}
#[derive(Debug, Clone)]
pub struct LightningClientContext {
    pub ln_decoder: Decoder,
}

impl Context for LightningClientContext {}

#[derive(Debug)]
pub struct LightningClientModule {
    pub cfg: LightningClientConfig,
    notifier: ModuleNotifier<DynGlobalClientContext, LightningClientStateMachines>,
    secp: Secp256k1<All>,
}

impl ClientModule for LightningClientModule {
    type Common = LightningModuleTypes;
    type ModuleStateMachineContext = LightningClientContext;
    type States = LightningClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        LightningClientContext {
            ln_decoder: self.decoder(),
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
    Refundable(u32, GatewayPayError),
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
        api: DynModuleApi,
        invoice: Invoice,
        gateway: LightningGateway,
        fed_id: FederationId,
        mut rng: impl RngCore + CryptoRng + 'a,
    ) -> anyhow::Result<(
        ClientOutput<LightningOutput, LightningClientStateMachines>,
        ContractId,
    )> {
        let federation_currency = network_to_currency(self.cfg.network);
        let invoice_currency = invoice.currency();
        ensure!(
            federation_currency == invoice_currency,
            "Invalid invoice currency: expected={:?}, got={:?}",
            federation_currency,
            invoice_currency
        );

        let consensus_height = api
            .fetch_consensus_block_height()
            .await?
            .ok_or(format_err!("Cannot get consensus block height"))?;
        let absolute_timelock = consensus_height + OUTGOING_LN_CONTRACT_TIMELOCK;

        // Compute amount to lock in the outgoing contract
        let invoice_amount_msat = invoice
            .amount_milli_satoshis()
            .ok_or(anyhow::anyhow!("MissingInvoiceAmount"))?;

        let fees = gateway.fees;
        let base_fee = fees.base_msat as u64;
        let margin_fee: u64 = if fees.proportional_millionths > 0 {
            let fee_percent = 1000000 / fees.proportional_millionths as u64;
            invoice_amount_msat / fee_percent
        } else {
            0
        };

        let contract_amount_msat = invoice_amount_msat + base_fee + margin_fee;
        let contract_amount = Amount::from_msats(contract_amount_msat);

        let user_sk = bitcoin::KeyPair::new(&self.secp, &mut rng);

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

        Ok((
            ClientOutput {
                output: ln_output,
                state_machines: sm_gen,
            },
            contract_id,
        ))
    }

    async fn await_receive_success(
        &self,
        operation_id: OperationId,
    ) -> Result<(), LightningReceiveError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(LightningClientStateMachines::Receive(state)) => match state.state {
                    LightningReceiveStates::Funded(_) => return Ok(()),
                    LightningReceiveStates::Canceled(e) => {
                        return Err(e);
                    }
                    _ => {}
                },
                Some(_) => {}
                None => {}
            }
        }
    }

    async fn await_claim_acceptance(
        &self,
        operation_id: OperationId,
    ) -> Result<TransactionId, LightningReceiveError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(LightningClientStateMachines::Receive(state)) => match state.state {
                    LightningReceiveStates::Success(txid) => return Ok(txid),
                    LightningReceiveStates::Canceled(e) => {
                        return Err(e);
                    }
                    _ => {}
                },
                Some(_) => {}
                None => {}
            }
        }
    }

    // Wait for the Lightning invoice to be paid successfully or waiting for refund
    async fn await_payment_success(
        &self,
        operation_id: OperationId,
    ) -> Result<String, LightningPayError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(LightningClientStateMachines::Pay(state)) => match state.state {
                    LightningPayStates::Success(preimage) => {
                        return Ok(preimage);
                    }
                    LightningPayStates::Refundable(refundable) => {
                        return Err(LightningPayError::Refundable(
                            refundable.block_timelock,
                            refundable.error,
                        ));
                    }
                    _ => {}
                },
                Some(_) => {}
                None => {}
            }
        }
    }

    async fn await_refund(
        &self,
        operation_id: OperationId,
    ) -> Result<TransactionId, LightningPayError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(LightningClientStateMachines::Pay(state)) => match state.state {
                    LightningPayStates::Refunded(refund_txid) => {
                        return Ok(refund_txid);
                    }
                    LightningPayStates::Failure(reason) => {
                        return Err(LightningPayError::Failed(reason))
                    }
                    _ => {}
                },
                Some(_) => {}
                None => {}
            }
        }
    }

    pub async fn create_lightning_receive_output<'a>(
        &'a self,
        amount: Amount,
        description: String,
        mut rng: impl RngCore + CryptoRng + 'a,
        expiry_time: Option<u64>,
        gateway: LightningGateway,
        network: Network,
    ) -> anyhow::Result<(
        OperationId,
        Invoice,
        ClientOutput<LightningOutput, LightningClientStateMachines>,
    )> {
        let payment_keypair = KeyPair::new(&self.secp, &mut rng);
        let preimage: [u8; 32] = payment_keypair.x_only_public_key().0.serialize();
        let payment_hash = bitcoin::secp256k1::hashes::sha256::Hash::hash(&preimage);

        // Temporary lightning node pubkey
        let (node_secret_key, node_public_key) = self.secp.generate_keypair(&mut rng);

        // Route hint instructing payer how to route to gateway
        let route_hint_last_hop = RouteHintHop {
            src_node_id: gateway.node_pub_key,
            short_channel_id: gateway.mint_channel_id,
            fees: RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            cltv_expiry_delta: 30,
            htlc_minimum_msat: None,
            htlc_maximum_msat: None,
        };
        let route_hints = if gateway.route_hints.is_empty() {
            vec![RouteHint(vec![route_hint_last_hop])]
        } else {
            gateway
                .route_hints
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
                .collect()
        };

        let duration_since_epoch = fedimint_core::time::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let mut invoice_builder = InvoiceBuilder::new(network_to_currency(network))
            .amount_milli_satoshis(amount.msats)
            .description(description)
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret(rng.gen()))
            .duration_since_epoch(duration_since_epoch)
            .min_final_cltv_expiry(18)
            .payee_pub_key(node_public_key)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ));

        for rh in route_hints {
            invoice_builder = invoice_builder.private_route(rh);
        }

        let invoice = invoice_builder
            .build_signed(|hash| self.secp.sign_ecdsa_recoverable(hash, &node_secret_key))?;

        let operation_id = OperationId(invoice.payment_hash().into_inner());

        let sm_invoice = invoice.clone();
        let sm_gen = Arc::new(move |txid: TransactionId, _input_idx: u64| {
            vec![LightningClientStateMachines::Receive(
                LightningReceiveStateMachine {
                    operation_id,
                    state: LightningReceiveStates::SubmittedOffer(LightningReceiveSubmittedOffer {
                        offer_txid: txid,
                        invoice: sm_invoice.clone(),
                        payment_keypair,
                    }),
                },
            )]
        });

        let ln_output = LightningOutput::Offer(IncomingContractOffer {
            amount,
            hash: payment_hash,
            encrypted_preimage: EncryptedPreimage::new(
                Preimage(preimage),
                &self.cfg.threshold_pub_key,
            ),
            expiry_time,
        });

        Ok((
            operation_id,
            invoice,
            ClientOutput {
                output: ln_output,
                state_machines: sm_gen,
            },
        ))
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LightningClientStateMachines {
    Pay(LightningPayStateMachine),
    Receive(LightningReceiveStateMachine),
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
            LightningClientStateMachines::Pay(pay_state) => pay_state.operation_id(),
            LightningClientStateMachines::Receive(receive_state) => receive_state.operation_id(),
        }
    }
}

pub fn network_to_currency(network: Network) -> Currency {
    match network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Regtest => Currency::Regtest,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Signet => Currency::Signet,
    }
}
