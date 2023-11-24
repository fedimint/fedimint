mod db;
pub mod incoming;
pub mod pay;
pub mod receive;

use std::collections::BTreeMap;
use std::iter::once;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, ensure, format_err, Context};
use async_stream::stream;
use bitcoin::{KeyPair, Network};
use bitcoin_hashes::{sha256, Hash};
use db::{DbKeyPrefix, LightningGatewayKey, PaymentResult, PaymentResultKey};
use fedimint_client::derivable_secret::ChildId;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext, FederationInfo};
use fedimint_core::api::DynModuleApi;
use fedimint_core::config::{
    ClientConfig, FederationId, META_OVERRIDE_URL_KEY, META_VETTED_GATEWAYS_KEY,
};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::task::{timeout, MaybeSend, MaybeSync};
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_pair_items, Amount, OutPoint, TransactionId,
};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::incoming::{IncomingContract, IncomingContractOffer};
use fedimint_ln_common::contracts::outgoing::{
    OutgoingContract, OutgoingContractAccount, OutgoingContractData,
};
use fedimint_ln_common::contracts::{
    Contract, ContractId, DecryptedPreimage, EncryptedPreimage, IdentifiableContract, Preimage,
    PreimageKey,
};
use fedimint_ln_common::{
    ContractOutput, LightningClientContext, LightningCommonInit, LightningGateway,
    LightningGatewayAnnouncement, LightningGatewayRegistration, LightningModuleTypes,
    LightningOutput, LightningOutputV0,
};
use futures::StreamExt;
use incoming::IncomingSmError;
use lightning_invoice::{
    Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret, RouteHint, RouteHintHop, RoutingFees,
    DEFAULT_EXPIRY_TIME,
};
use rand::seq::IteratorRandom;
use rand::{CryptoRng, Rng, RngCore};
use secp256k1::PublicKey;
use secp256k1_zkp::{All, Secp256k1};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use thiserror::Error;
use tracing::{debug, error};

use crate::db::{
    LightningGatewayKeyPrefix, MetaOverrides, MetaOverridesKey, MetaOverridesPrefix,
    PaymentResultPrefix,
};
use crate::incoming::{
    FundingOfferState, IncomingSmCommon, IncomingSmStates, IncomingStateMachine,
};
use crate::pay::{
    GatewayPayError, LightningPayCommon, LightningPayCreatedOutgoingLnContract,
    LightningPayStateMachine, LightningPayStates,
};
use crate::receive::{
    LightningReceiveError, LightningReceiveStateMachine, LightningReceiveStates,
    LightningReceiveSubmittedOffer,
};

/// Number of blocks until outgoing lightning contracts times out and user
/// client can get refund
const OUTGOING_LN_CONTRACT_TIMELOCK: u64 = 500;

const META_OVERRIDE_CACHE_DURATION: Duration = Duration::from_secs(10 * 60);

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
    UnexpectedError {
        error_message: String,
    },
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

async fn invoice_has_internal_payment_markers(
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

async fn invoice_routes_back_to_federation(
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
    },
}

#[derive(Debug, Clone)]
pub struct LightningClientInit;

#[apply(async_trait_maybe_send!)]
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
            match table {
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
                DbKeyPrefix::MetaOverrides => {
                    push_db_pair_items!(
                        dbtx,
                        MetaOverridesPrefix,
                        MetaOverridesKey,
                        MetaOverrides,
                        ln_client_items,
                        "Meta Overrides"
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
        let secp = Secp256k1::new();
        Ok(LightningClientModule {
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
        })
    }
}

/// Client side lightning module
///
/// Note that lightning gateways use a different version
/// of client side module.
#[derive(Debug)]
pub struct LightningClientModule {
    pub cfg: LightningClientConfig,
    notifier: ModuleNotifier<DynGlobalClientContext, LightningClientStateMachines>,
    redeem_key: KeyPair,
    secp: Secp256k1<All>,
    module_api: DynModuleApi,
    preimage_auth: KeyPair,
    client_ctx: ClientContext<Self>,
}

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
        }
    }

    fn input_amount(
        &self,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        let input = input.maybe_v0_ref()?;

        Some(TransactionItemAmount {
            amount: input.amount,
            fee: self.cfg.fee_consensus.contract_input,
        })
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        let output = output.maybe_v0_ref()?;

        let amt = match output {
            LightningOutputV0::Contract(account_output) => TransactionItemAmount {
                amount: account_output.amount,
                fee: self.cfg.fee_consensus.contract_output,
            },
            LightningOutputV0::Offer(_) | LightningOutputV0::CancelOutgoing { .. } => {
                TransactionItemAmount {
                    amount: Amount::ZERO,
                    fee: Amount::ZERO,
                }
            }
        };
        Some(amt)
    }
}

#[derive(Error, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PayError {
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

    fn get_payment_operation_id(&self, payment_hash: &sha256::Hash, index: u16) -> OperationId {
        // Copy the 32 byte payment hash and a 2 byte index to make every payment
        // attempt have a unique `OperationId`
        let mut bytes = [0; 34];
        bytes[0..32].copy_from_slice(&payment_hash.into_inner());
        bytes[32..34].copy_from_slice(&index.to_le_bytes());
        let hash: sha256::Hash = Hash::hash(&bytes);
        OperationId(hash.into_inner())
    }

    // Ping gateway endpoint to verify that it is available before locking funds in
    // OutgoingContract
    async fn verify_gateway_availability(&self, gateway: &LightningGateway) -> anyhow::Result<()> {
        let response = reqwest::Client::new()
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
            return Err(anyhow::anyhow!(
                "Gateway is not available. Returned error code: {}",
                response.status()
            ));
        }

        let text_gateway_id = response.text().await?;
        let gateway_id = PublicKey::from_str(&text_gateway_id[1..text_gateway_id.len() - 1])?;
        if gateway_id != gateway.gateway_id {
            return Err(anyhow::anyhow!(
                "Unexpected gateway id returned: {gateway_id}"
            ));
        }

        Ok(())
    }

    /// Hashes the client's preimage authentication secret with the provided
    /// `payment_hash`. The resulting hash is used when contacting the
    /// gateway to determine if this client is allowed to be shown the
    /// preimage.
    fn get_preimage_authentication(&self, payment_hash: &sha256::Hash) -> sha256::Hash {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&payment_hash.into_inner());
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
        let federation_currency = network_to_currency(self.cfg.network);
        let invoice_currency = invoice.currency();
        ensure!(
            federation_currency == invoice_currency,
            "Invalid invoice currency: expected={:?}, got={:?}",
            federation_currency,
            invoice_currency
        );

        // Do not create the funding transaction if the gateway is not currently
        // available
        self.verify_gateway_availability(&gateway).await?;

        let consensus_count = self
            .module_api
            .fetch_consensus_block_count()
            .await?
            .ok_or(format_err!("Cannot get consensus block count"))?;
        let absolute_timelock = consensus_count + OUTGOING_LN_CONTRACT_TIMELOCK - 1;

        // Compute amount to lock in the outgoing contract
        let invoice_amount_msat = invoice
            .amount_milli_satoshis()
            .context("MissingInvoiceAmount")?;

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

        let preimage_auth = self.get_preimage_authentication(invoice.payment_hash());
        let payment_hash = *invoice.payment_hash();
        let contract = OutgoingContract {
            hash: payment_hash,
            gateway_key: gateway.gateway_redeem_key,
            timelock: absolute_timelock as u32,
            user_key: user_sk.public_key(),
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
            vec![LightningClientStateMachines::LightningPay(
                LightningPayStateMachine {
                    common: LightningPayCommon {
                        operation_id,
                        federation_id: fed_id,
                        contract: outgoing_payment.clone(),
                        gateway_fee: Amount::from_msats(base_fee + margin_fee),
                        preimage_auth,
                        payment_hash,
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

        let (incoming_output, contract_id) = create_incoming_contract_output(
            &self.module_api,
            *payment_hash,
            invoice_amount,
            self.redeem_key,
        )
        .await?;

        let client_output = ClientOutput::<LightningOutputV0, LightningClientStateMachines> {
            output: incoming_output,
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
                Some(_) => {}
                None => {}
            }
        }
    }

    // Wait for the Lightning invoice to be paid successfully or waiting for refund
    async fn await_lightning_payment_success(
        &self,
        operation_id: OperationId,
    ) -> Result<String, PayError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(LightningClientStateMachines::LightningPay(state)) => match state.state {
                    LightningPayStates::Success(preimage) => {
                        return Ok(preimage);
                    }
                    LightningPayStates::Refundable(refundable) => {
                        return Err(PayError::Refundable(
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

    async fn await_refund(&self, operation_id: OperationId) -> Result<Vec<OutPoint>, PayError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(LightningClientStateMachines::LightningPay(state)) => match state.state {
                    LightningPayStates::Refunded(out_points) => {
                        return Ok(out_points);
                    }
                    LightningPayStates::Failure(reason) => return Err(PayError::Failed(reason)),
                    _ => {}
                },
                Some(_) => {}
                None => {}
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_lightning_receive_output<'a>(
        &'a self,
        amount: Amount,
        description: String,
        mut rng: impl RngCore + CryptoRng + 'a,
        expiry_time: Option<u64>,
        src_node_id: secp256k1::PublicKey,
        short_channel_id: u64,
        route_hints: Vec<fedimint_ln_common::route_hints::RouteHint>,
        network: Network,
    ) -> anyhow::Result<(
        OperationId,
        Bolt11Invoice,
        ClientOutput<LightningOutput, LightningClientStateMachines>,
    )> {
        let payment_keypair = KeyPair::new(&self.secp, &mut rng);
        let preimage_key: [u8; 33] = payment_keypair.public_key().serialize();
        let payment_hash = sha256::Hash::hash(&sha256::Hash::hash(&preimage_key));

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

        let duration_since_epoch = fedimint_core::time::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let mut invoice_builder = InvoiceBuilder::new(network_to_currency(network))
            .amount_milli_satoshis(amount.msats)
            .description(description)
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret(rng.gen()))
            .duration_since_epoch(duration_since_epoch)
            .min_final_cltv_expiry_delta(18)
            .payee_pub_key(node_public_key)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ));

        for rh in final_route_hints {
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

        let ln_output = LightningOutput::new_v0_offer(IncomingContractOffer {
            amount,
            hash: payment_hash,
            encrypted_preimage: EncryptedPreimage::new(
                PreimageKey(preimage_key),
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

    /// The set active gateway, or a random one if none has been set
    pub async fn select_active_gateway(&self) -> anyhow::Result<LightningGateway> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        match dbtx.get_value(&LightningGatewayKey).await {
            Some(active_gateway) => Ok(active_gateway.info),
            None => {
                let gateways = self.fetch_registered_gateways().await?;

                let vetted = gateways
                    .clone()
                    .into_iter()
                    .filter(|g| g.vetted)
                    .collect::<Vec<_>>();
                if !vetted.is_empty() {
                    debug!("Choosing a vetted gateway");
                    vetted
                        .into_iter()
                        .map(|gw| gw.info)
                        .choose(&mut rand::thread_rng())
                        .ok_or(anyhow::anyhow!("Could not choose a vetted gateway"))
                } else {
                    debug!("Choosing a random gateway");
                    gateways
                        .into_iter()
                        .map(|gw| gw.info)
                        .choose(&mut rand::thread_rng())
                        .ok_or(anyhow::anyhow!("Could not choose a gateway"))
                }
            }
        }
    }

    /// Sets the gateway to be used by all other operations
    pub async fn set_active_gateway(
        &self,
        gateway_id: &secp256k1::PublicKey,
    ) -> anyhow::Result<()> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let gateways = self.fetch_registered_gateways().await?;
        if gateways.is_empty() {
            debug!("Could not find any gateways");
            return Err(anyhow::anyhow!("Could not find any gateways"));
        };
        let gateway = gateways
            .into_iter()
            .find(|g| &g.info.gateway_id == gateway_id)
            .ok_or_else(|| {
                anyhow::anyhow!("Could not find gateway with gateway id {:?}", gateway_id)
            })?;

        dbtx.insert_entry(&LightningGatewayKey, &gateway.anchor())
            .await;
        dbtx.commit_tx().await;
        Ok(())
    }

    async fn fetch_meta_overrides(&self, config: ClientConfig) -> anyhow::Result<String> {
        let federation_id = config.global.federation_id();
        let override_src = match FederationInfo::from_config(config)
            .await?
            .meta::<String>(META_OVERRIDE_URL_KEY)?
        {
            Some(override_src) => override_src,
            None => {
                debug!("No meta override source configured");
                return Ok("".into());
            }
        };
        debug!("Fetching meta overrides from {override_src}");

        if let Some(meta) = self
            .client_ctx
            .module_db()
            .begin_transaction()
            .await
            .get_value(&MetaOverridesKey {})
            .await
        {
            if meta.fetched_at.elapsed().unwrap() < META_OVERRIDE_CACHE_DURATION {
                debug!("Using cached meta overrides");
                return Ok(meta.value);
            }
            debug!("Cached meta overrides are stale");
        };

        let response = reqwest::Client::new()
            .get(override_src.as_str())
            .send()
            .await
            .context("Meta override request failed")?;
        debug!("Meta override source returned status: {response:?}");

        let federation_meta = match response.status() {
            reqwest::StatusCode::OK => {
                let txt = response.text().await.context(format!(
                    "Meta override source returned invalid body: {override_src}"
                ))?;
                let m: serde_json::Value = serde_json::from_str(&txt).map_err(|_| {
                    anyhow::anyhow!("Meta override source returned invalid json: {txt}")
                })?;
                if !m.is_object() {
                    return Err(anyhow::anyhow!("Meta override is not valid"));
                }

                match m.get(&federation_id.to_string()) {
                    Some(meta) => {
                        debug!("Found meta overrides for federation: {federation_id}");
                        meta.to_string()
                    }
                    None => {
                        debug!("No meta overrides found for federation: {federation_id}");
                        return Ok("".into());
                    }
                }
            }
            _ => Err(anyhow::anyhow!(
                "Meta override source returned error code: {}",
                response.status()
            ))?,
        };

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        dbtx.insert_entry(
            &MetaOverridesKey {},
            &MetaOverrides {
                value: federation_meta.clone(),
                fetched_at: fedimint_core::time::now(),
            },
        )
        .await;
        dbtx.commit_tx().await;

        Ok(federation_meta)
    }

    /// Gateways actively registered with the fed
    pub async fn fetch_registered_gateways(
        &self,
    ) -> anyhow::Result<Vec<LightningGatewayAnnouncement>> {
        let mut gateways = self.module_api.fetch_gateways().await?;

        if !gateways.is_empty() {
            debug!("Fetching meta overrides from remote source/cache");
            let config = self.client_ctx.get_config().clone();
            let federation_meta = match self.fetch_meta_overrides(config).await {
                Ok(meta) => {
                    if meta.is_empty() {
                        debug!("No meta overrides found");
                        return Ok(gateways);
                    }
                    meta
                }
                Err(e) => {
                    error!("Error fetching meta overrides: {}", e);
                    return Ok(gateways);
                }
            };

            debug!("Applying vetted meta field to registered gateways");
            let meta: BTreeMap<String, serde_json::Value> = serde_json::from_str(&federation_meta)
                .context(format!(
                    "Meta override source returned invalid json: {}",
                    federation_meta
                ))?;
            let vetted_gids = match meta
                .get(META_VETTED_GATEWAYS_KEY)
                .and_then(|vetted| serde_json::from_value::<Vec<String>>(vetted.clone()).ok())
            {
                Some(vetted) => {
                    debug!("Found the following vetted gateways: {:?}", vetted);
                    vetted
                        .into_iter()
                        .map(|pk| PublicKey::from_str(&pk).map_err(anyhow::Error::from))
                        .collect::<Result<Vec<_>, _>>()?
                }
                None => Vec::new(),
            };
            debug!("Vetted gateways: {:?}", vetted_gids);

            for gateway in gateways.iter_mut() {
                gateway.vetted = vetted_gids.contains(&gateway.info.gateway_id);
            }
        }

        Ok(gateways)
    }

    /// Pays a LN invoice with our available funds
    pub async fn pay_bolt11_invoice<M: Serialize + MaybeSend + MaybeSync>(
        &self,
        invoice: Bolt11Invoice,
        extra_meta: M,
    ) -> anyhow::Result<OutgoingLightningPayment> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        let prev_payment_result = self
            .get_prev_payment_result(invoice.payment_hash(), &mut dbtx.to_ref_nc())
            .await;

        if let Some(completed_payment) = prev_payment_result.completed_payment {
            return Ok(completed_payment);
        }

        // Verify that no previous payment attempt is still running
        let prev_operation_id =
            self.get_payment_operation_id(invoice.payment_hash(), prev_payment_result.index);
        if self.client_ctx.has_active_states(prev_operation_id).await {
            return Err(anyhow::anyhow!("Previous payment attempt still in progress. Previous Operation Id: {prev_operation_id}"));
        }

        let next_index = prev_payment_result.index + 1;
        let operation_id = self.get_payment_operation_id(invoice.payment_hash(), next_index);

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

        let is_internal_payment = invoice_has_internal_payment_markers(
            &invoice,
            self.client_ctx.get_internal_payment_markers()?,
        )
        .await
            || invoice_routes_back_to_federation(
                &invoice,
                self.fetch_registered_gateways()
                    .await?
                    .into_iter()
                    .map(|gw| gw.info)
                    .collect(),
            )
            .await;

        let (pay_type, client_output, contract_id) = if is_internal_payment {
            let (output, contract_id) = self
                .create_incoming_output(operation_id, invoice.clone())
                .await?;
            (PayType::Internal(operation_id), output, contract_id)
        } else {
            let active_gateway = self.select_active_gateway().await?;
            let (output, contract_id) = self
                .create_outgoing_output(
                    operation_id,
                    invoice.clone(),
                    active_gateway,
                    self.client_ctx.get_config().global.federation_id(),
                    rand::rngs::OsRng,
                )
                .await?;
            (PayType::Lightning(operation_id), output, contract_id)
        };

        // Verify that no other outgoing contract exists or the value is empty
        if let Ok(contract) = self.module_api.fetch_contract(contract_id).await {
            if contract.amount.msats != 0 {
                return Err(anyhow::anyhow!(
                    "Funded contract already exists. ContractId: {contract_id}"
                ));
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
                            .ok_or(anyhow::anyhow!("MissingInvoiceAmount"))?,
                    )
                    .expect("Contract amount should be greater or equal than invoice amount");
                Amount::from_msats(fee_msat)
            }
            _ => unreachable!("User client will only create contract outputs on spend"),
        };

        let output = self.client_ctx.make_client_output(ClientOutput {
            output: LightningOutput::V0(client_output.output),
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

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, move || {
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

    pub async fn subscribe_ln_pay(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<LnPayState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let (out_point, _, change) = match operation.meta::<LightningOperationMeta>().variant {
            LightningOperationMetaVariant::Pay(LightningOperationMetaPay {
                out_point,
                invoice,
                change,
                ..
            }) => (out_point, invoice, change),
            _ => bail!("Operation is not a lightning payment"),
        };

        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, move || {
            stream! {
                let self_ref = client_ctx.self_ref();

                yield LnPayState::Created;

                if client_ctx
                    .transaction_updates(operation_id)
                    .await
                    .await_tx_accepted(out_point.txid)
                    .await
                    .is_err()
                {
                    yield LnPayState::Canceled;
                    return;
                }
                yield LnPayState::Funded;

                match self_ref.await_lightning_payment_success(operation_id).await {
                    Ok(preimage) => {
                        if !change.is_empty() {
                            yield LnPayState::AwaitingChange;
                            match client_ctx.await_primary_module_outputs(operation_id, change).await {
                                Ok(_) => {}
                                Err(_) => {
                                    yield LnPayState::UnexpectedError { error_message: "Error occurred while waiting for the primary module's output".to_string() };
                                    return;
                                }
                            }
                        }

                        yield LnPayState::Success {preimage};
                        return;
                    }
                    Err(PayError::Refundable(block_height, error)) => {
                        yield LnPayState::WaitingForRefund{ block_height, gateway_error: error.clone() };

                        if let Ok(out_points) = self_ref.await_refund(operation_id).await {
                            // need to await primary module to get refund
                            if client_ctx.await_primary_module_outputs(operation_id, out_points).await.is_ok() {
                                yield LnPayState::Refunded { gateway_error: error };
                                return;
                            }
                        }
                    }
                    _ => {}
                }

                yield LnPayState::UnexpectedError { error_message: "Error occurred trying to get refund. Refund was not successful".to_string() };
            }
        }))
    }

    /// Receive over LN with a new invoice
    pub async fn create_bolt11_invoice<M: Serialize + Send + Sync>(
        &self,
        amount: Amount,
        description: String,
        expiry_time: Option<u64>,
        extra_meta: M,
    ) -> anyhow::Result<(OperationId, Bolt11Invoice)> {
        let (src_node_id, short_channel_id, route_hints) = match self.select_active_gateway().await
        {
            Ok(active_gateway) => (
                active_gateway.node_pub_key,
                active_gateway.mint_channel_id,
                active_gateway.route_hints,
            ),
            Err(_) => {
                let markers = self.client_ctx.get_internal_payment_markers()?;
                (markers.0, markers.1, vec![])
            }
        };

        let (operation_id, invoice, output) = self
            .create_lightning_receive_output(
                amount,
                description,
                rand::rngs::OsRng,
                expiry_time,
                src_node_id,
                short_channel_id,
                route_hints,
                self.cfg.network,
            )
            .await?;
        let tx = TransactionBuilder::new().with_output(self.client_ctx.make_client_output(output));
        let extra_meta = serde_json::to_value(extra_meta).expect("extra_meta is serializable");
        let operation_meta_gen = |txid, _| LightningOperationMeta {
            variant: LightningOperationMetaVariant::Receive {
                out_point: OutPoint { txid, out_idx: 0 },
                invoice: invoice.clone(),
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

        // Wait for the transaction to be accepted by the federation, otherwise the
        // invoice will not be able to be paid
        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(txid)
            .await
            .map_err(|e| anyhow::anyhow!("Offer transaction was not accepted: {e:?}"))?;

        Ok((operation_id, invoice))
    }

    pub async fn subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<LnReceiveState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let (out_point, invoice) = match operation.meta::<LightningOperationMeta>().variant {
            LightningOperationMetaVariant::Receive { out_point, invoice } => (out_point, invoice),
            _ => bail!("Operation is not a lightning payment"),
        };

        let tx_accepted_future = self
            .client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(out_point.txid);

        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, move || {
            stream! {

                let self_ref = client_ctx.self_ref();

                yield LnReceiveState::Created;

                if tx_accepted_future.await.is_err() {
                    yield LnReceiveState::Canceled { reason: LightningReceiveError::Rejected };
                    return;
                }
                yield LnReceiveState::WaitingForPayment { invoice: invoice.to_string(), timeout: invoice.expiry_time() };

                match self_ref.await_receive_success(operation_id).await {
                    Ok(()) => {
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
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LightningClientStateMachines {
    InternalPay(IncomingStateMachine),
    LightningPay(LightningPayStateMachine),
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

fn network_to_currency(network: Network) -> Currency {
    match network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Regtest => Currency::Regtest,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Signet => Currency::Signet,
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
    redeem_key: secp256k1::KeyPair,
) -> Result<(LightningOutputV0, ContractId), IncomingSmError> {
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

    Ok((incoming_output, contract_id))
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
