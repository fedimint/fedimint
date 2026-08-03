use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::{Amount, OutPoint, OutPointRange, TransactionId};
use fedimint_lnv2_common::contracts::{IncomingContract, fee_from_expiration};
use fedimint_lnv2_common::{LightningInput, LightningInputV0};
use fedimint_logging::LOG_CLIENT_MODULE_LNV2;
use tpe::AggregateDecryptionKey;
use tracing::{instrument, warn};

use crate::api::LightningFederationApi;
use crate::events::ReceivePaymentEvent;
use crate::{LightningClientContext, LightningOperationMeta};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ReceiveStateMachine {
    pub common: ReceiveSMCommon,
    pub state: ReceiveSMState,
}

impl ReceiveStateMachine {
    #[must_use]
    pub fn update(&self, state: ReceiveSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ReceiveSMCommon {
    pub operation_id: OperationId,
    pub contract: IncomingContract,
    pub claim_keypair: Keypair,
    pub agg_decryption_key: AggregateDecryptionKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum ReceiveSMState {
    Pending,
    /// Terminal claiming state written by clients from before the claim
    /// transaction was watched for rejection. Only kept such that databases
    /// written by those clients still decode; new operations use
    /// [`ReceiveSMState::Claiming`]. Operations parked here whose claim was
    /// rejected can be re-driven with
    /// [`crate::LightningClientModule::reclaim_receive`].
    ClaimingLegacy(Vec<OutPoint>),
    Expired,
    Claiming {
        change: OutPointRange,
    },
    Claimed {
        change: OutPointRange,
    },
    Failed,
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that waits on the receipt of a Lightning payment.
///
/// A rejected claim transaction fails the operation instead of being retried:
/// the incoming contract stays funded and claimable on the federation, so the
/// operation can be re-driven with
/// [`crate::LightningClientModule::reclaim_receive`].
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Pending -- incoming contract is confirmed --> Claiming
///     Pending -- decryption contract expires --> Expired
///     Claiming -- claim transaction is accepted --> Claimed
///     Claiming -- claim transaction is rejected --> Failed
/// ```
impl State for ReceiveStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();
        let ctx = context.clone();

        match &self.state {
            ReceiveSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_incoming_contract(self.common.contract.clone(), gc.clone()),
                    move |dbtx, contract_confirmed, old_state| {
                        Box::pin(Self::transition_incoming_contract(
                            dbtx,
                            old_state,
                            gc.clone(),
                            contract_confirmed,
                        ))
                    },
                )]
            }
            ReceiveSMState::Claiming { change } => {
                let change = *change;

                vec![StateTransition::new(
                    Self::await_claim_decision(gc.clone(), change.txid()),
                    move |dbtx, decision, old_state| {
                        Box::pin(Self::transition_claim_decision(
                            dbtx,
                            old_state,
                            ctx.clone(),
                            decision,
                            change,
                        ))
                    },
                )]
            }
            ReceiveSMState::ClaimingLegacy(..)
            | ReceiveSMState::Expired
            | ReceiveSMState::Claimed { .. }
            | ReceiveSMState::Failed => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl ReceiveStateMachine {
    #[instrument(target = LOG_CLIENT_MODULE_LNV2, skip(global_context))]
    async fn await_incoming_contract(
        contract: IncomingContract,
        global_context: DynGlobalClientContext,
    ) -> Option<OutPoint> {
        global_context
            .module_api()
            .await_incoming_contract(
                &contract.contract_id(),
                contract.commitment.expiration_or_fee,
            )
            .await
    }

    async fn transition_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: ReceiveStateMachine,
        global_context: DynGlobalClientContext,
        outpoint: Option<OutPoint>,
    ) -> ReceiveStateMachine {
        let Some(funding_outpoint) = outpoint else {
            return old_state.update(ReceiveSMState::Expired);
        };

        let client_input = ClientInput::<LightningInput> {
            input: LightningInput::V0(LightningInputV0::Incoming(
                funding_outpoint,
                old_state.common.agg_decryption_key,
            )),
            amounts: Amounts::new_bitcoin(old_state.common.contract.commitment.amount),
            keys: vec![old_state.common.claim_keypair],
        };

        let change = global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
            .expect("Cannot claim input, additional funding needed");

        old_state.update(ReceiveSMState::Claiming { change })
    }

    #[instrument(target = LOG_CLIENT_MODULE_LNV2, skip(global_context))]
    async fn await_claim_decision(
        global_context: DynGlobalClientContext,
        claim_txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(claim_txid).await
    }

    async fn transition_claim_decision(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: ReceiveStateMachine,
        context: LightningClientContext,
        decision: Result<(), String>,
        change: OutPointRange,
    ) -> ReceiveStateMachine {
        match decision {
            Ok(()) => {
                Self::log_receive_event(&context, dbtx, &old_state).await;

                old_state.update(ReceiveSMState::Claimed { change })
            }
            Err(error) => {
                warn!(
                    target: LOG_CLIENT_MODULE_LNV2,
                    error = %error.as_str(),
                    contract_id = ?old_state.common.contract.contract_id(),
                    "The claim transaction was rejected; the incoming contract remains funded and claimable"
                );

                old_state.update(ReceiveSMState::Failed)
            }
        }
    }

    async fn log_receive_event(
        context: &LightningClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: &ReceiveStateMachine,
    ) {
        // The event reports the invoice amount and the gateway fee separately.
        // Manual receives carry the invoice in their operation meta, so the fee
        // is the difference between invoice and contract amount. Lnurl receives
        // do not have an invoice on the client, so the fee is recovered from the
        // fee-encoded contract expiration set by the recurring daemon instead.
        let fee = match context
            .client_ctx
            .get_operation(old_state.common.operation_id)
            .await
            .map(|operation| operation.meta::<LightningOperationMeta>())
        {
            // A receive operation meta with an invoice is only recorded for
            // manually created invoices; lnurl receives have no invoice on the
            // client, so the fee is recovered from the fee-encoded expiration.
            Ok(LightningOperationMeta::Receive(meta)) => meta.gateway_fee(),
            // A recovered receive lost its invoice with the original database
            // and its expiration is a real timestamp rather than a fee
            // encoding, so the gateway fee is unknown and reported as zero.
            Ok(LightningOperationMeta::RecoveredReceive(..)) => Amount::ZERO,
            _ => Amount::from_msats(fee_from_expiration(
                old_state.common.contract.commitment.expiration_or_fee,
            )),
        };

        context
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                ReceivePaymentEvent {
                    operation_id: old_state.common.operation_id,
                    amount: old_state.common.contract.commitment.amount + fee,
                    fee,
                },
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::{BitcoinHash, OutPoint, OutPointRange, TransactionId};

    use super::ReceiveSMState;

    /// A structural mirror of [`ReceiveSMState`], pinning the persisted
    /// variant order: the first three variants are the enum as encoded by
    /// clients from before the claim transaction was watched for rejection
    /// (with `ClaimingLegacy` under its original name), and the appended
    /// variants are what current clients persist. The derive assigns variant
    /// indices in declaration order, so any reorder or insertion in
    /// [`ReceiveSMState`] breaks this test instead of corrupting the decoding
    /// of existing databases.
    #[derive(Encodable)]
    enum MirrorReceiveSMState {
        Pending,
        Claiming(Vec<OutPoint>),
        Expired,
        ClaimingCurrent { change: OutPointRange },
        Claimed { change: OutPointRange },
        Failed,
    }

    #[test]
    fn pins_receive_state_variant_encoding() {
        let txid = TransactionId::from_byte_array([42; 32]);

        let out_points = vec![OutPoint { txid, out_idx: 7 }];

        let change = OutPointRange::new_single(txid, 3).expect("Valid index");

        let cases = [
            (MirrorReceiveSMState::Pending, ReceiveSMState::Pending),
            (
                MirrorReceiveSMState::Claiming(out_points.clone()),
                ReceiveSMState::ClaimingLegacy(out_points),
            ),
            (MirrorReceiveSMState::Expired, ReceiveSMState::Expired),
            (
                MirrorReceiveSMState::ClaimingCurrent { change },
                ReceiveSMState::Claiming { change },
            ),
            (
                MirrorReceiveSMState::Claimed { change },
                ReceiveSMState::Claimed { change },
            ),
            (MirrorReceiveSMState::Failed, ReceiveSMState::Failed),
        ];

        for (mirror, expected) in cases {
            let decoded = ReceiveSMState::consensus_decode_whole(
                &mirror.consensus_encode_to_vec(),
                &ModuleDecoderRegistry::default(),
            )
            .expect("Pinned state should decode");

            assert_eq!(decoded, expected);
        }
    }
}
