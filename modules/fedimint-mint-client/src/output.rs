use std::collections::BTreeMap;
use std::hash;
use std::time::Duration;

use anyhow::{anyhow, bail};
use fedimint_api_client::api::{deserialize_outcome, FederationApiExt, SerdeOutputOutcome};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_client::module::ClientContext;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::{Decoder, OperationId};
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::secp256k1::{Keypair, Secp256k1, Signing};
use fedimint_core::task::sleep;
use fedimint_core::{Amount, NumPeersExt, OutPoint, PeerId, Tiered, TransactionId};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_logging::LOG_CLIENT_MODULE_MINT;
use fedimint_mint_common::endpoint_constants::AWAIT_OUTPUT_OUTCOME_ENDPOINT;
use fedimint_mint_common::{BlindNonce, MintOutputOutcome, Nonce};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator as _, ParallelIterator as _};
use serde::{Deserialize, Serialize};
use tbs::{
    aggregate_signature_shares, blind_message, unblind_signature, AggregatePublicKey,
    BlindedMessage, BlindedSignature, BlindedSignatureShare, BlindingKey, PublicKeyShare,
};
use tracing::{debug, error};

use crate::client_db::NoteKey;
use crate::event::NoteCreated;
use crate::{MintClientContext, MintClientModule, SpendableNote};

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Child ID used to derive the spend key from a note's [`DerivableSecret`]
const SPEND_KEY_CHILD_ID: ChildId = ChildId(0);

/// Child ID used to derive the blinding key from a note's [`DerivableSecret`]
const BLINDING_KEY_CHILD_ID: ChildId = ChildId(1);

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine managing the e-cash issuance process related to a mint output.
///
/// ```mermaid
/// graph LR
///     classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Created -- containing tx rejected --> Aborted
///     Created -- await output outcome --> Outcome["Outcome Received"]:::virtual
///     subgraph Await Outcome
///     Outcome -- valid blind signatures  --> Succeeded
///     Outcome -- invalid blind signatures  --> Failed
///     end
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MintOutputStates {
    /// Issuance request was created, we are waiting for blind signatures
    Created(MintOutputStatesCreated),
    /// The transaction containing the issuance was rejected, we can stop
    /// looking for decryption shares
    Aborted(MintOutputStatesAborted),
    // FIXME: handle offline federation failure mode more gracefully
    /// The transaction containing the issuance was accepted but an unexpected
    /// error occurred, this should never happen with a honest federation and
    /// bug-free code.
    Failed(MintOutputStatesFailed),
    /// The issuance was completed successfully and the e-cash notes added to
    /// our wallet
    Succeeded(MintOutputStatesSucceeded),
    /// Issuance request was created, we are waiting for blind signatures
    CreatedMulti(MintOutputStatesCreatedMulti),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputCommonV1 {
    pub(crate) operation_id: OperationId,
    pub(crate) out_point: OutPoint,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputCommon {
    pub(crate) operation_id: OperationId,
    pub(crate) txid: TransactionId,
    pub(crate) out_idxs: std::ops::RangeInclusive<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputStateMachineV1 {
    pub(crate) common: MintOutputCommonV1,
    pub(crate) state: MintOutputStates,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputStateMachine {
    pub(crate) common: MintOutputCommon,
    pub(crate) state: MintOutputStates,
}

impl State for MintOutputStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintOutputStates::Created(created) => {
                created.transitions(context, global_context, &self.common)
            }
            MintOutputStates::CreatedMulti(created) => {
                created.transitions(context, global_context, &self.common)
            }
            MintOutputStates::Aborted(_)
            | MintOutputStates::Failed(_)
            | MintOutputStates::Succeeded(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

/// See [`MintOutputStates`]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputStatesCreated {
    pub(crate) amount: Amount,
    pub(crate) issuance_request: NoteIssuanceRequest,
}

impl MintOutputStatesCreated {
    fn transitions(
        &self,
        // TODO: make cheaper to clone (Arc?)
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
        common: &MintOutputCommon,
    ) -> Vec<StateTransition<MintOutputStateMachine>> {
        let tbs_pks = context.tbs_pks.clone();
        let client_ctx = context.client_ctx.clone();

        vec![
            // Check if transaction was rejected
            StateTransition::new(
                Self::await_tx_rejected(global_context.clone(), common.clone()),
                |_dbtx, (), state| Box::pin(async move { Self::transition_tx_rejected(&state) }),
            ),
            // Check for output outcome
            StateTransition::new(
                Self::await_outcome_ready(
                    global_context.clone(),
                    common.clone(),
                    context.mint_decoder.clone(),
                    self.amount,
                    self.issuance_request.blinded_message(),
                    context.peer_tbs_pks.clone(),
                ),
                move |dbtx, blinded_signature_shares, old_state| {
                    Box::pin(Self::transition_outcome_ready(
                        client_ctx.clone(),
                        dbtx,
                        blinded_signature_shares,
                        old_state,
                        tbs_pks.clone(),
                    ))
                },
            ),
        ]
    }

    async fn await_tx_rejected(global_context: DynGlobalClientContext, common: MintOutputCommon) {
        if global_context.await_tx_accepted(common.txid).await.is_err() {
            return;
        }
        std::future::pending::<()>().await;
    }

    fn transition_tx_rejected(old_state: &MintOutputStateMachine) -> MintOutputStateMachine {
        assert!(matches!(old_state.state, MintOutputStates::Created(_)));

        MintOutputStateMachine {
            common: old_state.common.clone(),
            state: MintOutputStates::Aborted(MintOutputStatesAborted),
        }
    }

    async fn await_outcome_ready(
        global_context: DynGlobalClientContext,
        common: MintOutputCommon,
        module_decoder: Decoder,
        amount: Amount,
        message: BlindedMessage,
        peer_tbs_pks: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    ) -> BTreeMap<PeerId, BlindedSignatureShare> {
        loop {
            let decoder = module_decoder.clone();
            let pks = peer_tbs_pks.clone();

            match global_context
                .api()
                .request_with_strategy(
                    // this query collects a threshold of 2f + 1 valid blind signature shares
                    FilterMapThreshold::new(
                        move |peer, outcome| {
                            verify_blind_share(peer, &outcome, amount, message, &decoder, &pks)
                        },
                        global_context.api().all_peers().to_num_peers(),
                    ),
                    AWAIT_OUTPUT_OUTCOME_ENDPOINT.to_owned(),
                    ApiRequestErased::new(OutPoint {
                        txid: common.txid,
                        out_idx: *common.out_idxs.start(),
                    }),
                )
                .await
            {
                Ok(outcome) => return outcome,
                Err(error) => {
                    error.report_if_important();

                    sleep(RETRY_DELAY).await;
                }
            };
        }
    }

    async fn transition_outcome_ready(
        client_ctx: ClientContext<MintClientModule>,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        blinded_signature_shares: BTreeMap<PeerId, BlindedSignatureShare>,
        old_state: MintOutputStateMachine,
        tbs_pks: Tiered<AggregatePublicKey>,
    ) -> MintOutputStateMachine {
        // we combine the shares, finalize the issuance request with the blind signature
        // and store the resulting note in the database

        let MintOutputStates::Created(created) = old_state.state else {
            panic!("Unexpected prior state")
        };

        let agg_blind_signature = aggregate_signature_shares(
            &blinded_signature_shares
                .into_iter()
                .map(|(peer, share)| (peer.to_usize() as u64 + 1, share))
                .collect(),
        );

        let amount_key = tbs_pks
            .tier(&created.amount)
            .expect("We obtained this amount from tbs_pks when we created the output");

        // this implies that the mint client config's public keys are inconsistent
        if !tbs::verify_blinded_signature(
            created.issuance_request.blinded_message(),
            agg_blind_signature,
            *amount_key,
        ) {
            return MintOutputStateMachine {
                common: old_state.common,
                state: MintOutputStates::Failed(MintOutputStatesFailed {
                    error: "Invalid blind signature".to_string(),
                }),
            };
        }

        let spendable_note = created.issuance_request.finalize(agg_blind_signature);

        assert!(spendable_note.note().verify(*amount_key));

        debug!(target: LOG_CLIENT_MODULE_MINT, amount = %created.amount, note=%spendable_note, "Adding new note from transaction output");

        client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                NoteCreated {
                    nonce: spendable_note.nonce(),
                },
            )
            .await;
        if let Some(note) = dbtx
            .module_tx()
            .insert_entry(
                &NoteKey {
                    amount: created.amount,
                    nonce: spendable_note.nonce(),
                },
                &spendable_note.to_undecoded(),
            )
            .await
        {
            error!(?note, "E-cash note was replaced in DB");
        }

        MintOutputStateMachine {
            common: old_state.common,
            state: MintOutputStates::Succeeded(MintOutputStatesSucceeded {
                amount: created.amount,
            }),
        }
    }
}

/// See [`MintOutputStates`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputStatesCreatedMulti {
    pub(crate) issuance_requests: BTreeMap<u64, (Amount, NoteIssuanceRequest)>,
}

impl MintOutputStatesCreatedMulti {
    fn transitions(
        &self,
        // TODO: make cheaper to clone (Arc?)
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
        common: &MintOutputCommon,
    ) -> Vec<StateTransition<MintOutputStateMachine>> {
        let tbs_pks = context.tbs_pks.clone();
        let client_ctx = context.client_ctx.clone();

        vec![
            // Check if transaction was rejected
            StateTransition::new(
                Self::await_tx_rejected(global_context.clone(), common.clone()),
                |_dbtx, (), state| Box::pin(async move { Self::transition_tx_rejected(&state) }),
            ),
            // Check for output outcome
            StateTransition::new(
                Self::await_outcome_ready(
                    global_context.clone(),
                    common.clone(),
                    context.mint_decoder.clone(),
                    self.issuance_requests.clone(),
                    context.peer_tbs_pks.clone(),
                ),
                move |dbtx, blinded_signature_shares, old_state| {
                    Box::pin(Self::transition_outcome_ready(
                        client_ctx.clone(),
                        dbtx,
                        blinded_signature_shares,
                        old_state,
                        tbs_pks.clone(),
                    ))
                },
            ),
        ]
    }

    async fn await_tx_rejected(global_context: DynGlobalClientContext, common: MintOutputCommon) {
        if global_context.await_tx_accepted(common.txid).await.is_err() {
            return;
        }
        std::future::pending::<()>().await;
    }

    fn transition_tx_rejected(old_state: &MintOutputStateMachine) -> MintOutputStateMachine {
        assert!(matches!(old_state.state, MintOutputStates::CreatedMulti(_)));

        MintOutputStateMachine {
            common: old_state.common.clone(),
            state: MintOutputStates::Aborted(MintOutputStatesAborted),
        }
    }

    async fn await_outcome_ready(
        global_context: DynGlobalClientContext,
        common: MintOutputCommon,
        module_decoder: Decoder,
        issuance_requests: BTreeMap<u64, (Amount, NoteIssuanceRequest)>,
        peer_tbs_pks: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    ) -> Vec<(u64, BTreeMap<PeerId, BlindedSignatureShare>)> {
        let mut ret = vec![];
        // NOTE: We need a new api endpoint that can confirm multiple notes at once?
        // --dpc
        for (out_idx, (amount, issuance_request)) in issuance_requests {
            let blinded_sig_share = fedimint_core::util::retry(
                "await and fetch output sigs",
                fedimint_core::util::backoff_util::custom_backoff(RETRY_DELAY, RETRY_DELAY, None),
                || async {
                    let decoder = module_decoder.clone();
                    let pks = peer_tbs_pks.clone();

                    Ok(global_context
                        .api()
                        .request_with_strategy(
                            // this query collects a threshold of 2f + 1 valid blind signature
                            // shares
                            FilterMapThreshold::new(
                                move |peer, outcome| {
                                    verify_blind_share(
                                        peer,
                                        &outcome,
                                        amount,
                                        issuance_request.blinded_message(),
                                        &decoder,
                                        &pks,
                                    )
                                },
                                global_context.api().all_peers().to_num_peers(),
                            ),
                            AWAIT_OUTPUT_OUTCOME_ENDPOINT.to_owned(),
                            ApiRequestErased::new(OutPoint {
                                txid: common.txid,
                                out_idx,
                            }),
                        )
                        .await?)
                },
            )
            .await
            .expect("Will retry forever");

            ret.push((out_idx, blinded_sig_share));
        }

        ret
    }

    async fn transition_outcome_ready(
        client_ctx: ClientContext<MintClientModule>,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        blinded_signature_shares: Vec<(u64, BTreeMap<PeerId, BlindedSignatureShare>)>,
        old_state: MintOutputStateMachine,
        tbs_pks: Tiered<AggregatePublicKey>,
    ) -> MintOutputStateMachine {
        // we combine the shares, finalize the issuance request with the blind signature
        // and store the resulting note in the database

        let mut amount_total = Amount::ZERO;
        let MintOutputStates::CreatedMulti(created) = old_state.state else {
            panic!("Unexpected prior state")
        };

        let mut spendable_notes: Vec<(Amount, SpendableNote)> = vec![];

        // Note verification is relatively slow and CPU-bound, so parallelize them
        blinded_signature_shares
            .into_par_iter()
            .map(|(out_idx, blinded_signature_shares)| {
                let agg_blind_signature = aggregate_signature_shares(
                    &blinded_signature_shares
                        .into_iter()
                        .map(|(peer, share)| (peer.to_usize() as u64 + 1, share))
                        .collect(),
                );

                // this implies that the mint client config's public keys are inconsistent
                let (amount, issuance_request) =
                    created.issuance_requests.get(&out_idx).expect("Must have");

                let amount_key = tbs_pks.tier(amount).expect("Must have keys for any amount");

                let spendable_note = issuance_request.finalize(agg_blind_signature);

                assert!(spendable_note.note().verify(*amount_key), "We checked all signature shares in the trigger future, so the combined signature has to be valid");

                (*amount, spendable_note)
            })
            .collect_into_vec(&mut spendable_notes);

        for (amount, spendable_note) in spendable_notes {
            debug!(target: LOG_CLIENT_MODULE_MINT, amount = %amount, note=%spendable_note, "Adding new note from transaction output");

            client_ctx
                .log_event(
                    &mut dbtx.module_tx(),
                    NoteCreated {
                        nonce: spendable_note.nonce(),
                    },
                )
                .await;

            amount_total += amount;
            if let Some(note) = dbtx
                .module_tx()
                .insert_entry(
                    &NoteKey {
                        amount,
                        nonce: spendable_note.nonce(),
                    },
                    &spendable_note.to_undecoded(),
                )
                .await
            {
                error!(?note, "E-cash note was replaced in DB");
            }
        }
        MintOutputStateMachine {
            common: old_state.common,
            state: MintOutputStates::Succeeded(MintOutputStatesSucceeded {
                amount: amount_total,
            }),
        }
    }
}

/// # Panics
/// If the given `outcome` is not a [`MintOutputOutcome::V0`] outcome.
pub fn verify_blind_share(
    peer: PeerId,
    outcome: &SerdeOutputOutcome,
    amount: Amount,
    blinded_message: BlindedMessage,
    decoder: &Decoder,
    peer_tbs_pks: &BTreeMap<PeerId, Tiered<PublicKeyShare>>,
) -> anyhow::Result<BlindedSignatureShare> {
    let outcome = deserialize_outcome::<MintOutputOutcome>(outcome, decoder)?;

    let blinded_signature_share = outcome
        .ensure_v0_ref()
        .expect("We only process output outcome versions created by ourselves")
        .0;

    let amount_key = peer_tbs_pks
        .get(&peer)
        .ok_or(anyhow!("Unknown peer"))?
        .tier(&amount)
        .map_err(|_| anyhow!("Invalid Amount Tier"))?;

    if !tbs::verify_blind_share(blinded_message, blinded_signature_share, *amount_key) {
        bail!("Invalid blind signature")
    }

    Ok(blinded_signature_share)
}

/// See [`MintOutputStates`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputStatesAborted;

/// See [`MintOutputStates`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputStatesFailed {
    pub error: String,
}

/// See [`MintOutputStates`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputStatesSucceeded {
    pub amount: Amount,
}

/// Keeps the data to generate [`SpendableNote`] once the
/// mint successfully processed the transaction signing the corresponding
/// [`BlindNonce`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Encodable, Decodable)]
pub struct NoteIssuanceRequest {
    /// Spend key from which the note nonce (corresponding public key) is
    /// derived
    spend_key: Keypair,
    /// Key to unblind the blind signature supplied by the mint for this note
    blinding_key: BlindingKey,
}

impl hash::Hash for NoteIssuanceRequest {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.spend_key.hash(state);
        // ignore `blinding_key` as it doesn't impl Hash; `spend_key` has enough
        // entropy anyway
    }
}
impl NoteIssuanceRequest {
    /// Generate a request session for a single note and returns it plus the
    /// corresponding blinded message
    pub fn new<C>(ctx: &Secp256k1<C>, secret: &DerivableSecret) -> (NoteIssuanceRequest, BlindNonce)
    where
        C: Signing,
    {
        let spend_key = secret.child_key(SPEND_KEY_CHILD_ID).to_secp_key(ctx);
        let nonce = Nonce(spend_key.public_key());
        let blinding_key = BlindingKey(secret.child_key(BLINDING_KEY_CHILD_ID).to_bls12_381_key());
        let blinded_nonce = blind_message(nonce.to_message(), blinding_key);

        let cr = NoteIssuanceRequest {
            spend_key,
            blinding_key,
        };

        (cr, BlindNonce(blinded_nonce))
    }

    /// Return nonce of the e-cash note being requested
    pub fn nonce(&self) -> Nonce {
        Nonce(self.spend_key.public_key())
    }

    pub fn blinded_message(&self) -> BlindedMessage {
        blind_message(self.nonce().to_message(), self.blinding_key)
    }

    /// Use the blind signature to create spendable e-cash notes
    pub fn finalize(&self, blinded_signature: BlindedSignature) -> SpendableNote {
        SpendableNote {
            signature: unblind_signature(self.blinding_key, blinded_signature),
            spend_key: self.spend_key,
        }
    }
}
