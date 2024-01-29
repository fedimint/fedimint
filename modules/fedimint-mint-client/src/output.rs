use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, bail};
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::{deserialize_outcome, FederationApiExt, SerdeOutputOutcome};
use fedimint_core::core::{Decoder, OperationId};
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::endpoint_constants::AWAIT_OUTPUT_OUTCOME_ENDPOINT;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::FilterMapThreshold;
use fedimint_core::task::sleep;
use fedimint_core::{Amount, NumPeers, OutPoint, PeerId, Tiered, TransactionId};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_mint_common::{
    BlindNonce, MintOutputOutcome, Nonce, Note, UnknownMintOutputOutcomeVariantError,
};
use secp256k1::{KeyPair, Secp256k1, Signing};
use serde::{Deserialize, Serialize};
use tbs::{
    aggregate_signature_shares, blind_message, unblind_signature, AggregatePublicKey,
    BlindedSignature, BlindingKey, PublicKeyShare,
};
use thiserror::Error;
use tracing::{error, trace};

use crate::client_db::NoteKey;
use crate::{MintClientContext, SpendableNote};

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Child ID used to derive the spend key from a note's [`DerivableSecret`]
const SPEND_KEY_CHILD_ID: ChildId = ChildId(0);

/// Child ID used to derive the blinding key from a note's [`DerivableSecret`]
const BLINDING_KEY_CHILD_ID: ChildId = ChildId(1);

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
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
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
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOutputCommon {
    pub(crate) operation_id: OperationId,
    pub(crate) out_point: OutPoint,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOutputStateMachine {
    pub(crate) common: MintOutputCommon,
    pub(crate) state: MintOutputStates,
}

impl State for MintOutputStateMachine {
    type ModuleContext = MintClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MintOutputStates::Created(created) => {
                created.transitions(context, global_context, self.common)
            }
            MintOutputStates::Aborted(_) => {
                vec![]
            }
            MintOutputStates::Failed(_) => {
                vec![]
            }
            MintOutputStates::Succeeded(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

/// See [`MintOutputStates`]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
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
        common: MintOutputCommon,
    ) -> Vec<StateTransition<MintOutputStateMachine>> {
        let tbs_pks = context.tbs_pks.clone();
        vec![
            // Check if transaction was rejected
            StateTransition::new(
                Self::await_tx_rejected(global_context.clone(), common),
                |_dbtx, (), state| Box::pin(Self::transition_tx_rejected(state)),
            ),
            // Check for output outcome
            StateTransition::new(
                Self::await_outcome_ready(
                    global_context.clone(),
                    common,
                    context.mint_decoder.clone(),
                    self.amount,
                    self.issuance_request,
                    context.peer_tbs_pks.clone(),
                ),
                move |dbtx, output_outcomes, old_state| {
                    Box::pin(Self::transition_outcome_ready(
                        dbtx,
                        output_outcomes,
                        old_state,
                        // TODO: avoid clone of whole object
                        tbs_pks.clone(),
                    ))
                },
            ),
        ]
    }

    async fn await_tx_rejected(global_context: DynGlobalClientContext, common: MintOutputCommon) {
        if global_context
            .await_tx_accepted(common.operation_id, common.out_point.txid)
            .await
            .is_err()
        {
            return;
        }
        std::future::pending().await
    }

    async fn transition_tx_rejected<'a>(
        old_state: MintOutputStateMachine,
    ) -> MintOutputStateMachine {
        assert!(matches!(old_state.state, MintOutputStates::Created(_)));

        MintOutputStateMachine {
            common: old_state.common,
            state: MintOutputStates::Aborted(MintOutputStatesAborted),
        }
    }

    async fn await_outcome_ready(
        global_context: DynGlobalClientContext,
        common: MintOutputCommon,
        module_decoder: Decoder,
        amount: Amount,
        request: NoteIssuanceRequest,
        peer_tbs_pks: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    ) -> Result<BTreeMap<PeerId, MintOutputOutcome>, String> {
        loop {
            let decoder = module_decoder.clone();
            let pks = peer_tbs_pks.clone();

            match global_context
                .api()
                .request_with_strategy(
                    // this query collects a threshold of 2f + 1 valid blind signature shares
                    FilterMapThreshold::new(
                        move |peer, outcome| {
                            verify_blind_share(peer, outcome, amount, &request, &decoder, &pks)
                        },
                        global_context.api().all_peers().total(),
                    ),
                    AWAIT_OUTPUT_OUTCOME_ENDPOINT.to_owned(),
                    ApiRequestErased::new(common.out_point),
                )
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(error) => {
                    error.report_if_important();

                    trace!(
                        "Awaiting outcome to become ready failed, retrying in {}s: {error}",
                        RETRY_DELAY.as_secs()
                    );

                    sleep(RETRY_DELAY).await;
                }
            };
        }
    }

    async fn transition_outcome_ready(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        output_outcomes_result: Result<BTreeMap<PeerId, MintOutputOutcome>, String>,
        old_state: MintOutputStateMachine,
        mint_keys: Tiered<AggregatePublicKey>,
    ) -> MintOutputStateMachine {
        let (amount, issuance_request) = match old_state.state {
            MintOutputStates::Created(created) => (created.amount, created.issuance_request),
            _ => panic!("Unexpected prior state"),
        };

        // if the query obtained a threshold of valid blind signature shares, we combine
        // the shares, finalize the issuance request with the blind signature
        // and store the resulting note in the database
        let note_res = output_outcomes_result.and_then(|blind_signature_shares| {
            match mint_keys.tier(&amount) {
                Ok(amount_key) => issuance_request
                    .finalize(
                        aggregate_signature_shares(
                            &blind_signature_shares
                                .iter()
                                .map(|(peer, share)| {
                                    let share = share.ensure_v0_ref().expect(
                                    "We only process output outcome versions created by ourselves",
                                );
                                    (peer.to_usize() as u64 + 1, share.0)
                                })
                                .collect(),
                        ),
                        *amount_key,
                    )
                    .map_err(|e| e.to_string()),
                Err(error) => Err(NoteFinalizationError::InvalidAmountTier(error.0).to_string()),
            }
        });

        match note_res {
            Ok(note) => {
                if let Some(note) = dbtx
                    .module_tx()
                    .insert_entry(
                        &NoteKey {
                            amount,
                            nonce: note.nonce(),
                        },
                        &note,
                    )
                    .await
                {
                    error!(
                        ?note,
                        "E-cash note was replaced in DB, this should never happen!"
                    )
                }

                MintOutputStateMachine {
                    common: old_state.common,
                    state: MintOutputStates::Succeeded(MintOutputStatesSucceeded { amount }),
                }
            }
            Err(error) => MintOutputStateMachine {
                common: old_state.common,
                state: MintOutputStates::Failed(MintOutputStatesFailed { error }),
            },
        }
    }
}

/// # Panics
/// If the given `outcome` is not a [`MintOutputOutcome::V0`] outcome.
pub fn verify_blind_share(
    peer: PeerId,
    outcome: SerdeOutputOutcome,
    amount: Amount,
    request: &NoteIssuanceRequest,
    decoder: &Decoder,
    peer_tbs_pks: &BTreeMap<PeerId, Tiered<PublicKeyShare>>,
) -> anyhow::Result<MintOutputOutcome> {
    let outcome = deserialize_outcome::<MintOutputOutcome>(outcome.clone(), decoder)?;
    let outcome_v0 = outcome
        .ensure_v0_ref()
        .expect("We only process output outcome versions created by ourselves");

    let blinded_message = blind_message(request.nonce().to_message(), request.blinding_key);

    let amount_key = peer_tbs_pks[&peer]
        .tier(&amount)
        .map_err(|_| anyhow!("Invalid Amount Tier"))?;

    if !tbs::verify_blind_share(blinded_message, outcome_v0.0, *amount_key) {
        bail!("Invalid blind signature")
    }

    Ok(outcome)
}

/// See [`MintOutputStates`]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOutputStatesAborted;

/// See [`MintOutputStates`]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOutputStatesFailed {
    pub error: String,
}

/// See [`MintOutputStates`]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct MintOutputStatesSucceeded {
    pub amount: Amount,
}

/// Single [`Note`] issuance request to the mint.f
///
/// Keeps the data to generate [`SpendableNote`] once the
/// mint successfully processed the transaction signing the corresponding
/// [`BlindNonce`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Encodable, Decodable)]
pub struct NoteIssuanceRequest {
    /// Spend key from which the note nonce (corresponding public key) is
    /// derived
    spend_key: KeyPair,
    /// Key to unblind the blind signature supplied by the mint for this note
    blinding_key: BlindingKey,
}

impl NoteIssuanceRequest {
    /// Generate a request session for a single note and returns it plus the
    /// corresponding blinded message
    pub fn new<C>(ctx: &Secp256k1<C>, secret: DerivableSecret) -> (NoteIssuanceRequest, BlindNonce)
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

    pub fn recover_blind_nonce(&self) -> BlindNonce {
        let message = Nonce(self.spend_key.public_key()).to_message();
        BlindNonce(tbs::blind_message(message, self.blinding_key))
    }

    /// Use the blind signatures received from the federation to create
    /// spendable e-cash notes
    pub fn finalize(
        &self,
        bsig: BlindedSignature,
        mint_pub_key: AggregatePublicKey,
    ) -> std::result::Result<SpendableNote, NoteFinalizationError> {
        let signature = unblind_signature(self.blinding_key, bsig);
        let note = Note {
            nonce: self.nonce(),
            signature,
        };
        if note.verify(mint_pub_key) {
            let spendable_note = SpendableNote {
                signature: note.signature,
                spend_key: self.spend_key,
            };

            Ok(spendable_note)
        } else {
            Err(NoteFinalizationError::InvalidSignature)
        }
    }
}

#[derive(Error, Debug)]
pub enum NoteFinalizationError {
    #[error("The returned answer does not fit the request")]
    WrongMintAnswer,
    #[error("The blind signature")]
    InvalidSignature,
    #[error("The blind signature at index {0} is invalid")]
    InvalidSignatureAtIdx(usize),
    #[error("Expected signatures for issuance request {0}, got signatures for request {1}")]
    InvalidIssuanceId(TransactionId, TransactionId),
    #[error("Invalid amount tier {0:?}")]
    InvalidAmountTier(Amount),
    #[error("The client does not know this issuance")]
    UnknownIssuance,
    #[error("The client does not know this output outcome version, it likely didn't generate the associated transaction")]
    UnknownOutputOutcomeVersion(UnknownMintOutputOutcomeVariantError),
}
