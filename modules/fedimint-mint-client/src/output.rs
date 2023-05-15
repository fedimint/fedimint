use std::time::Duration;

use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::Decoder;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{Amount, OutPoint, Tiered, TieredMulti, TransactionId};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_mint_common::{BlindNonce, MintOutputBlindSignatures, MintOutputOutcome, Nonce, Note};
use secp256k1::{KeyPair, Secp256k1, Signing};
use serde::{Deserialize, Serialize};
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedSignature, BlindingKey};
use thiserror::Error;
use tracing::error;

use crate::db::NoteKey;
use crate::{MintClientContext, SpendableNote};

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
    pub(crate) note_issuance: MultiNoteIssuanceRequest,
}

impl MintOutputStatesCreated {
    fn transitions(
        &self,
        // TODO: make cheaper to clone (Arc?)
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
        common: MintOutputCommon,
    ) -> Vec<StateTransition<MintOutputStateMachine>> {
        let mint_keys = context.mint_keys.clone();
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
                ),
                move |dbtx, bsigs, old_state| {
                    Box::pin(Self::transition_outcome_ready(
                        dbtx,
                        bsigs,
                        old_state,
                        // TODO: avoid clone of whole object
                        mint_keys.clone(),
                    ))
                },
            ),
        ]
    }

    async fn await_tx_rejected(global_context: DynGlobalClientContext, common: MintOutputCommon) {
        global_context
            .await_tx_rejected(common.operation_id, common.out_point.txid)
            .await;
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
    ) -> Result<MintOutputBlindSignatures, String> {
        loop {
            let outcome: MintOutputOutcome = global_context
                .api()
                .await_output_outcome(common.out_point, Duration::MAX, &module_decoder)
                .await
                .map_err(|e| e.to_string())?;

            match outcome.0 {
                Some(bsigs) => return Ok(bsigs),
                None => {
                    // FIXME: hack since we can't await outpoints yet?! may return non-final outcome
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn transition_outcome_ready(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        bsig_res: Result<MintOutputBlindSignatures, String>,
        old_state: MintOutputStateMachine,
        mint_keys: Tiered<AggregatePublicKey>,
    ) -> MintOutputStateMachine {
        let issuance = match old_state.state {
            MintOutputStates::Created(created) => created.note_issuance,
            _ => panic!("Unexpected prior state"),
        };
        let notes_res = bsig_res.and_then(|bsigs| {
            issuance
                .finalize(bsigs, &mint_keys)
                .map_err(|e| e.to_string())
        });

        match notes_res {
            Ok(notes) => {
                for (amount, note) in notes.iter_items() {
                    let replaced = dbtx
                        .module_tx()
                        .insert_entry(
                            &NoteKey {
                                amount,
                                nonce: note.note.0,
                            },
                            note,
                        )
                        .await;
                    if let Some(note) = replaced {
                        error!(
                            ?note,
                            "E-cash note was replaced in DB, this should never happen!"
                        )
                    }
                }
                MintOutputStateMachine {
                    common: old_state.common,
                    state: MintOutputStates::Succeeded(MintOutputStatesSucceeded {
                        amount: notes.total_amount(),
                    }),
                }
            }
            Err(error) => MintOutputStateMachine {
                common: old_state.common,
                state: MintOutputStates::Failed(MintOutputStatesFailed { error }),
            },
        }
    }
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
    amount: Amount,
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
    pub(crate) fn new<C>(
        ctx: &Secp256k1<C>,
        secret: DerivableSecret,
    ) -> (NoteIssuanceRequest, BlindNonce)
    where
        C: Signing,
    {
        let spend_key = secret.child_key(SPEND_KEY_CHILD_ID).to_secp_key(ctx);
        let nonce = Nonce(spend_key.x_only_public_key().0);
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
        Nonce(self.spend_key.x_only_public_key().0)
    }

    pub fn recover_blind_nonce(&self) -> BlindNonce {
        let message = Nonce(self.spend_key.x_only_public_key().0).to_message();
        BlindNonce(tbs::blind_message(message, self.blinding_key))
    }

    /// Use the blind signatures received from the federation to create
    /// spendable e-cash notes
    pub fn finalize(
        &self,
        bsig: BlindedSignature,
        mint_pub_key: AggregatePublicKey,
    ) -> std::result::Result<SpendableNote, NoteFinalizationError> {
        let sig = unblind_signature(self.blinding_key, bsig);
        let note = Note(self.nonce(), sig);
        if note.verify(mint_pub_key) {
            let spendable_note = SpendableNote {
                note,
                spend_key: self.spend_key,
            };

            Ok(spendable_note)
        } else {
            Err(NoteFinalizationError::InvalidSignature)
        }
    }
}

/// Multiple [`Note`] issuance requests
///
/// Keeps all the data to generate [`SpendableNote`]s once the
/// mint successfully processed corresponding [`NoteIssuanceRequest`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, Encodable, Decodable)]
pub struct MultiNoteIssuanceRequest {
    /// Finalization data for all note outputs in this request
    pub notes: TieredMulti<NoteIssuanceRequest>,
}

impl MultiNoteIssuanceRequest {
    /// Finalize the issuance request using a [`MintOutputBlindSignatures`] from
    /// the mint containing the blind signatures for all notes in this
    /// `IssuanceRequest`. It also takes the mint's [`AggregatePublicKey`]
    /// to validate the supplied blind signatures.
    pub fn finalize(
        &self,
        bsigs: MintOutputBlindSignatures,
        mint_pub_key: &Tiered<AggregatePublicKey>,
    ) -> std::result::Result<TieredMulti<SpendableNote>, NoteFinalizationError> {
        if !self.notes.structural_eq(&bsigs.0) {
            return Err(NoteFinalizationError::WrongMintAnswer);
        }

        self.notes
            .iter_items()
            .zip(bsigs.0)
            .enumerate()
            .map(|(idx, ((amt, note_req), (_amt, bsig)))| {
                Ok((
                    amt,
                    match note_req.finalize(
                        bsig,
                        *mint_pub_key
                            .tier(&amt)
                            .map_err(|e| NoteFinalizationError::InvalidAmountTier(e.0))?,
                    ) {
                        Err(NoteFinalizationError::InvalidSignature) => {
                            Err(NoteFinalizationError::InvalidSignatureAtIdx(idx))
                        }
                        other => other,
                    }?,
                ))
            })
            .collect()
    }
}

impl Extend<(Amount, NoteIssuanceRequest)> for MultiNoteIssuanceRequest {
    fn extend<T: IntoIterator<Item = (Amount, NoteIssuanceRequest)>>(&mut self, iter: T) {
        self.notes.extend(iter)
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
}
