use std::collections::BTreeMap;

use fedimint_client::DynGlobalClientContext;
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, runtime};
use fedimint_mintv2_common::{Denomination, verify_note};
use serde::{Deserialize, Serialize};
use tbs::{
    AggregatePublicKey, BlindedSignature, BlindedSignatureShare, PublicKeyShare,
    aggregate_signature_shares,
};

use crate::api::MintV2ModuleApi;
use crate::client_db::SpendableNoteKey;
use crate::{MintClientContext, NoteIssuanceRequest};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintOutputStateMachine {
    pub common: OutputSMCommon,
    pub state: OutputSMState,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct OutputSMCommon {
    pub operation_id: OperationId,
    pub range: Option<OutPointRange>,
    pub issuance_requests: Vec<NoteIssuanceRequest>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum OutputSMState {
    /// Issuance request was created, we are waiting for blind signatures.
    Pending,
    /// The transaction containing the issuance was rejected, we can stop
    /// looking for decryption shares.
    Aborted,
    /// The transaction containing the issuance was accepted but an unexpected
    /// error occurred, this should never happen with a honest federation and
    /// bug-free code.
    Failure,
    /// The issuance was completed successfully and the e-cash notes added to
    /// our wallet.
    Success,
}

impl State for MintOutputStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let context = context.clone();

        match &self.state {
            OutputSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_issuance(
                        global_context.clone(),
                        self.common.range,
                        self.common.issuance_requests.clone(),
                        context.tbs_pks.clone(),
                        context.tbs_agg_pks.clone(),
                    ),
                    move |dbtx, outcome, old_state| {
                        let balance_update_sender = context.balance_update_sender.clone();

                        dbtx.module_tx()
                            .on_commit(move || balance_update_sender.send_replace(()));

                        Box::pin(Self::transition_issuance(dbtx, outcome, old_state))
                    },
                )]
            }
            OutputSMState::Aborted | OutputSMState::Failure | OutputSMState::Success => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

/// What the issuance trigger resolves to.
///
/// The shares are aggregated and the notes verified in the trigger, off the
/// async workers, so the transition only unblinds and inserts them.
#[derive(Debug, Serialize, Deserialize)]
pub enum IssuanceOutcome {
    /// The transaction containing the issuance was rejected.
    Aborted,
    /// The aggregated signatures of the notes that verified, in order, and
    /// whether one did not: the verified ones are kept either way, the
    /// machine fails on the invalid one.
    Signatures {
        signatures: Vec<BlindedSignature>,
        invalid: bool,
    },
}

impl MintOutputStateMachine {
    async fn await_issuance(
        global_context: DynGlobalClientContext,
        range: Option<OutPointRange>,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
        tbs_agg_pks: BTreeMap<Denomination, AggregatePublicKey>,
    ) -> IssuanceOutcome {
        let signature_shares = if let Some(range) = range {
            if global_context.await_tx_accepted(range.txid).await.is_err() {
                return IssuanceOutcome::Aborted;
            }

            global_context
                .module_api()
                .fetch_signature_shares(range, issuance_requests.clone(), tbs_pks)
                .await
        } else {
            global_context
                .module_api()
                .fetch_signature_shares_recovery(issuance_requests.clone(), tbs_pks)
                .await
        };

        // Aggregating a note's shares is a Lagrange interpolation and verifying
        // it two pairings; keep them off the async workers.
        runtime::spawn_blocking(move || {
            let mut signatures = Vec::with_capacity(issuance_requests.len());

            for (i, request) in issuance_requests.iter().enumerate() {
                let agg_blind_signature = aggregate_signature_shares(
                    &signature_shares
                        .iter()
                        .map(|(peer, shares)| (peer.to_usize() as u64, shares[i]))
                        .collect(),
                );

                let spendable_note = request.finalize(agg_blind_signature);

                let pk = *tbs_agg_pks
                    .get(&request.denomination)
                    .expect("No aggregated pk found for denomination");

                if !verify_note(spendable_note.note(), pk) {
                    return IssuanceOutcome::Signatures {
                        signatures,
                        invalid: true,
                    };
                }

                signatures.push(agg_blind_signature);
            }

            IssuanceOutcome::Signatures {
                signatures,
                invalid: false,
            }
        })
        .await
    }

    async fn transition_issuance(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outcome: IssuanceOutcome,
        old_state: MintOutputStateMachine,
    ) -> MintOutputStateMachine {
        let (signatures, invalid) = match outcome {
            IssuanceOutcome::Aborted => {
                return MintOutputStateMachine {
                    common: old_state.common,
                    state: OutputSMState::Aborted,
                };
            }
            IssuanceOutcome::Signatures {
                signatures,
                invalid,
            } => (signatures, invalid),
        };

        for (request, signature) in old_state.common.issuance_requests.iter().zip(signatures) {
            dbtx.module_tx()
                .insert_new_entry(&SpendableNoteKey(request.finalize(signature)), &())
                .await;
        }

        MintOutputStateMachine {
            common: old_state.common,
            state: if invalid {
                OutputSMState::Failure
            } else {
                OutputSMState::Success
            },
        }
    }
}

pub fn verify_blind_shares(
    peer: PeerId,
    signature_shares: Vec<BlindedSignatureShare>,
    issuance_requests: &[NoteIssuanceRequest],
    tbs_pks: &BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
) -> Result<Vec<BlindedSignatureShare>, VerifyBlindSharesError> {
    if signature_shares.len() != issuance_requests.len() {
        return Err(VerifyBlindSharesError::ShareCount);
    }

    for (request, share) in issuance_requests.iter().zip(signature_shares.iter()) {
        let amount_key = tbs_pks
            .get(&request.denomination)
            .expect("No pk shares found for denomination")
            .get(&peer)
            .expect("No pk share found for peer");

        if !tbs::verify_signature_share(request.blinded_message(), *share, *amount_key) {
            return Err(VerifyBlindSharesError::InvalidShare);
        }
    }

    Ok(signature_shares)
}

/// Why a guardian's blind signature shares were rejected.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VerifyBlindSharesError {
    /// The guardian sent a different number of shares than notes were
    /// requested.
    #[error("Invalid number of signatures shares")]
    ShareCount,

    /// A share does not verify against the guardian's public key share.
    #[error("Invalid blind signature")]
    InvalidShare,
}
