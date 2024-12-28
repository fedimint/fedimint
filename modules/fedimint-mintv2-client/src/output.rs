use std::collections::BTreeMap;

use anyhow::ensure;
use fedimint_client::DynGlobalClientContext;
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::PeerId;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::Denomination;
use tbs::{AggregatePublicKey, BlindedSignatureShare, PublicKeyShare, aggregate_signature_shares};

use crate::api::MintV2ModuleApi;
use crate::client_db::SpendableNoteKey;
use crate::{MintClientContext, NoteIssuanceRequest, issuance};

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
            OutputSMState::Pending => vec![StateTransition::new(
                Self::await_signature_shares(
                    global_context.clone(),
                    self.common.range,
                    self.common.issuance_requests.clone(),
                    context.tbs_pks.clone(),
                    context.root_secret.clone(),
                ),
                move |dbtx, signature_shares, old_state| {
                    Box::pin(Self::transition_outcome_ready(
                        dbtx,
                        signature_shares,
                        old_state,
                        context.tbs_agg_pks.clone(),
                        context.root_secret.clone(),
                    ))
                },
            )],
            OutputSMState::Aborted | OutputSMState::Failure | OutputSMState::Success => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl MintOutputStateMachine {
    async fn await_signature_shares(
        global_context: DynGlobalClientContext,
        range: Option<OutPointRange>,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
        root_secret: DerivableSecret,
    ) -> Result<BTreeMap<PeerId, Vec<BlindedSignatureShare>>, String> {
        if let Some(range) = range {
            global_context.await_tx_accepted(range.txid).await?;

            global_context
                .module_api()
                .fetch_signature_shares(range, issuance_requests, tbs_pks, root_secret)
                .await
        } else {
            global_context
                .module_api()
                .fetch_signature_shares_recovery(issuance_requests, tbs_pks, root_secret)
                .await
        }
    }

    async fn transition_outcome_ready(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        signature_shares: Result<BTreeMap<PeerId, Vec<BlindedSignatureShare>>, String>,
        old_state: MintOutputStateMachine,
        tbs_pks: BTreeMap<Denomination, AggregatePublicKey>,
        root_secret: DerivableSecret,
    ) -> MintOutputStateMachine {
        let Ok(signature_shares) = signature_shares else {
            return MintOutputStateMachine {
                common: old_state.common,
                state: OutputSMState::Aborted,
            };
        };

        for (i, request) in old_state.common.issuance_requests.iter().enumerate() {
            let agg_blind_signature = aggregate_signature_shares(
                &signature_shares
                    .iter()
                    .map(|(peer, shares)| (peer.to_usize() as u64, shares[i]))
                    .collect(),
            );

            let spendable_note = request.finalize(&root_secret, agg_blind_signature);

            if !spendable_note.note().verify(
                *tbs_pks
                    .get(&request.denomination)
                    .expect("No aggregated pk found for denomination"),
            ) {
                return MintOutputStateMachine {
                    common: old_state.common,
                    state: OutputSMState::Failure,
                };
            }

            dbtx.module_tx()
                .insert_new_entry(&SpendableNoteKey(spendable_note), &())
                .await;
        }

        MintOutputStateMachine {
            common: old_state.common,
            state: OutputSMState::Success,
        }
    }
}

pub fn verify_blind_shares(
    peer: PeerId,
    signature_shares: Vec<BlindedSignatureShare>,
    issuance_requests: &[NoteIssuanceRequest],
    tbs_pks: &BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
    root_secret: &DerivableSecret,
) -> anyhow::Result<Vec<BlindedSignatureShare>> {
    ensure!(
        signature_shares.len() == issuance_requests.len(),
        "Invalid number of signatures shares"
    );

    for (request, share) in issuance_requests.iter().zip(signature_shares.iter()) {
        let amount_key = tbs_pks
            .get(&request.denomination)
            .expect("No pk shares found for denomination")
            .get(&peer)
            .expect("No pk share found for peer {peer}");

        ensure!(
            tbs::verify_signature_share(
                issuance::blinded_message(&issuance::output_secret(
                    request.denomination,
                    request.tweak,
                    root_secret,
                )),
                *share,
                *amount_key
            ),
            "Invalid blind signature"
        );
    }

    Ok(signature_shares)
}
