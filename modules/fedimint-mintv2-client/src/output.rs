use std::collections::BTreeMap;

use anyhow::ensure;
use fedimint_api_client::api::FederationApiExt;
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_client::module::{ClientContext, OutPointRange};
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::{Amount, NumPeersExt, PeerId};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::endpoint_constants::SIGNATURE_SHARES_ENDPOINT;
use tbs::{
    aggregate_signature_shares, AggregatePublicKey, BlindedMessage, BlindedSignatureShare,
    PublicKeyShare,
};

use crate::client_db::SpendableNoteKey;
use crate::event::NoteCreated;
use crate::{MintClientContext, MintClientModule, NoteIssuanceRequest};

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
        let client_ctx = context.client_ctx.clone();

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
                        client_ctx.clone(),
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
        tbs_pks: BTreeMap<Amount, BTreeMap<PeerId, PublicKeyShare>>,
        root_secret: DerivableSecret,
    ) -> Result<BTreeMap<PeerId, Vec<BlindedSignatureShare>>, String> {
        if let Some(range) = range {
            global_context.await_tx_accepted(range.txid()).await?;
        }

        let nonces = issuance_requests
            .iter()
            .map(|request| request.blinded_message(&root_secret))
            .collect::<Vec<BlindedMessage>>();

        let shares = global_context
            .module_api()
            .request_with_strategy_retry(
                // This query collects a threshold of 2f + 1 valid blind signature shares
                FilterMapThreshold::new(
                    move |peer, signature_shares| {
                        verify_blind_shares(
                            peer,
                            signature_shares,
                            &issuance_requests,
                            &tbs_pks,
                            &root_secret,
                        )
                    },
                    global_context.api().all_peers().to_num_peers(),
                ),
                SIGNATURE_SHARES_ENDPOINT.to_owned(),
                ApiRequestErased::new(nonces),
            )
            .await;

        Ok(shares)
    }

    async fn transition_outcome_ready(
        client_ctx: ClientContext<MintClientModule>,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        signature_shares: Result<BTreeMap<PeerId, Vec<BlindedSignatureShare>>, String>,
        old_state: MintOutputStateMachine,
        tbs_pks: BTreeMap<Amount, AggregatePublicKey>,
        root_secret: DerivableSecret,
    ) -> MintOutputStateMachine {
        let signature_shares = match signature_shares {
            Ok(signature_shares) => signature_shares,
            Err(..) => {
                return MintOutputStateMachine {
                    common: old_state.common,
                    state: OutputSMState::Aborted,
                }
            }
        };

        for (i, request) in old_state.common.issuance_requests.iter().enumerate() {
            let agg_blind_signature = aggregate_signature_shares(
                &signature_shares
                    .iter()
                    .map(|(peer, shares)| (peer.to_usize() as u64 + 1, shares[i]))
                    .collect(),
            );

            let spendable_note = request.finalize(&root_secret, agg_blind_signature);

            if !spendable_note.note().verify(
                *tbs_pks
                    .get(&request.amount)
                    .expect("No aggregated pk found for amount"),
            ) {
                return MintOutputStateMachine {
                    common: old_state.common,
                    state: OutputSMState::Failure,
                };
            }

            client_ctx
                .log_event(
                    &mut dbtx.module_tx(),
                    NoteCreated {
                        nonce: spendable_note.nonce(),
                    },
                )
                .await;

            dbtx.module_tx()
                .insert_new_entry(&SpendableNoteKey(spendable_note), &())
                .await
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
    issuance_requests: &Vec<NoteIssuanceRequest>,
    tbs_pks: &BTreeMap<Amount, BTreeMap<PeerId, PublicKeyShare>>,
    root_secret: &DerivableSecret,
) -> anyhow::Result<Vec<BlindedSignatureShare>> {
    ensure!(
        signature_shares.len() == issuance_requests.len(),
        "Invalid number of signatures shares"
    );

    for (request, share) in issuance_requests.iter().zip(signature_shares.iter()) {
        let amount_key = tbs_pks
            .get(&request.amount)
            .expect("No pk shares found for amount {amount}")
            .get(&peer)
            .expect("No pk share found for peer {peer}");

        ensure!(
            tbs::verify_blind_share(request.blinded_message(root_secret), *share, *amount_key),
            "Invalid blind signature"
        );
    }

    Ok(signature_shares)
}
