use fedimint_client::sm::Executor;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::{DynGlobalApi, GlobalFederationApi};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, Tiered, TieredMulti};
use serde::{Deserialize, Serialize};

use super::MintClientModule;
use crate::output::{MintOutputStateMachine, NoteIssuanceRequest};
use crate::{MintClientStateMachines, NoteIndex, SpendableNote};

pub mod recovery;

/// Snapshot of a ecash state (notes)
///
/// Used to speed up and improve privacy of ecash recovery,
/// by avoiding scanning the whole history.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct EcashBackup {
    spendable_notes: TieredMulti<SpendableNote>,
    pending_notes: Vec<(OutPoint, Amount, NoteIssuanceRequest)>,
    session_count: u64,
    next_note_idx: Tiered<NoteIndex>,
}

impl EcashBackup {
    /// An empty backup with, like a one created by a newly created client.
    pub fn new_empty() -> Self {
        Self {
            spendable_notes: TieredMulti::default(),
            pending_notes: vec![],
            session_count: 0,
            next_note_idx: Tiered::default(),
        }
    }
}

impl MintClientModule {
    pub async fn prepare_plaintext_ecash_backup(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        executor: Executor<DynGlobalClientContext>,
        api: DynGlobalApi,
        module_instance_id: ModuleInstanceId,
    ) -> anyhow::Result<EcashBackup> {
        // fetch consensus height first - so we dont miss anything when scanning
        let session_count = api.session_count().await?;

        let notes = Self::get_all_spendable_notes(dbtx).await;

        let pending_notes: Vec<(OutPoint, Amount, NoteIssuanceRequest)> = executor
            .get_active_states()
            .await
            .into_iter()
            .filter_map(|(dyn_state, _active_state)| {
                if dyn_state.module_instance_id() != module_instance_id {
                    return None;
                }

                let state: MintClientStateMachines = dyn_state
                    .as_any()
                    .downcast_ref()
                    .cloned()
                    .expect("Can't downcast mint client state machine state");

                match state {
                    MintClientStateMachines::Output(MintOutputStateMachine { common, state }) => {
                        match state {
                            crate::output::MintOutputStates::Created(state) => Some((common.out_point, state.amount, state.issuance_request)),
                            crate::output::MintOutputStates::Succeeded(_) => None /* we back these via get_all_spendable_notes */,
                            _ => None,
                        }
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>() ;

        let mut idxes = vec![];
        for &amount in self.cfg.tbs_pks.tiers() {
            idxes.push((amount, self.get_next_note_index(dbtx, amount).await));
        }
        let next_note_idx = Tiered::from_iter(idxes);

        Ok(EcashBackup {
            spendable_notes: notes,
            pending_notes,
            next_note_idx,
            session_count,
        })
    }
}
