use fedimint_client::module::recovery::{DynModuleBackup, ModuleBackup};
use fedimint_client::module::ClientDbTxContext;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, Tiered, TieredMulti};
use serde::{Deserialize, Serialize};

use super::MintClientModule;
use crate::output::{MintOutputStateMachine, NoteIssuanceRequest};
use crate::{MintClientStateMachines, NoteIndex, SpendableNote};

pub mod recovery;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub enum EcashBackup {
    V0(EcashBackupV0),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl EcashBackup {
    pub fn new_v0(
        spendable_notes: TieredMulti<SpendableNote>,
        pending_notes: Vec<(OutPoint, Amount, NoteIssuanceRequest)>,
        session_count: u64,
        next_note_idx: Tiered<NoteIndex>,
    ) -> EcashBackup {
        EcashBackup::V0(EcashBackupV0 {
            spendable_notes,
            pending_notes,
            session_count,
            next_note_idx,
        })
    }
}

/// Snapshot of a ecash state (notes)
///
/// Used to speed up and improve privacy of ecash recovery,
/// by avoiding scanning the whole history.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct EcashBackupV0 {
    spendable_notes: TieredMulti<SpendableNote>,
    pending_notes: Vec<(OutPoint, Amount, NoteIssuanceRequest)>,
    session_count: u64,
    next_note_idx: Tiered<NoteIndex>,
}

impl EcashBackupV0 {
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

impl ModuleBackup for EcashBackup {}

impl IntoDynInstance for EcashBackup {
    type DynType = DynModuleBackup;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleBackup::from_typed(instance_id, self)
    }
}

impl MintClientModule {
    pub async fn prepare_plaintext_ecash_backup(
        &self,
        dbtx_ctx: &'_ mut ClientDbTxContext<'_, '_, Self>,
    ) -> anyhow::Result<EcashBackup> {
        // fetch consensus height first - so we dont miss anything when scanning
        let session_count = self.client_ctx.global_api().session_count().await?;

        let notes = Self::get_all_spendable_notes(&mut dbtx_ctx.module_dbtx()).await;

        let pending_notes: Vec<(OutPoint, Amount, NoteIssuanceRequest)> = self.client_ctx.get_own_active_states().await.into_iter()
            .filter_map(|(state, _active_state)| {

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
            idxes.push((
                amount,
                self.get_next_note_index(&mut dbtx_ctx.module_dbtx(), amount)
                    .await,
            ));
        }
        let next_note_idx = Tiered::from_iter(idxes);

        Ok(EcashBackup::new_v0(
            notes,
            pending_notes,
            session_count,
            next_note_idx,
        ))
    }
}
