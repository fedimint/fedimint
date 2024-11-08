use fedimint_client::module::recovery::{DynModuleBackup, ModuleBackup};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, Tiered, TieredMulti};
use fedimint_mint_common::KIND;
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

impl ModuleBackup for EcashBackup {
    const KIND: Option<ModuleKind> = Some(KIND);
}

impl IntoDynInstance for EcashBackup {
    type DynType = DynModuleBackup;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleBackup::from_typed(instance_id, self)
    }
}

impl MintClientModule {
    pub async fn prepare_plaintext_ecash_backup(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> anyhow::Result<EcashBackup> {
        // fetch consensus height first - so we dont miss anything when scanning
        let session_count = self.client_ctx.global_api().session_count().await?;

        let notes = Self::get_all_spendable_notes(dbtx).await;

        let pending_notes: Vec<(OutPoint, Amount, NoteIssuanceRequest)> = self
            .client_ctx
            .get_own_active_states()
            .await
            .into_iter()
            .filter_map(|(state, _active_state)| match state {
                MintClientStateMachines::Output(MintOutputStateMachine {
                    common,
                    state: crate::output::MintOutputStates::Created(created_state),
                }) => Some(vec![(
                    OutPoint {
                        txid: common.out_point_range.txid(),
                        // MintOutputStates::Created always has one out_idx
                        out_idx: common.out_point_range.start_idx(),
                    },
                    created_state.amount,
                    created_state.issuance_request,
                )]),
                MintClientStateMachines::Output(MintOutputStateMachine {
                    common,
                    state: crate::output::MintOutputStates::CreatedMulti(created_state),
                }) => Some(
                    common
                        .out_point_range
                        .into_iter()
                        .map(|(txid, out_idx)| {
                            let issuance_request = created_state
                                .issuance_requests
                                .get(&out_idx)
                                .expect("Must have corresponding out_idx");
                            (
                                OutPoint { txid, out_idx },
                                issuance_request.0,
                                issuance_request.1,
                            )
                        })
                        .collect(),
                ),
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>();

        let mut idxes = vec![];
        for &amount in self.cfg.tbs_pks.tiers() {
            idxes.push((amount, self.get_next_note_index(dbtx, amount).await));
        }
        let next_note_idx = Tiered::from_iter(idxes);

        Ok(EcashBackup::new_v0(
            notes
                .into_iter_items()
                .map(|(amt, spendable_note)| Ok((amt, spendable_note.decode()?)))
                .collect::<anyhow::Result<TieredMulti<_>>>()?,
            pending_notes,
            session_count,
            next_note_idx,
        ))
    }
}
