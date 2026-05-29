use std::collections::BTreeMap;

use fedimint_client_module::module::ClientContext;
use fedimint_client_module::module::init::ClientModuleRecoverArgs;
use fedimint_client_module::module::init::recovery::{
    RecoveryFromHistory, RecoveryFromHistoryCommon,
};
use fedimint_client_module::module::recovery::{DynModuleBackup, ModuleBackup};
use fedimint_client_module::{ModuleInstanceId, ModuleKind};
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{BitcoinHash, OutPoint, apply, async_trait_maybe_send};
use fedimint_escrow_common::{EscrowId, EscrowInput, EscrowOutput, KIND, Outcome, Resolution};
use serde::{Deserialize, Serialize};

use crate::EscrowClientInit;
use crate::client_db::{
    ClientEscrowKey, EscrowClientRecord, EscrowClientStatus, EscrowRecoveryFinalizedKey,
    EscrowRecoveryStateKey,
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct EscrowBackup {
    pub session_count: u64,
    pub records: Vec<EscrowClientRecord>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct EscrowRecovery {
    pub client_pubkey: fedimint_core::secp256k1::PublicKey,
    pub found_records: BTreeMap<EscrowId, EscrowClientRecord>,
}

impl ModuleBackup for EscrowBackup {
    const KIND: Option<ModuleKind> = Some(KIND);
}

impl IntoDynInstance for EscrowBackup {
    type DynType = DynModuleBackup;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleBackup::from_typed(instance_id, self)
    }
}

#[apply(async_trait_maybe_send!)]
impl RecoveryFromHistory for EscrowRecovery {
    type Init = EscrowClientInit;

    async fn new(
        _init: &EscrowClientInit,
        args: &ClientModuleRecoverArgs<EscrowClientInit>,
        snapshot: Option<&EscrowBackup>,
    ) -> anyhow::Result<(Self, u64)> {
        let keypair = args
            .module_root_secret()
            .clone()
            .to_secp_key(&fedimint_core::secp256k1::Secp256k1::new());

        let client_pubkey = keypair.public_key();

        let mut found_records = BTreeMap::new();
        let start_session = if let Some(backup) = snapshot {
            for record in &backup.records {
                found_records.insert(record.escrow_id, record.clone());
            }
            backup.session_count
        } else {
            0
        };

        Ok((
            EscrowRecovery {
                client_pubkey,
                found_records,
            },
            start_session,
        ))
    }

    async fn load_dbtx(
        _init: &EscrowClientInit,
        dbtx: &mut DatabaseTransaction<'_>,
        _args: &ClientModuleRecoverArgs<EscrowClientInit>,
    ) -> anyhow::Result<Option<(Self, RecoveryFromHistoryCommon)>> {
        Ok(dbtx.get_value(&EscrowRecoveryStateKey).await)
    }

    async fn store_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        common: &RecoveryFromHistoryCommon,
    ) {
        dbtx.insert_entry(&EscrowRecoveryStateKey, &(self.clone(), common.clone()))
            .await;
    }

    async fn delete_dbtx(&self, dbtx: &mut DatabaseTransaction<'_>) {
        dbtx.remove_entry(&EscrowRecoveryStateKey).await;
    }

    async fn load_finalized(dbtx: &mut DatabaseTransaction<'_>) -> Option<bool> {
        dbtx.get_value(&EscrowRecoveryFinalizedKey).await
    }

    async fn store_finalized(dbtx: &mut DatabaseTransaction<'_>, state: bool) {
        dbtx.insert_entry(&EscrowRecoveryFinalizedKey, &state).await;
    }

    async fn handle_output(
        &mut self,
        _client_ctx: &ClientContext<crate::EscrowClientModule>,
        out_point: OutPoint,
        output: &EscrowOutput,
        _session_idx: u64,
    ) -> anyhow::Result<()> {
        let contract = &output.contract;

        let is_participant = self.client_pubkey == contract.buyer_key
            || self.client_pubkey == contract.seller_key
            || self.client_pubkey == contract.arbiter_key;

        if !is_participant {
            return Ok(());
        }

        let placeholder_operation_id = OperationId(*out_point.txid.as_byte_array());

        self.found_records
            .entry(contract.escrow_id)
            .or_insert_with(|| EscrowClientRecord {
                escrow_id: contract.escrow_id,
                operation_id: placeholder_operation_id,
                amount: contract.amount,
                status: EscrowClientStatus::Active,
            });

        Ok(())
    }

    async fn handle_input(
        &mut self,
        _client_ctx: &ClientContext<crate::EscrowClientModule>,
        _idx: usize,
        input: &EscrowInput,
        _session_idx: u64,
    ) -> anyhow::Result<()> {
        if let Some(record) = self.found_records.get_mut(&input.escrow_id) {
            record.status = match &input.resolution {
                Resolution::BuyerRelease { .. } => EscrowClientStatus::Released,
                Resolution::ArbiterOutcome { outcome, .. } => match outcome {
                    Outcome::Release => EscrowClientStatus::Released,
                    Outcome::Refund => EscrowClientStatus::Refunded,
                },
            };
        }
        Ok(())
    }

    async fn finalize_dbtx(&self, dbtx: &mut DatabaseTransaction<'_>) -> anyhow::Result<()> {
        for (escrow_id, record) in &self.found_records {
            dbtx.insert_entry(&ClientEscrowKey(*escrow_id), record)
                .await;
        }
        Ok(())
    }
}
