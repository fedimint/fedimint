use fedimint_core::core::{ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{impl_db_record, Amount};
use strum_macros::EnumIter;
use tracing::warn;

use crate::states::DummyStateMachine;

#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    ClientFunds = 0x04,
    // Used to verify that 0x50 key can be written to, which used to conflict with
    // `DatabaseVersionKeyV0`
    ClientName = 0x50,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientFundsKeyV0;

impl_db_record!(
    key = DummyClientFundsKeyV0,
    value = (),
    db_prefix = DbKeyPrefix::ClientFunds,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientFundsKeyV1;

impl_db_record!(
    key = DummyClientFundsKeyV1,
    value = Amount,
    db_prefix = DbKeyPrefix::ClientFunds,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientNameKey;

impl_db_record!(
    key = DummyClientNameKey,
    value = String,
    db_prefix = DbKeyPrefix::ClientName,
);

/// Migrates the database from version 0 to version 1 by
/// removing `DummyClientFundsKeyV0` and inserting `DummyClientFundsKeyV1`.
/// The new key/value pair has an `Amount` as the value.
pub async fn migrate_to_v1(
    dbtx: &mut DatabaseTransaction<'_>,
) -> anyhow::Result<Option<(Vec<(Vec<u8>, OperationId)>, Vec<(Vec<u8>, OperationId)>)>> {
    if dbtx.remove_entry(&DummyClientFundsKeyV0).await.is_some() {
        // Since this is a dummy migration, we can insert any value for the client
        // funds. Real modules should handle the funds properly.

        dbtx.insert_new_entry(&DummyClientFundsKeyV1, &Amount::from_sats(1000))
            .await;
    } else {
        warn!("Dummy client did not have client funds, skipping database migration");
    }

    Ok(None)
}

/// Maps all `Unreachable` states in the state machine to `OutputDone`
pub(crate) fn get_v1_migrated_state(
    bytes: &[u8],
    operation_id: OperationId,
) -> anyhow::Result<Option<(Vec<u8>, OperationId)>> {
    let decoders = ModuleDecoderRegistry::default();
    let mut cursor = std::io::Cursor::new(bytes);
    let module_instance_id =
        fedimint_core::core::ModuleInstanceId::consensus_decode(&mut cursor, &decoders)?;
    let dummy_sm_variant = u16::consensus_decode(&mut cursor, &decoders)?;

    if dummy_sm_variant != 5 {
        return Ok(None);
    }

    // Migrate `Unreachable` states to `OutputDone`
    let unreachable = Unreachable::consensus_decode(&mut cursor, &decoders)?;
    let new_state = DummyStateMachine::OutputDone(unreachable.amount, unreachable.operation_id);
    let bytes = (module_instance_id, new_state).consensus_encode_to_vec();
    Ok(Some((bytes, operation_id)))
}

#[derive(Debug)]
struct Unreachable {
    _module_instance_id: ModuleInstanceId,
    operation_id: OperationId,
    amount: Amount,
}

impl Decodable for Unreachable {
    fn consensus_decode<R: std::io::Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let module_instance_id = ModuleInstanceId::consensus_decode(reader, modules)?;
        let operation_id = OperationId::consensus_decode(reader, modules)?;
        let amount = Amount::consensus_decode(reader, modules)?;

        Ok(Unreachable {
            _module_instance_id: module_instance_id,
            operation_id,
            amount,
        })
    }
}
