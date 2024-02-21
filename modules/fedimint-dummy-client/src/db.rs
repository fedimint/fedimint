use fedimint_client::sm::DynState;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseValue, IDatabaseTransactionOpsCoreTyped};
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
) -> anyhow::Result<Option<(Vec<DynState>, Vec<DynState>)>> {
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

/// Migrates the database from version 1 to version 2. Maps all `Unreachable`
/// states in the state machine to `InputDone`.
pub async fn migrate_to_v2(
    module_instance_id: ModuleInstanceId,
    active_states: Vec<(Vec<u8>, OperationId)>,
    inactive_states: Vec<(Vec<u8>, OperationId)>,
    decoders: ModuleDecoderRegistry,
) -> anyhow::Result<Option<(Vec<DynState>, Vec<DynState>)>> {
    let mut new_active_states = Vec::new();
    for (active_state, _) in active_states {
        // Try to decode the bytes as a `DynState`
        let dynstate = DynState::from_bytes(active_state.as_slice(), &decoders)?;
        let typed_state = dynstate
            .as_any()
            .downcast_ref::<DummyStateMachine>()
            .expect("Unexpected DynState suppilied to migration function");

        match typed_state {
            DummyStateMachine::Unreachable(_, _) => {
                // Try to parse the bytes as the `Unreachable` struct to simulate a deleted
                // state. In a real migration, `DynState::from_bytes` will
                // fail since `DummyStateMachine::Unreachable` will not exist.
                if let Ok(unreachable) =
                    Unreachable::consensus_decode_vec(active_state.clone(), &decoders)
                {
                    new_active_states.push(
                        DummyStateMachine::OutputDone(unreachable.amount, unreachable.operation_id)
                            .into_dyn(module_instance_id),
                    );
                }
            }
            state => new_active_states.push(state.clone().into_dyn(module_instance_id)),
        }
    }

    let mut new_inactive_states = Vec::new();
    for (inactive_state, _) in inactive_states {
        // Try to decode the bytes as a `DynState`
        let dynstate = DynState::from_bytes(inactive_state.as_slice(), &decoders)?;
        let typed_state = dynstate
            .as_any()
            .downcast_ref::<DummyStateMachine>()
            .expect("Unexpected DynState suppilied to migration function");

        match typed_state {
            DummyStateMachine::Unreachable(_, _) => {
                // Try to parse the bytes as the `Unreachable` struct to simulate a deleted
                // state. In a real migration, `DynState::from_bytes` will
                // fail since `DummyStateMachine::Unreachable` will not exist.
                if let Ok(unreachable) =
                    Unreachable::consensus_decode_vec(inactive_state.clone(), &decoders)
                {
                    new_inactive_states.push(
                        DummyStateMachine::OutputDone(unreachable.amount, unreachable.operation_id)
                            .into_dyn(module_instance_id),
                    );
                }
            }
            state => new_inactive_states.push(state.clone().into_dyn(module_instance_id)),
        }
    }

    Ok(Some((new_active_states, new_inactive_states)))
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
