use std::io::Cursor;

use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseValue as _, WriteDatabaseTransaction};
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::util::BoxFuture;

/// `ClientMigrationFn` is a function that modules can implement to "migrate"
/// the database to the next database version.
pub type ClientModuleMigrationFn = for<'r, 'tx> fn(
    &'r mut WriteDatabaseTransaction<'tx>,
    Vec<(Vec<u8>, OperationId)>, // active states
    Vec<(Vec<u8>, OperationId)>, // inactive states
) -> BoxFuture<
    'r,
    anyhow::Result<Option<(Vec<(Vec<u8>, OperationId)>, Vec<(Vec<u8>, OperationId)>)>>,
>;

/// Helper function definition for migrating a single state.
type MigrateStateFn =
    fn(OperationId, &mut Cursor<&[u8]>) -> anyhow::Result<Option<(Vec<u8>, OperationId)>>;

/// Migrates a particular state by looping over all active and inactive states.
/// If the `migrate` closure returns `None`, this state was not migrated and
/// should be added to the new state machine vectors.
pub fn migrate_state(
    active_states: Vec<(Vec<u8>, OperationId)>,
    inactive_states: Vec<(Vec<u8>, OperationId)>,
    migrate: MigrateStateFn,
) -> anyhow::Result<Option<(Vec<(Vec<u8>, OperationId)>, Vec<(Vec<u8>, OperationId)>)>> {
    let mut new_active_states = Vec::with_capacity(active_states.len());
    for (active_state, operation_id) in active_states {
        let bytes = active_state.as_slice();

        let decoders = ModuleDecoderRegistry::default();
        let mut cursor = std::io::Cursor::new(bytes);
        let module_instance_id = fedimint_core::core::ModuleInstanceId::consensus_decode_partial(
            &mut cursor,
            &decoders,
        )?;

        let state = match migrate(operation_id, &mut cursor)? {
            Some((mut state, operation_id)) => {
                let mut final_state = module_instance_id.to_bytes();
                final_state.append(&mut state);
                (final_state, operation_id)
            }
            None => (active_state, operation_id),
        };

        new_active_states.push(state);
    }

    let mut new_inactive_states = Vec::with_capacity(inactive_states.len());
    for (inactive_state, operation_id) in inactive_states {
        let bytes = inactive_state.as_slice();

        let decoders = ModuleDecoderRegistry::default();
        let mut cursor = std::io::Cursor::new(bytes);
        let module_instance_id = fedimint_core::core::ModuleInstanceId::consensus_decode_partial(
            &mut cursor,
            &decoders,
        )?;

        let state = match migrate(operation_id, &mut cursor)? {
            Some((mut state, operation_id)) => {
                let mut final_state = module_instance_id.to_bytes();
                final_state.append(&mut state);
                (final_state, operation_id)
            }
            None => (inactive_state, operation_id),
        };

        new_inactive_states.push(state);
    }

    Ok(Some((new_active_states, new_inactive_states)))
}
