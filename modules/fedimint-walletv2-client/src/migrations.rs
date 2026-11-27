//! Client database migrations.

use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, DbMigrationError, IDatabaseTransactionOpsCoreTyped};

use crate::db::{NextOutputIndexKey, ValidAddressIndexPrefix};

/// Address indices are per-account now, and the scanner has to know which
/// account each one belongs to.
///
/// Rather than re-key what is there, this drops the scan cursor and every
/// derived index and lets the scanner rebuild both from zero. That is cheaper
/// to get right than a rewrite and it is safe: the federation reports whether
/// an output is already spent, so a replay from index zero re-derives the same
/// addresses and claims nothing twice.
///
/// The cost is one full re-walk of the federation's output stream and one
/// address-frontier search per account, both of which the scanner already does
/// on a fresh join.
///
/// The state machines need nothing: they read their account off their
/// operation rather than carrying it, so the ones in flight keep their shape.
pub(crate) async fn migrate_to_accounts_v1(
    dbtx: &mut DatabaseTransaction<'_>,
    _active_states: Vec<(Vec<u8>, OperationId)>,
    _inactive_states: Vec<(Vec<u8>, OperationId)>,
) -> Result<Option<(Vec<(Vec<u8>, OperationId)>, Vec<(Vec<u8>, OperationId)>)>, DbMigrationError> {
    dbtx.remove_by_prefix(&ValidAddressIndexPrefix).await;

    dbtx.remove_entry(&NextOutputIndexKey).await;

    Ok(None)
}
