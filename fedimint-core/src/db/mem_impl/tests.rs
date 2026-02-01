use super::MemDatabase;
use crate::core::ModuleInstanceId;
use crate::db::{Database, IRawDatabaseExt};

fn database() -> Database {
    MemDatabase::new().into()
}

fn module_database(module_instance_id: ModuleInstanceId) -> Database {
    let db = MemDatabase::new().into_database();
    db.with_prefix_module_id(module_instance_id).0
}

#[test_log::test(tokio::test)]
async fn test_dbtx_insert_elements() {
    fedimint_core::db::verify_insert_elements(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_remove_nonexisting() {
    fedimint_core::db::verify_remove_nonexisting(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_remove_existing() {
    fedimint_core::db::verify_remove_nonexisting(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_read_own_writes() {
    fedimint_core::db::verify_read_own_writes(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_prevent_dirty_reads() {
    fedimint_core::db::verify_prevent_dirty_reads(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_find_by_range() {
    fedimint_core::db::verify_find_by_range(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_find_by_prefix() {
    fedimint_core::db::verify_find_by_prefix(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_commit() {
    fedimint_core::db::verify_commit(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_prevent_nonrepeatable_reads() {
    fedimint_core::db::verify_prevent_nonrepeatable_reads(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_phantom_entry() {
    fedimint_core::db::verify_phantom_entry(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_dbtx_remove_by_prefix() {
    fedimint_core::db::verify_remove_by_prefix(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_expect_write_conflict() {
    fedimint_core::db::expect_write_conflict(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_module_dbtx() {
    fedimint_core::db::verify_module_prefix(database()).await;
}

#[test_log::test(tokio::test)]
async fn test_module_db() {
    fedimint_core::db::verify_module_db(database(), module_database(1)).await;
}
