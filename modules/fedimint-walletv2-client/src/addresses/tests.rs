use assert_matches::assert_matches;
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, DatabaseError, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::registry::ModuleDecoderRegistry;

use super::{AddressWindow, reserve, retire, unused};
use crate::db::{RecoveryScanKey, ValidAddressIndexKey};
use crate::{MAX_UNPAID_RESERVATIONS, ReserveAddressError};

/// A wallet whose scanner has derived the addresses at `indices`.
async fn wallet_with_addresses(indices: &[u64]) -> Database {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

    let mut dbtx = db.begin_transaction().await;

    for index in indices {
        dbtx.insert_new_entry(&ValidAddressIndexKey(*index), &())
            .await;
    }

    dbtx.commit_tx().await;

    db
}

/// Reserves an address in a transaction of its own.
async fn reserve_committed(db: &Database) -> Result<Option<u64>, ReserveAddressError> {
    let mut dbtx = db.begin_transaction().await;

    let reserved = reserve(&mut dbtx, OperationId::new_random()).await?;

    dbtx.commit_tx().await;

    Ok(reserved)
}

/// Records a payment to an address in a transaction of its own.
async fn retire_committed(db: &Database, address_index: u64) {
    let mut dbtx = db.begin_transaction().await;

    retire(&mut dbtx, address_index).await;

    dbtx.commit_tx().await;
}

#[tokio::test]
async fn addresses_are_handed_out_lowest_first_and_only_once() {
    let db = wallet_with_addresses(&[7, 30, 500]).await;

    assert_eq!(unused(&mut db.begin_transaction_nc().await).await, Some(7));

    assert_eq!(reserve_committed(&db).await.expect("an address"), Some(7));
    assert_eq!(reserve_committed(&db).await.expect("an address"), Some(30));

    // A reserved address is not the unused one any more.
    assert_eq!(
        unused(&mut db.begin_transaction_nc().await).await,
        Some(500)
    );

    assert_eq!(reserve_committed(&db).await.expect("an address"), Some(500));

    // The scanner has not derived the next address yet.
    assert_eq!(unused(&mut db.begin_transaction_nc().await).await, None);
}

#[tokio::test]
async fn a_paid_address_and_those_below_it_are_not_handed_out_again() {
    let db = wallet_with_addresses(&[7, 30, 500]).await;

    retire_committed(&db, 30).await;

    assert_eq!(reserve_committed(&db).await.expect("an address"), Some(500));

    // A payment to an address below the last one paid changes nothing.
    assert!(!retire(&mut db.begin_transaction().await, 7).await);
}

#[tokio::test]
async fn only_addresses_reserved_ahead_of_the_last_paid_one_count_towards_the_limit() {
    let indices: Vec<u64> = (0..=2 * MAX_UNPAID_RESERVATIONS as u64).collect();
    let db = wallet_with_addresses(&indices).await;

    for index in 0..MAX_UNPAID_RESERVATIONS as u64 {
        assert_eq!(
            reserve_committed(&db).await.expect("an address"),
            Some(index)
        );
    }

    assert_matches!(
        reserve_committed(&db).await,
        Err(ReserveAddressError::TooManyUnpaid)
    );

    // The second reserved address is paid. It and the one before it leave
    // the addresses still handed out, which leaves the third as the only
    // reservation ahead of the last address paid.
    retire_committed(&db, 1).await;

    let window = AddressWindow::load(&mut db.begin_transaction_nc().await).await;

    assert_eq!(window.reserved, 1);

    for index in MAX_UNPAID_RESERVATIONS as u64..2 * MAX_UNPAID_RESERVATIONS as u64 - 1 {
        assert_eq!(
            reserve_committed(&db).await.expect("an address"),
            Some(index)
        );
    }

    assert_matches!(
        reserve_committed(&db).await,
        Err(ReserveAddressError::TooManyUnpaid)
    );
}

/// A reservation made while a payment to the same address is being recorded
/// does not commit: it would otherwise follow a payment made before it.
#[tokio::test]
async fn a_reservation_conflicts_with_a_payment_found_for_its_address_meanwhile() {
    let db = wallet_with_addresses(&[7, 30]).await;

    let mut reservation = db.begin_transaction().await;

    assert_eq!(
        reserve(&mut reservation, OperationId::new_random())
            .await
            .expect("an address"),
        Some(7)
    );

    retire_committed(&db, 7).await;

    assert_matches!(
        reservation.commit_tx_result().await,
        Err(DatabaseError::WriteConflict)
    );

    // Tried again, the reservation is handed the next address.
    assert_eq!(reserve_committed(&db).await.expect("an address"), Some(30));
}

/// The other order: a payment recorded while its address is being reserved
/// does not commit either, and is recorded when the scanner tries again.
#[tokio::test]
async fn a_payment_found_conflicts_with_its_address_being_reserved_meanwhile() {
    let db = wallet_with_addresses(&[7, 30]).await;

    let mut payment = db.begin_transaction().await;

    assert!(retire(&mut payment, 7).await);

    assert_eq!(reserve_committed(&db).await.expect("an address"), Some(7));

    assert_matches!(
        payment.commit_tx_result().await,
        Err(DatabaseError::WriteConflict)
    );
}

#[tokio::test]
async fn two_reservations_cannot_both_take_one_address() {
    let db = wallet_with_addresses(&[7, 30]).await;

    let mut first = db.begin_transaction().await;
    let mut second = db.begin_transaction().await;

    assert_eq!(
        reserve(&mut first, OperationId::new_random())
            .await
            .expect("an address"),
        Some(7)
    );
    assert_eq!(
        reserve(&mut second, OperationId::new_random())
            .await
            .expect("an address"),
        Some(7)
    );

    first.commit_tx_result().await.expect("the first commits");

    assert_matches!(
        second.commit_tx_result().await,
        Err(DatabaseError::WriteConflict)
    );

    assert_eq!(reserve_committed(&db).await.expect("an address"), Some(30));
}

/// Until a recovery has gone through the federation's outputs it is not
/// known which addresses were paid, so none is handed out.
#[tokio::test]
async fn no_address_is_handed_out_while_a_recovery_scans() {
    let db = wallet_with_addresses(&[7, 30]).await;

    let mut dbtx = db.begin_transaction().await;

    dbtx.insert_entry(&RecoveryScanKey, &()).await;

    dbtx.commit_tx().await;

    assert_eq!(unused(&mut db.begin_transaction_nc().await).await, None);
    assert_eq!(reserve_committed(&db).await.expect("no refusal"), None);

    let mut dbtx = db.begin_transaction().await;

    dbtx.remove_entry(&RecoveryScanKey).await;

    dbtx.commit_tx().await;

    assert_eq!(reserve_committed(&db).await.expect("an address"), Some(7));
}
