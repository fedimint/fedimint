use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use bitcoin::Amount;
use fedimint_client::RootSecret;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::runtime;
use fedimint_walletv2_client::events::ReceivePaymentStatus;
use fedimint_walletv2_client::{
    MAX_UNPAID_RESERVATIONS, ReservationState, ReserveAddressError, WalletClientModule,
};
use futures::StreamExt;

use crate::{
    WalletEvent, await_finality_delay, fixtures, initialize_consensus, wallet_event_stream,
};

/// The seed of the wallets these tests restart or restore.
const SEED: [u8; 64] = [0x42; 64];

fn root_secret() -> RootSecret {
    RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(&SEED))
}

/// Every reservation is handed an address of its own, only so many of them
/// may wait for a payment at once, and a payment moves the reservation it was
/// made to and no other.
#[tokio::test(flavor = "multi_thread")]
async fn a_payment_moves_only_the_reservation_it_was_made_to() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    let wallet = client.get_first_module::<WalletClientModule>()?;

    // One after the other, so that `unpaid` holds the lower address of the
    // two: the limit below counts the addresses reserved ahead of the last
    // one paid.
    let unpaid = wallet.reserve_address().await?;
    let paid = wallet.reserve_address().await?;

    assert_ne!(unpaid.address, paid.address);
    assert_ne!(unpaid.operation_id, paid.operation_id);

    // A reserved address is not handed out to anyone else.
    let unreserved = wallet.receive().await;

    assert_ne!(unreserved, unpaid.address);
    assert_ne!(unreserved, paid.address);

    for _ in 2..MAX_UNPAID_RESERVATIONS {
        wallet.reserve_address().await?;
    }

    assert_matches!(
        wallet.reserve_address().await,
        Err(ReserveAddressError::TooManyUnpaid)
    );

    let mut unpaid_updates = wallet
        .subscribe_reservation(unpaid.operation_id)
        .await?
        .into_stream();

    let mut paid_updates = wallet
        .subscribe_reservation(paid.operation_id)
        .await?
        .into_stream();

    assert_eq!(unpaid_updates.next().await, Some(ReservationState::Pending));
    assert_eq!(paid_updates.next().await, Some(ReservationState::Pending));

    let mut events = pin!(wallet_event_stream(&client));

    bitcoin
        .send_and_mine_block(&paid.address, Amount::from_int_btc(1))
        .await;

    await_finality_delay(&client, &bitcoin).await?;

    let Some(ReservationState::Claiming(claim)) = paid_updates.next().await else {
        panic!("Expected the payment to be claimed");
    };

    assert_eq!(
        paid_updates.next().await,
        Some(ReservationState::Claimed(claim))
    );
    assert_eq!(paid_updates.next().await, None);

    // The receive operation that claimed the payment names the reservation.
    let Some(WalletEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };

    assert_eq!(receive.operation_id, claim);
    assert_eq!(receive.reservation, Some(paid.operation_id));
    assert_eq!(receive.address, *paid.address.as_unchecked());

    assert!(
        runtime::timeout(Duration::from_secs(1), unpaid_updates.next())
            .await
            .is_err(),
        "The reservation that was not paid must not move"
    );

    // A reservation that has ended ends the same way for whoever asks later.
    assert_eq!(
        wallet
            .subscribe_reservation(paid.operation_id)
            .await?
            .into_stream()
            .collect::<Vec<_>>()
            .await
            .last(),
        Some(&ReservationState::Claimed(claim))
    );

    Ok(())
}

/// A reservation made before a restart is still followed after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_reservation_is_followed_across_a_restart() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let db: Database = MemDatabase::new().into();
    let client = fed.join_client_with_db(db.clone(), root_secret()).await;
    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    let reservation = client
        .get_first_module::<WalletClientModule>()?
        .reserve_address()
        .await?;

    Arc::into_inner(client)
        .expect("Nothing else holds the client")
        .shutdown()
        .await;

    let client = fed.open_client_with_db(db, root_secret()).await;
    let wallet = client.get_first_module::<WalletClientModule>()?;

    let mut updates = wallet
        .subscribe_reservation(reservation.operation_id)
        .await?
        .into_stream();

    assert_eq!(updates.next().await, Some(ReservationState::Pending));

    bitcoin
        .send_and_mine_block(&reservation.address, Amount::from_int_btc(1))
        .await;

    await_finality_delay(&client, &bitcoin).await?;

    let Some(ReservationState::Claiming(claim)) = updates.next().await else {
        panic!("Expected the payment to be claimed");
    };

    assert_eq!(updates.next().await, Some(ReservationState::Claimed(claim)));

    Ok(())
}

/// A wallet recovered from its seed knows nothing of its reservations, and
/// would stop looking for payments at the first reserved address that was
/// never paid. Its recovery derives every address a reservation could have
/// been made for, so a payment to one reserved after an unpaid one is found.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovered_wallet_finds_a_payment_to_a_reservation_made_after_an_unpaid_one()
-> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let bitcoin = fixtures.bitcoin();

    let original = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret())
        .await;

    // Recovered into a database of its own while the original wallet is
    // still at work: both derive the same addresses, each a search that takes
    // a while, and side by side that takes half as long.
    let recovered = fed
        .recover_client_with_db(MemDatabase::new().into(), root_secret())
        .await;

    initialize_consensus(&original, &bitcoin).await?;

    let (_unpaid, paid) = {
        let wallet = original.get_first_module::<WalletClientModule>()?;

        (
            wallet.reserve_address().await?,
            wallet.reserve_address().await?,
        )
    };

    // The original wallet is gone before the payment is made, so it is the
    // recovered one that has to claim it.
    Arc::into_inner(original)
        .expect("Nothing else holds the client")
        .shutdown()
        .await;

    recovered.wait_for_all_recoveries().await?;

    let mut events = pin!(wallet_event_stream(&recovered));

    bitcoin
        .send_and_mine_block(&paid.address, Amount::from_int_btc(1))
        .await;

    await_finality_delay(&recovered, &bitcoin).await?;

    let Some(WalletEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };

    assert_eq!(receive.address, *paid.address.as_unchecked());
    assert_eq!(receive.reservation, None);

    let Some(WalletEvent::ReceiveStatus(status)) = events.next().await else {
        panic!("Expected ReceiveStatus event");
    };

    assert_eq!(status.operation_id, receive.operation_id);
    assert_eq!(status.status, ReceivePaymentStatus::Success);

    Ok(())
}
