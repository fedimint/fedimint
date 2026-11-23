use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fedimint_core::util::SafeUrl;
use fedimint_ln_common::contracts::Preimage;
use ldk_node::NodeError;
use ldk_node::payment::{PaymentDetails, PaymentDirection, PaymentKind, PaymentStatus};
use lightning::ln::channelmanager::PaymentId;
use lightning::offers::offer::OfferId;
use lightning::types::payment::PaymentPreimage;
use lockable::LockPool;
use tokio::sync::{RwLock, oneshot};

use super::{
    GatewayLdkClient, InboundRegistrationRefusal, LdkClientInitError, LdkOfferId, MnemonicSource,
    PendingPaymentWakeup, channel_push_amount_msats, check_inbound_registration, get_esplora_url,
    htlc_completion_error, offer_payment_result,
};
use crate::LightningRpcError;

#[test]
fn channel_push_amount_conversions_preserve_ldk_values() {
    assert_eq!(channel_push_amount_msats(0).unwrap(), None);
    assert_eq!(channel_push_amount_msats(1).unwrap(), Some(1000));
    let max_sats = u64::MAX / 1000;
    assert_eq!(
        channel_push_amount_msats(max_sats).unwrap(),
        Some(max_sats * 1000)
    );
}

#[test]
fn channel_push_amount_conversions_reject_ldk_overflow() {
    for sats in [u64::MAX / 1000 + 1, u64::MAX] {
        assert!(matches!(
            channel_push_amount_msats(sats),
            Err(LightningRpcError::FailedToOpenChannel { .. })
        ));
    }
}

/// The gateway retries `FailedToCompleteHtlc` forever and records only
/// `HtlcCompletionRejected`, so an `ldk-node` error that cannot change on
/// retry must map to the latter or the completion state machine never ends.
#[test]
fn completion_errors_are_permanent_unless_persistence_failed() {
    for err in [
        NodeError::InvalidPaymentHash,
        NodeError::InvalidPaymentPreimage,
        NodeError::InvalidAmount,
    ] {
        assert!(
            matches!(
                htlc_completion_error(&err, "ph"),
                LightningRpcError::HtlcCompletionRejected { .. }
            ),
            "{err} must be permanent"
        );
    }

    assert!(matches!(
        htlc_completion_error(&NodeError::PersistenceFailed, "ph"),
        LightningRpcError::FailedToCompleteHtlc { .. }
    ));
}

#[test]
fn verify_ldk_esplora_url() {
    let url = SafeUrl::parse("https://mempool.space/api/").expect("Cannot parse URL");
    let esplora_url = get_esplora_url(url).expect("Could not get esplora URL");
    // URLs without ports are allowed to have trailing slashes
    assert!(esplora_url.ends_with("/"));

    let url = SafeUrl::parse("https://mutinynet.com/api/").expect("Cannot parse URL");
    let esplora_url = get_esplora_url(url).expect("Could not get esplora URL");
    // URLs without ports are allowed to have trailing slashes
    assert!(esplora_url.ends_with("/"));

    let url = SafeUrl::parse("http://127.0.0.1:3003/").expect("Cannot parse URL");
    let esplora_url = get_esplora_url(url).expect("Could not get esplora URL");
    // URLs with ports are NOT allowed to have trailing slashes
    assert!(!esplora_url.ends_with("/"));
}

#[test]
fn an_esplora_url_without_a_host_is_rejected() {
    let url = SafeUrl::parse("unix:/run/esplora.sock").expect("Cannot parse URL");

    assert!(matches!(
        get_esplora_url(url),
        Err(LdkClientInitError::MissingEsploraHost)
    ));
}

/// The data directory is checked before LDK builds anything, so a path LDK
/// cannot use is refused without touching the disk or the network.
#[cfg(unix)]
#[test]
fn a_non_utf8_data_dir_is_rejected_before_the_node_is_built() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    use bitcoin::Network;
    use fedimint_bip39::Mnemonic;
    use fedimint_gateway_common::ChainSource;

    let runtime = Arc::new(tokio::runtime::Runtime::new().expect("A tokio runtime can be built"));
    let result = GatewayLdkClient::new(
        Path::new(OsStr::from_bytes(b"\xff")),
        ChainSource::Esplora {
            server_url: SafeUrl::parse("http://127.0.0.1:3002").expect("Cannot parse URL"),
        },
        Network::Regtest,
        0,
        String::new(),
        Mnemonic::from_entropy(&[0; 16]).expect("16 bytes of entropy form a mnemonic"),
        MnemonicSource::Generated,
        runtime,
    );

    assert!(matches!(result, Err(LdkClientInitError::InvalidDataDir)));
}

#[tokio::test]
async fn wake_pending_payment_reports_waiter_state() {
    let pending_payments = Arc::new(RwLock::new(HashMap::new()));
    let payment_id = PaymentId([1; 32]);

    // No waiter registered yet.
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::NoWaiter
    );

    // A registered waiter is woken and removed from the map.
    let (sender, receiver) = oneshot::channel();
    pending_payments.write().await.insert(payment_id, sender);
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::Woken
    );
    assert!(receiver.await.is_ok());
    assert!(pending_payments.read().await.is_empty());

    // A waiter whose receiver was dropped is reported as such and removed.
    let (sender, receiver) = oneshot::channel();
    drop(receiver);
    pending_payments.write().await.insert(payment_id, sender);
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::ReceiverDropped
    );
    assert!(pending_payments.read().await.is_empty());
}

/// A recheck interval long enough that only the terminal event can end a wait
/// within a test.
const ONLY_EVENTS: Duration = Duration::from_secs(3600);

/// The waiter is registered before the status is first read, so a terminal
/// event that fires right after that read still wakes it. A payment that is
/// already terminal at that read is returned without waiting.
#[tokio::test]
async fn wait_for_terminal_payment_registers_before_reading_the_status() {
    let pending_payments = Arc::new(RwLock::new(HashMap::new()));
    let payment_id = PaymentId([4; 32]);

    let result = GatewayLdkClient::wait_for_terminal_payment(
        &pending_payments,
        payment_id,
        ONLY_EVENTS,
        || {
            let registered = pending_payments
                .try_read()
                .is_ok_and(|waiters| waiters.contains_key(&payment_id));
            Some(registered)
        },
    )
    .await;

    assert_eq!(result, Some(true));
    assert!(pending_payments.read().await.is_empty());
}

/// A pending payment is waited for until the event handler wakes its waiter,
/// and the status is read again after the wakeup.
#[tokio::test]
async fn wait_for_terminal_payment_waits_for_the_terminal_event() {
    let pending_payments = Arc::new(RwLock::new(HashMap::new()));
    let payment_id = PaymentId([5; 32]);
    let status = Arc::new(Mutex::new(None));
    let checks = Arc::new(AtomicUsize::new(0));

    let waiter = fedimint_core::runtime::spawn("terminal payment waiter", {
        let pending_payments = pending_payments.clone();
        let status = status.clone();
        let checks = checks.clone();
        async move {
            GatewayLdkClient::wait_for_terminal_payment(
                &pending_payments,
                payment_id,
                ONLY_EVENTS,
                || {
                    checks.fetch_add(1, Ordering::SeqCst);
                    *status.lock().expect("status lock is not poisoned")
                },
            )
            .await
        }
    });

    // The first check runs after the waiter is registered and finds the
    // payment pending.
    tokio::time::timeout(Duration::from_secs(10), async {
        while checks.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the waiter checks the payment status");
    assert!(!waiter.is_finished());

    *status.lock().expect("status lock is not poisoned") = Some(7);
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::Woken
    );

    let result = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .expect("the woken waiter returns")
        .expect("the waiter task does not panic");
    assert_eq!(result, Some(7));
    assert_eq!(checks.load(Ordering::SeqCst), 2);
    assert!(pending_payments.read().await.is_empty());
}

/// A terminal status that the node has recorded ends the wait even when its
/// event is never delivered, for example while the event handler is held up
/// by an unrelated event.
#[tokio::test]
async fn wait_for_terminal_payment_rechecks_a_stored_result_without_an_event() {
    let pending_payments = Arc::new(RwLock::new(HashMap::new()));
    let payment_id = PaymentId([7; 32]);
    let status = Arc::new(Mutex::new(None));
    let checks = Arc::new(AtomicUsize::new(0));

    let waiter = fedimint_core::runtime::spawn("terminal payment waiter", {
        let pending_payments = pending_payments.clone();
        let status = status.clone();
        let checks = checks.clone();
        async move {
            GatewayLdkClient::wait_for_terminal_payment(
                &pending_payments,
                payment_id,
                Duration::from_millis(10),
                || {
                    checks.fetch_add(1, Ordering::SeqCst);
                    *status.lock().expect("status lock is not poisoned")
                },
            )
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        while checks.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the waiter checks the payment status");

    // Record the terminal status without delivering its event.
    *status.lock().expect("status lock is not poisoned") = Some(7);

    let result = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .expect("the waiter notices the stored result")
        .expect("the waiter task does not panic");
    assert_eq!(result, Some(7));
    assert!(pending_payments.read().await.is_empty());
}

/// A wakeup for a payment that is still not terminal is reported as `None`
/// rather than waiting forever.
#[tokio::test]
async fn wait_for_terminal_payment_reports_a_wakeup_without_a_terminal_status() {
    let pending_payments = Arc::new(RwLock::new(HashMap::new()));
    let payment_id = PaymentId([6; 32]);

    let waiter = fedimint_core::runtime::spawn("terminal payment waiter", {
        let pending_payments = pending_payments.clone();
        let never_terminal = || None::<u8>;
        async move {
            GatewayLdkClient::wait_for_terminal_payment(
                &pending_payments,
                payment_id,
                ONLY_EVENTS,
                never_terminal,
            )
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        while GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await
            != PendingPaymentWakeup::Woken
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the waiter registers and can be woken");

    let result = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .expect("the woken waiter returns")
        .expect("the waiter task does not panic");
    assert_eq!(result, None);
    assert!(pending_payments.read().await.is_empty());
}

/// Overlapping `pay_offer` calls for the same offer wait for each other on the
/// per-offer lock instead of blocking the runtime thread, where
/// `blocking_lock` would panic.
#[tokio::test]
async fn overlapping_payments_to_the_same_offer_wait_for_the_offer_lock() {
    let pool = Arc::new(LockPool::new());
    let offer_id = LdkOfferId(OfferId([8; 32]));

    let first_payment = pool.async_lock(offer_id).await;

    let second_payment = fedimint_core::runtime::spawn("second offer payment", {
        let pool = pool.clone();
        async move {
            let _offer_lock_guard = pool.async_lock(offer_id).await;
        }
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!second_payment.is_finished());

    drop(first_payment);
    tokio::time::timeout(Duration::from_secs(10), second_payment)
        .await
        .expect("the second payment gets the lock once the first one is done")
        .expect("the second payment task does not panic");
}

fn offer_payment(status: PaymentStatus, kind: PaymentKind) -> PaymentDetails {
    PaymentDetails {
        id: PaymentId([7; 32]),
        kind,
        amount_msat: Some(1_000),
        fee_paid_msat: None,
        direction: PaymentDirection::Outbound,
        status,
        latest_update_timestamp: 0,
    }
}

fn bolt12_offer_kind(preimage: Option<PaymentPreimage>) -> PaymentKind {
    PaymentKind::Bolt12Offer {
        hash: None,
        preimage,
        secret: None,
        offer_id: OfferId([8; 32]),
        payer_note: None,
        quantity: None,
    }
}

#[test]
fn offer_payment_result_waits_for_a_terminal_status() {
    assert!(
        offer_payment_result(&offer_payment(
            PaymentStatus::Pending,
            bolt12_offer_kind(None)
        ))
        .is_none()
    );

    let preimage = PaymentPreimage([9; 32]);
    assert!(matches!(
        offer_payment_result(&offer_payment(
            PaymentStatus::Succeeded,
            bolt12_offer_kind(Some(preimage))
        )),
        Some(Ok(Preimage(bytes))) if bytes == preimage.0
    ));

    // A success without a preimage cannot be reported as paid.
    assert!(matches!(
        offer_payment_result(&offer_payment(
            PaymentStatus::Succeeded,
            bolt12_offer_kind(None)
        )),
        Some(Err(LightningRpcError::FailedPayment { .. }))
    ));

    assert!(matches!(
        offer_payment_result(&offer_payment(
            PaymentStatus::Failed,
            bolt12_offer_kind(None)
        )),
        Some(Err(LightningRpcError::FailedPayment { .. }))
    ));
}

#[test]
fn inbound_registration_refuses_hashes_we_pay_outbound() {
    // A held `pay()` lock means a payment is in flight, whatever the store
    // says about the hash.
    for existing_direction in [
        None,
        Some(PaymentDirection::Inbound),
        Some(PaymentDirection::Outbound),
    ] {
        assert_eq!(
            check_inbound_registration(false, existing_direction),
            Err(InboundRegistrationRefusal::OutboundInFlight)
        );
    }

    // Any outbound record, pending or terminal, is refused so a restarted
    // `pay()` can still read the payment's result from it.
    assert_eq!(
        check_inbound_registration(true, Some(PaymentDirection::Outbound)),
        Err(InboundRegistrationRefusal::OutboundRecorded)
    );

    // A fresh hash is fine, as is a duplicate inbound registration, which the
    // gateway's own reservation screens before reaching the node.
    assert_eq!(check_inbound_registration(true, None), Ok(()));
    assert_eq!(
        check_inbound_registration(true, Some(PaymentDirection::Inbound)),
        Ok(())
    );
}

#[tokio::test]
async fn registration_try_lock_is_refused_while_pay_holds_the_hash_lock() {
    // `pay()` takes the per-hash lock with `async_lock` and holds it until the
    // payment is terminal; `create_invoice` must see that as busy.
    let pool = LockPool::new();
    let payment_id = PaymentId([2; 32]);
    let other_payment_id = PaymentId([3; 32]);

    let pay_guard = pool.async_lock(payment_id).await;
    assert!(pool.try_lock(payment_id).is_none());
    // Other hashes are unaffected.
    assert!(pool.try_lock(other_payment_id).is_some());

    drop(pay_guard);
    assert!(pool.try_lock(payment_id).is_some());
}
