use std::collections::HashMap;
use std::sync::Arc;

use fedimint_core::util::SafeUrl;
use ldk_node::NodeError;
use ldk_node::payment::PaymentDirection;
use lightning::ln::channelmanager::PaymentId;
use lockable::LockPool;
use tokio::sync::{RwLock, oneshot};

use super::{
    GatewayLdkClient, InboundRegistrationRefusal, LdkClientInitError, PendingPaymentWakeup,
    check_inbound_registration, get_esplora_url, htlc_completion_error,
};
use crate::LightningRpcError;

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
