use std::collections::HashMap;
use std::sync::Arc;

use fedimint_core::util::SafeUrl;
use lightning::ln::channelmanager::PaymentId;
use tokio::sync::{RwLock, oneshot};

use super::{GatewayLdkClient, PendingPaymentCompletion, PendingPaymentWakeup, get_esplora_url};

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

#[tokio::test]
async fn wake_pending_payment_reports_waiter_state() {
    let pending_payments = Arc::new(RwLock::new(HashMap::new()));
    let payment_id = PaymentId([1; 32]);

    // No waiter registered yet.
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(
            &pending_payments,
            payment_id,
            Some("RouteNotFound".to_string()),
            true,
        )
        .await,
        PendingPaymentWakeup::NoWaiter
    );
    assert!(matches!(
        pending_payments.read().await.get(&payment_id),
        Some(PendingPaymentCompletion::Failed { failure_reason })
            if failure_reason == "RouteNotFound"
    ));
    pending_payments.write().await.remove(&payment_id);

    // No-waiter failures for non-Bolt11 payment ids are not cached, since only
    // the Bolt11 `pay()` path consumes this map.
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(
            &pending_payments,
            payment_id,
            Some("RouteNotFound".to_string()),
            false,
        )
        .await,
        PendingPaymentWakeup::NoWaiter
    );
    assert!(pending_payments.read().await.is_empty());

    // A registered waiter is woken and removed from the map.
    let (sender, receiver) = oneshot::channel();
    pending_payments
        .write()
        .await
        .insert(payment_id, PendingPaymentCompletion::Waiting(sender));
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(
            &pending_payments,
            payment_id,
            Some("RouteNotFound".to_string()),
            true,
        )
        .await,
        PendingPaymentWakeup::Woken
    );
    assert_eq!(receiver.await, Ok(Some("RouteNotFound".to_string())));
    assert!(pending_payments.read().await.is_empty());

    // A waiter whose receiver was dropped is reported as such and removed.
    let (sender, receiver) = oneshot::channel();
    drop(receiver);
    pending_payments
        .write()
        .await
        .insert(payment_id, PendingPaymentCompletion::Waiting(sender));
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id, None, false).await,
        PendingPaymentWakeup::ReceiverDropped
    );
    assert!(pending_payments.read().await.is_empty());
}
