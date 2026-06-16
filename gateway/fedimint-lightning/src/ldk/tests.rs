use std::collections::HashMap;
use std::sync::Arc;

use fedimint_core::util::SafeUrl;
use lightning::ln::channelmanager::PaymentId;
use tokio::sync::{RwLock, oneshot};

use super::{GatewayLdkClient, PendingPaymentWakeup, get_esplora_url};

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

    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::NoWaiter
    );

    let (sender, receiver) = oneshot::channel();
    pending_payments.write().await.insert(payment_id, sender);
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::Woken
    );
    assert!(receiver.await.is_ok());
    assert!(pending_payments.read().await.is_empty());

    let (sender, receiver) = oneshot::channel();
    drop(receiver);
    pending_payments.write().await.insert(payment_id, sender);
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::ReceiverDropped
    );
    assert!(pending_payments.read().await.is_empty());
}
