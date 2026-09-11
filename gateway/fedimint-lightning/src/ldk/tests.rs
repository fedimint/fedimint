use std::collections::HashMap;
use std::sync::Arc;

use fedimint_core::util::SafeUrl;
use ldk_node::NodeError;
use ldk_node::payment::PaymentDirection;
use lightning::ln::channelmanager::PaymentId;
use lockable::LockPool;
use tokio::sync::{RwLock, oneshot};

use super::{
    GatewayLdkClient, InboundRegistrationRefusal, PendingPaymentWakeup, check_inbound_registration,
    get_esplora_url, htlc_completion_error, htlc_in_flight_msats,
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

/// `total_lightning_balance_sats` counts zero for an outbound payment's
/// `MaybeTimeoutClaimableHTLC`, so the in-flight bucket has to carry its full
/// value or the sats vanish from the partition entirely.
#[test]
fn in_flight_bucket_carries_outbound_payment_htlcs_in_full() {
    use ldk_node::LightningBalance;
    use lightning::ln::types::ChannelId;
    use lightning::types::payment::PaymentHash;

    let counterparty_node_id = bitcoin::secp256k1::PublicKey::from_secret_key(
        bitcoin::secp256k1::SECP256K1,
        &bitcoin::secp256k1::SecretKey::from_slice(&[7; 32])
            .expect("32 repeated non-zero bytes are a valid secret key"),
    );
    let timeout_claimable =
        |amount_satoshis, outbound_payment| LightningBalance::MaybeTimeoutClaimableHTLC {
            channel_id: ChannelId([1; 32]),
            counterparty_node_id,
            amount_satoshis,
            claimable_height: 100,
            payment_hash: PaymentHash([2; 32]),
            outbound_payment,
        };

    // Ours, in flight: the whole amount, in msat.
    assert_eq!(
        htlc_in_flight_msats(&[timeout_claimable(1_500, true)]),
        1_500_000
    );

    // Forwarded for someone else: `claimable_amount_satoshis()` returns its
    // amount, so the channel-local bucket already holds it.
    assert_eq!(htlc_in_flight_msats(&[timeout_claimable(1_500, false)]), 0);

    // Inbound, preimage unknown: not the gateway's money.
    assert_eq!(
        htlc_in_flight_msats(&[LightningBalance::MaybePreimageClaimableHTLC {
            channel_id: ChannelId([1; 32]),
            counterparty_node_id,
            amount_satoshis: 2_000,
            expiry_height: 100,
            payment_hash: PaymentHash([3; 32]),
        }]),
        0
    );

    // Dust and sub-satoshi remainders still come from the rounded fields.
    let on_close = LightningBalance::ClaimableOnChannelClose {
        channel_id: ChannelId([1; 32]),
        counterparty_node_id,
        amount_satoshis: 50_000,
        transaction_fee_satoshis: 200,
        outbound_payment_htlc_rounded_msat: 700,
        outbound_forwarded_htlc_rounded_msat: 300,
        inbound_claiming_htlc_rounded_msat: 11,
        inbound_htlc_rounded_msat: 22,
    };
    assert_eq!(htlc_in_flight_msats(std::slice::from_ref(&on_close)), 1_000);

    // A whole channel at once: two of our HTLCs in flight, one forwarded, plus
    // the remainders.
    assert_eq!(
        htlc_in_flight_msats(&[
            on_close,
            timeout_claimable(1_500, true),
            timeout_claimable(2_500, true),
            timeout_claimable(9_000, false),
        ]),
        1_000 + 1_500_000 + 2_500_000
    );

    assert_eq!(htlc_in_flight_msats(&[]), 0);
}
