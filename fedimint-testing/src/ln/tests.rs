use bitcoin::hashes::{Hash, sha256};
use fedimint_core::Amount;
use fedimint_lightning::ILnRpcClient;

use super::FakeLightningTest;

/// The fake's outbound record backs `outbound_payment_exists`, which the
/// gateway state machines use to distinguish a payment dispatched before
/// a restart from one that never left the gateway. A record that answered
/// wrongly would make the resume-past-expiry tests pass or fail for the
/// wrong reason.
#[tokio::test]
async fn outbound_record_tracks_dispatched_payments() {
    let ln = FakeLightningTest::new();
    let invoice = ln
        .invoice(Amount::from_sats(1000), None)
        .expect("can create invoice");
    let payment_hash = *invoice.payment_hash();

    assert!(
        !ln.outbound_payment_exists(payment_hash)
            .await
            .expect("fake lookup cannot fail"),
        "no payment has been dispatched yet"
    );

    ln.pay(invoice, 0, Amount::ZERO)
        .await
        .expect("fake payment succeeds");

    assert!(
        ln.outbound_payment_exists(payment_hash)
            .await
            .expect("fake lookup cannot fail"),
        "the dispatched payment must be on record"
    );
    assert!(
        !ln.outbound_payment_exists(sha256::Hash::hash(b"never dispatched"))
            .await
            .expect("fake lookup cannot fail"),
        "an unrelated hash must not be reported as dispatched"
    );
}
