use bitcoin::hashes::{Hash, sha256};
use fedimint_core::secp256k1::{Secp256k1, SecretKey};
use lightning_invoice::{CreationError, Currency, InvoiceBuilder, PaymentSecret};

use super::{Bolt11Invoice, Duration, has_invoice_expired};

#[test]
fn test_invoice_expiration() -> Result<(), CreationError> {
    let now = fedimint_core::time::duration_since_epoch();
    let one_second = Duration::from_secs(1);
    for expiration in [one_second, Duration::from_hours(1)] {
        for tolerance in [one_second, Duration::from_mins(1)] {
            let invoice = invoice(now, expiration)?;
            assert!(!has_invoice_expired(
                &invoice,
                now.checked_sub(one_second).unwrap(),
                tolerance
            ));
            assert!(!has_invoice_expired(&invoice, now, tolerance));
            assert!(!has_invoice_expired(&invoice, now + expiration, tolerance));
            assert!(!has_invoice_expired(
                &invoice,
                (now + expiration + tolerance)
                    .checked_sub(one_second)
                    .unwrap(),
                tolerance
            ));
            assert!(has_invoice_expired(
                &invoice,
                now + expiration + tolerance,
                tolerance
            ));
            assert!(has_invoice_expired(
                &invoice,
                now + expiration + tolerance + one_second,
                tolerance
            ));
        }
    }
    Ok(())
}

fn invoice(now_epoch: Duration, expiry_time: Duration) -> Result<Bolt11Invoice, CreationError> {
    let ctx = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    InvoiceBuilder::new(Currency::Regtest)
        .description(String::new())
        .payment_hash(sha256::Hash::hash(&[0; 32]))
        .duration_since_epoch(now_epoch)
        .min_final_cltv_expiry_delta(0)
        .payment_secret(PaymentSecret([0; 32]))
        .amount_milli_satoshis(1000)
        .expiry_time(expiry_time)
        .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &secret_key))
}
