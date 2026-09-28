use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};

use super::{MissingInvoiceAmountError, PrunedInvoice};

/// An invoice without an amount cannot be pruned, and says that rather
/// than returning a message.
#[test]
fn pruning_an_amountless_invoice_reports_the_missing_amount() {
    let ctx = Secp256k1::new();
    let sk = SecretKey::from_slice(&[1; 32]).expect("Valid secret key");
    let invoice: Bolt11Invoice = InvoiceBuilder::new(Currency::Regtest)
        .description(String::new())
        .payment_hash(sha256::Hash::hash(&[0; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(0)
        .payment_secret(PaymentSecret([0; 32]))
        .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &sk))
        .expect("Failed to build invoice");

    assert_eq!(
        PrunedInvoice::try_from(invoice),
        Err(MissingInvoiceAmountError)
    );
}
