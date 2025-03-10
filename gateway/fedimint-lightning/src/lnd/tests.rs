use fedimint_core::encode_bolt11_invoice_features_without_length;
use hex::FromHex;
use lightning::ln::features::Bolt11InvoiceFeatures;

use super::wire_features_to_lnd_feature_vec;

#[test]
fn features_to_lnd() {
    assert_eq!(
        wire_features_to_lnd_feature_vec(&[]).unwrap(),
        Vec::<i32>::new()
    );

    let features_payment_secret = {
        let mut f = Bolt11InvoiceFeatures::empty();
        f.set_payment_secret_optional();
        encode_bolt11_invoice_features_without_length(&f)
    };
    assert_eq!(
        wire_features_to_lnd_feature_vec(&features_payment_secret).unwrap(),
        vec![15]
    );

    // Phoenix feature flags
    let features_payment_secret = Vec::from_hex("20000000000000000000000002000000024100").unwrap();
    assert_eq!(
        wire_features_to_lnd_feature_vec(&features_payment_secret).unwrap(),
        vec![8, 14, 17, 49, 149]
    );
}
