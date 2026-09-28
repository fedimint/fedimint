use std::str::FromStr as _;

use super::{PaymentCodeId, PaymentCodeRootKey};

/// A payment code id that is not hex says so through the hex parser's own
/// error, which is what clap and any other `FromStr` consumer prints.
#[test]
fn payment_code_id_rejects_non_hex() {
    // The type annotation on `_err` is the assertion: the compiler only
    // accepts it if `from_str` actually failed with the hex parser's own
    // error.
    let _err: bitcoin::hashes::hex::HexToArrayError =
        PaymentCodeId::from_str("not hex").expect_err("not hex");
}

/// A payment code root key that is not a public key says so through
/// secp256k1's own error.
#[test]
fn payment_code_root_key_rejects_non_key() {
    // The type annotation on `_err` is the assertion: the compiler only
    // accepts it if `from_str` actually failed with secp256k1's own
    // error.
    let _err: fedimint_core::secp256k1::Error =
        PaymentCodeRootKey::from_str("not a key").expect_err("not a key");
}
