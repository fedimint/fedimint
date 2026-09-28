use hex::FromHexError;
use serde_json::json;

use super::MetaValue;

#[test]
fn a_value_that_is_not_hex_is_rejected() {
    assert!(matches!(
        "zz".parse::<MetaValue>(),
        Err(FromHexError::InvalidHexCharacter { c: 'z', index: 0 })
    ));
    assert!(matches!(
        "0".parse::<MetaValue>(),
        Err(FromHexError::OddLength)
    ));
}

#[test]
fn a_value_round_trips_through_its_hex_form() {
    let value = MetaValue::from([0x01, 0x02, 0xff].as_slice());

    assert_eq!(
        value
            .to_string()
            .parse::<MetaValue>()
            .expect("The rendered form parses back"),
        value
    );
}

#[test]
fn a_json_value_is_read_both_strictly_and_lossily() {
    let value = MetaValue::from(br#"{"welcome":"hello"}"#.as_slice());

    assert_eq!(
        value.to_json().expect("The bytes are valid json"),
        json!({ "welcome": "hello" })
    );
    assert_eq!(
        value.to_json_lossy().expect("The bytes are valid json"),
        json!({ "welcome": "hello" })
    );
}

#[test]
fn bytes_that_are_not_json_are_rejected_either_way() {
    let value = MetaValue::from(b"not json".as_slice());

    assert!(value.to_json().is_err());
    assert!(value.to_json_lossy().is_err());
}

#[test]
fn the_lossy_read_replaces_invalid_utf8() {
    // A json string whose only content is one invalid utf-8 byte. The
    // strict read rejects the byte; the lossy read turns it into the
    // replacement character, which leaves a valid json string behind.
    let value = MetaValue::from(b"\"\xff\"".as_slice());

    assert!(value.to_json().is_err());
    assert_eq!(
        value
            .to_json_lossy()
            .expect("The lossy form is a valid json string"),
        json!("\u{fffd}")
    );
}
