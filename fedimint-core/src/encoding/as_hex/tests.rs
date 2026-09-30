use fedimint_derive::{Decodable, Encodable};

use crate::encoding::Decodable as _;
use crate::module::registry::ModuleRegistry;
use crate::util::FmtCompact as _;

#[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
struct TestStruct {
    vec: Vec<u8>,
    num: u32,
}

#[derive(Debug, serde::Deserialize)]
struct Wrapper {
    #[serde(with = "crate::encoding::as_hex", rename = "inner")]
    _inner: TestStruct,
}

#[test_log::test]
fn deserialize_reports_the_whole_decode_chain() {
    // `vec` decodes as one element (7); `num` then has no bytes left, so this
    // fails deep inside the derived decoder, not at the hex-parsing layer.
    let err =
        serde_json::from_str::<Wrapper>(r#"{"inner":"0107"}"#).expect_err("payload is truncated");

    let expected = TestStruct::consensus_decode_hex("0107", &ModuleRegistry::default())
        .expect_err("payload is truncated");

    assert!(
        err.to_string().starts_with(&format!(
            "decodable deserialization failed: {}",
            expected.fmt_compact()
        )),
        "{err}"
    );
    assert_ne!(
        expected.fmt_compact().to_string(),
        expected.to_string(),
        "the decode error has more than one layer and the message shows all of them"
    );
}
