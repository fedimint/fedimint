use std::collections::VecDeque;

use crate::encoding::tests::test_roundtrip_expected;
use crate::{Decodable, DecodeError, Encodable, ModuleDecoderRegistry};

// A zero-sized Rust type need not have a zero-byte encoding. The collection
// policy deliberately rejects even these types before calling their decoder.
#[derive(Debug, PartialEq, Eq)]
struct ByteEncodedZst;

impl Encodable for ByteEncodedZst {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        42u8.consensus_encode(writer)
    }
}

impl Decodable for ByteEncodedZst {
    fn consensus_decode_partial<D: std::io::Read>(
        _d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        panic!("zero-sized element decoder must not be invoked");
    }
}

#[test]
fn empty_zero_sized_collections_roundtrip() {
    test_roundtrip_expected(&Vec::<()>::new(), &[0]);
    test_roundtrip_expected(&VecDeque::<()>::new(), &[0]);
    test_roundtrip_expected(&Vec::<ByteEncodedZst>::new(), &[0]);
    test_roundtrip_expected(&VecDeque::<ByteEncodedZst>::new(), &[0]);
}

#[test]
fn nonempty_zero_sized_collections_are_rejected() {
    assert_eq!(std::mem::size_of::<ByteEncodedZst>(), 0);
    for len in [1, 3, u64::MAX] {
        let bytes = len.consensus_encode_to_vec();
        let modules = ModuleDecoderRegistry::default();
        assert!(Vec::<()>::consensus_decode_whole(&bytes, &modules).is_err());
        assert!(VecDeque::<()>::consensus_decode_whole(&bytes, &modules).is_err());
        assert!(Vec::<ByteEncodedZst>::consensus_decode_whole(&bytes, &modules).is_err());
        assert!(VecDeque::<ByteEncodedZst>::consensus_decode_whole(&bytes, &modules).is_err());
    }

    // Encoding remains unchanged, including for unsupported nonempty values.
    assert_eq!(vec![(); 3].consensus_encode_to_vec(), [3]);
    assert_eq!(VecDeque::from([(); 3]).consensus_encode_to_vec(), [3]);
    let bytes = vec![ByteEncodedZst].consensus_encode_to_vec();
    assert_eq!(bytes, [1, 42]);
    let modules = ModuleDecoderRegistry::default();
    assert!(Vec::<ByteEncodedZst>::consensus_decode_whole(&bytes, &modules).is_err());
    assert!(VecDeque::<ByteEncodedZst>::consensus_decode_whole(&bytes, &modules).is_err());
}

#[test]
fn non_zero_sized_collections_still_roundtrip_above_preallocation_cap() {
    let values = vec![42u16; 8_001];
    let bytes = values.consensus_encode_to_vec();
    test_roundtrip_expected(&values, &bytes);
    test_roundtrip_expected(&VecDeque::from(values), &bytes);
}
