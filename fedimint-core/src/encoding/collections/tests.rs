use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{Decodable, ModuleRegistry};
use crate::encoding::tests::test_roundtrip_expected;

#[test_log::test]
fn test_lists() {
    // The length of the list is encoded before the elements. It is encoded as a
    // variable length integer, but for lists with a length less than 253, it's
    // encoded as a single byte.
    test_roundtrip_expected(&vec![1u8, 2, 3], &[3u8, 1, 2, 3]);
    test_roundtrip_expected(&vec![1u16, 2, 3], &[3u8, 1, 2, 3]);
    test_roundtrip_expected(&vec![1u32, 2, 3], &[3u8, 1, 2, 3]);
    test_roundtrip_expected(&vec![1u64, 2, 3], &[3u8, 1, 2, 3]);

    // Empty list should be encoded as a single byte 0.
    test_roundtrip_expected::<Vec<u8>>(&vec![], &[0u8]);
    test_roundtrip_expected::<Vec<u16>>(&vec![], &[0u8]);
    test_roundtrip_expected::<Vec<u32>>(&vec![], &[0u8]);
    test_roundtrip_expected::<Vec<u64>>(&vec![], &[0u8]);

    // A length prefix greater than the number of elements should return an error.
    let buf = [4u8, 1, 2, 3];
    assert!(Vec::<u8>::consensus_decode_whole(&buf, &ModuleRegistry::default()).is_err());
    assert!(Vec::<u16>::consensus_decode_whole(&buf, &ModuleRegistry::default()).is_err());
    assert!(VecDeque::<u8>::consensus_decode_whole(&buf, &ModuleRegistry::default()).is_err());
    assert!(VecDeque::<u16>::consensus_decode_whole(&buf, &ModuleRegistry::default()).is_err());

    // A length prefix less than the number of elements should skip elements beyond
    // the encoded length.
    let buf = [2u8, 1, 2, 3];
    assert_eq!(
        Vec::<u8>::consensus_decode_partial(&mut &buf[..], &ModuleRegistry::default()).unwrap(),
        vec![1u8, 2]
    );
    assert_eq!(
        Vec::<u16>::consensus_decode_partial(&mut &buf[..], &ModuleRegistry::default()).unwrap(),
        vec![1u16, 2]
    );
    assert_eq!(
        VecDeque::<u8>::consensus_decode_partial(&mut &buf[..], &ModuleRegistry::default())
            .unwrap(),
        vec![1u8, 2]
    );
    assert_eq!(
        VecDeque::<u16>::consensus_decode_partial(&mut &buf[..], &ModuleRegistry::default())
            .unwrap(),
        vec![1u16, 2]
    );
}

#[test_log::test]
fn test_btreemap() {
    test_roundtrip_expected(
        &BTreeMap::from([("a".to_string(), 1u32), ("b".to_string(), 2)]),
        &[2, 1, 97, 1, 1, 98, 2],
    );
}

#[test_log::test]
fn test_btreeset() {
    test_roundtrip_expected(
        &BTreeSet::from(["a".to_string(), "b".to_string()]),
        &[2, 1, 97, 1, 98],
    );
}
