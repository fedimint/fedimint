use super::{ChildId, Decodable, DerivableSecret, Encodable};

#[test]
fn consensus_roundtrip_preserves_derivation() {
    let original = DerivableSecret::new_root(b"root key", b"salt")
        .child_key(ChildId(1))
        .child_key(ChildId(2));

    let encoded = original.consensus_encode_to_vec();
    let decoded = DerivableSecret::consensus_decode_whole(&encoded, &Default::default())
        .expect("decode should succeed");

    assert_eq!(original.level(), decoded.level());
    assert_eq!(
        original.to_random_bytes::<32>(),
        decoded.to_random_bytes::<32>()
    );
    assert_eq!(
        original.child_key(ChildId(3)).to_random_bytes::<32>(),
        decoded.child_key(ChildId(3)).to_random_bytes::<32>()
    );
}
