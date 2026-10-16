use std::time::Duration;

use super::{
    Decodable, Encodable, GuardianMetadata, MAX_FUTURE_TIMESTAMP_SECS, SignedGuardianMetadata,
    VerificationError,
};
use crate::module::registry::ModuleRegistry;

#[test]
fn signed_guardian_metadata_json_roundtrip() {
    let ctx = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::new(&ctx, &mut secp256k1::rand::thread_rng());
    let public_key = secp256k1::PublicKey::from_keypair(&keypair);

    let timestamp_secs = 1000;
    let metadata = GuardianMetadata::new(
        vec!["wss://example.com/api".parse().unwrap()],
        "test_pkarr_id".to_string(),
        timestamp_secs,
    );

    let signed = metadata.sign(&ctx, &keypair);

    // Serialize to JSON
    let json = serde_json::to_string(&signed).expect("serialization should succeed");

    // Verify JSON structure
    let json_value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        json_value.get("content").is_some(),
        "should have content field"
    );
    assert!(
        json_value.get("signature").is_some(),
        "should have signature field"
    );

    // Deserialize from JSON
    let deserialized: SignedGuardianMetadata =
        serde_json::from_str(&json).expect("deserialization should succeed");

    // Compare original and deserialized
    assert_eq!(signed.bytes, deserialized.bytes);
    assert_eq!(signed.value, deserialized.value);
    assert_eq!(signed.signature, deserialized.signature);
    assert_eq!(signed, deserialized);

    // Verify signature still works after roundtrip
    let now = Duration::from_secs(timestamp_secs);
    deserialized
        .verify(&ctx, &public_key, now)
        .expect("signature should verify after roundtrip");

    // Verify extracted metadata matches original
    assert_eq!(*deserialized.guardian_metadata(), metadata);
}

#[test]
fn signed_guardian_metadata_encodable_roundtrip() {
    let ctx = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::new(&ctx, &mut secp256k1::rand::thread_rng());
    let public_key = secp256k1::PublicKey::from_keypair(&keypair);

    let timestamp_secs = 1000;
    let metadata = GuardianMetadata::new(
        vec!["wss://example.com/api".parse().unwrap()],
        "test_pkarr_id".to_string(),
        timestamp_secs,
    );

    let signed = metadata.sign(&ctx, &keypair);

    // Encode to bytes
    let encoded = signed.consensus_encode_to_vec();

    // Decode from bytes
    let deserialized: SignedGuardianMetadata =
        Decodable::consensus_decode_whole(&encoded, &ModuleRegistry::default())
            .expect("decoding should succeed");

    // Compare original and deserialized
    assert_eq!(signed.bytes, deserialized.bytes);
    assert_eq!(signed.value, deserialized.value);
    assert_eq!(signed.signature, deserialized.signature);
    assert_eq!(signed, deserialized);

    // Verify signature still works after roundtrip
    let now = Duration::from_secs(timestamp_secs);
    deserialized
        .verify(&ctx, &public_key, now)
        .expect("signature should verify after roundtrip");

    // Verify extracted metadata matches original
    assert_eq!(*deserialized.guardian_metadata(), metadata);
}

#[test]
fn verify_valid_signature_and_timestamp() {
    let ctx = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::new(&ctx, &mut secp256k1::rand::thread_rng());
    let public_key = secp256k1::PublicKey::from_keypair(&keypair);

    let timestamp_secs = 10000;
    let metadata = GuardianMetadata::new(
        vec!["wss://example.com/api".parse().unwrap()],
        "test_pkarr_id".to_string(),
        timestamp_secs,
    );
    let signed = metadata.sign(&ctx, &keypair);

    // Verify succeeds when now == timestamp
    signed
        .verify(&ctx, &public_key, Duration::from_secs(timestamp_secs))
        .expect("should verify with matching timestamp");

    // Verify succeeds when now is after timestamp (metadata from the past)
    signed
        .verify(
            &ctx,
            &public_key,
            Duration::from_secs(timestamp_secs + 1000),
        )
        .expect("should verify with past timestamp");

    // Verify succeeds when timestamp is slightly in the future (within allowed
    // window)
    signed
        .verify(
            &ctx,
            &public_key,
            Duration::from_secs(timestamp_secs - MAX_FUTURE_TIMESTAMP_SECS),
        )
        .expect("should verify when timestamp is within allowed future window");
}

#[test]
fn verify_rejects_invalid_signature() {
    let ctx = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::new(&ctx, &mut secp256k1::rand::thread_rng());
    let wrong_keypair = secp256k1::Keypair::new(&ctx, &mut secp256k1::rand::thread_rng());
    let wrong_public_key = secp256k1::PublicKey::from_keypair(&wrong_keypair);

    let timestamp_secs = 1000;
    let metadata = GuardianMetadata::new(
        vec!["wss://example.com/api".parse().unwrap()],
        "test_pkarr_id".to_string(),
        timestamp_secs,
    );
    let signed = metadata.sign(&ctx, &keypair);

    // Verify fails with wrong public key
    let result = signed.verify(&ctx, &wrong_public_key, Duration::from_secs(timestamp_secs));
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "should reject invalid signature"
    );
}

#[test]
fn verify_rejects_timestamp_too_far_in_future() {
    let ctx = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::new(&ctx, &mut secp256k1::rand::thread_rng());
    let public_key = secp256k1::PublicKey::from_keypair(&keypair);

    let timestamp_secs = 10000;
    let metadata = GuardianMetadata::new(
        vec!["wss://example.com/api".parse().unwrap()],
        "test_pkarr_id".to_string(),
        timestamp_secs,
    );
    let signed = metadata.sign(&ctx, &keypair);

    // Verify fails when timestamp is too far in the future
    let now_secs = timestamp_secs - MAX_FUTURE_TIMESTAMP_SECS - 1;
    let result = signed.verify(&ctx, &public_key, Duration::from_secs(now_secs));
    assert!(
        matches!(
            result,
            Err(VerificationError::TimestampTooFarInFuture {
                timestamp_secs: ts,
                ..
            }) if ts == timestamp_secs
        ),
        "should reject timestamp too far in future"
    );
}
