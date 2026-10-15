use fedimint_core::Amount;
use fedimint_core::encoding::Decodable as _;
use fedimint_core::module::serde_json;

use super::FeeConsensus;

#[test]
fn decoded_fee_consensus_is_validated() {
    use fedimint_core::encoding::Encodable as _;
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    let modules = ModuleDecoderRegistry::default();
    for fee in [
        FeeConsensus::zero(),
        FeeConsensus::new(0).expect("zero ppm is valid"),
        FeeConsensus::new(1_000).expect("maximum ppm is valid"),
    ] {
        assert_eq!(
            serde_json::from_str::<FeeConsensus>(
                &serde_json::to_string(&fee).expect("fee consensus can be encoded")
            )
            .expect("valid JSON fee consensus can be decoded"),
            fee
        );
        assert_eq!(
            FeeConsensus::consensus_decode_whole(&fee.consensus_encode_to_vec(), &modules)
                .expect("valid consensus fee can be decoded"),
            fee
        );
    }

    for malformed in [
        (Amount::ZERO, 1),
        (Amount::from_msats(99), 0),
        (Amount::from_msats(100), 1_001),
        (Amount::from_msats(u64::MAX), u64::MAX),
    ] {
        let json = serde_json::json!({
            "base": malformed.0,
            "parts_per_million": malformed.1,
        });
        assert!(serde_json::from_value::<FeeConsensus>(json).is_err());

        let encoded = malformed.consensus_encode_to_vec();
        assert!(FeeConsensus::consensus_decode_whole(&encoded, &modules).is_err());
    }
}
