use fedimint_core::PeerId;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::AmountUnit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_core::util::SafeUrl;
use fedimint_mintv2_common::Denomination;

use crate::SpendableNote;
use crate::ecash::ECash;

/// Wire schema of [`ECashField`] as it was before the `Unit` variant was
/// added, standing in for clients that predate it.
#[derive(Clone, Debug, Encodable, Decodable)]
enum LegacyECashField {
    Mint(FederationId),
    Note(SpendableNote),
    Invite {
        peer_apis: Vec<(PeerId, SafeUrl)>,
        federation_id: FederationId,
    },
    ApiSecret(String),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, Encodable, Decodable)]
struct LegacyECash(Vec<LegacyECashField>);

/// Positional index `Unit` occupies in [`ECashField`], which is what a legacy
/// decoder reports for it.
const UNIT_VARIANT: u64 = 4;

fn dummy_note() -> SpendableNote {
    SpendableNote {
        denomination: Denomination(10),
        keypair: Keypair::new(SECP256K1, &mut thread_rng()),
        signature: tbs::Signature(bls12_381::G1Affine::generator()),
    }
}

fn decode<T: Decodable>(bytes: &[u8]) -> T {
    T::consensus_decode_whole(bytes, &ModuleDecoderRegistry::default()).expect("e-cash decodes")
}

#[test]
fn custom_unit_survives_encoding() {
    let unit = AmountUnit::new_custom(42);
    let mint = FederationId::dummy();

    let ecash = ECash::new(mint, vec![dummy_note()]).with_unit(unit);
    assert_eq!(ecash.unit(), unit);

    let decoded: ECash = decode(&ecash.consensus_encode_to_vec());
    assert_eq!(decoded.unit(), unit);
    assert_eq!(decoded.mint(), Some(mint));
    assert_eq!(decoded.amount(), Denomination(10).amount());
}

#[test]
fn bitcoin_unit_is_omitted() {
    let notes = vec![dummy_note()];
    let plain = ECash::new(FederationId::dummy(), notes.clone());
    let bitcoin = ECash::new(FederationId::dummy(), notes).with_unit(AmountUnit::BITCOIN);

    assert_eq!(
        bitcoin.consensus_encode_to_vec(),
        plain.consensus_encode_to_vec()
    );
    assert_eq!(
        decode::<ECash>(&bitcoin.consensus_encode_to_vec()).unit(),
        AmountUnit::BITCOIN
    );
    assert_eq!(
        decode::<ECash>(&plain.consensus_encode_to_vec()).unit(),
        AmountUnit::BITCOIN
    );
}

/// A client predating the `Unit` variant decodes it as an unknown field and
/// re-encodes it byte-for-byte, so the unit survives passing through it.
#[test]
fn legacy_client_preserves_unit_field() {
    let unit = AmountUnit::new_custom(42);
    let ecash = ECash::new(FederationId::dummy(), vec![dummy_note()]).with_unit(unit);
    let encoded = ecash.consensus_encode_to_vec();

    let legacy: LegacyECash = decode(&encoded);

    let Some(LegacyECashField::Default { variant, bytes }) = legacy.0.last() else {
        panic!("unit field should decode as unknown variant on a legacy client");
    };
    assert_eq!(*variant, UNIT_VARIANT);
    assert_eq!(*bytes, unit.consensus_encode_to_vec());

    let reencoded = legacy.consensus_encode_to_vec();
    assert_eq!(reencoded, encoded);
    assert_eq!(decode::<ECash>(&reencoded).unit(), unit);
}

/// E-cash produced by a client predating the `Unit` variant is read as
/// Bitcoin-denominated.
#[test]
fn legacy_ecash_without_unit_is_bitcoin() {
    let mint = FederationId::dummy();
    let legacy = LegacyECash(vec![
        LegacyECashField::Mint(mint),
        LegacyECashField::Note(dummy_note()),
    ]);

    let decoded: ECash = decode(&legacy.consensus_encode_to_vec());

    assert_eq!(decoded.unit(), AmountUnit::BITCOIN);
    assert_eq!(decoded.mint(), Some(mint));
    assert_eq!(decoded.amount(), Denomination(10).amount());
}
