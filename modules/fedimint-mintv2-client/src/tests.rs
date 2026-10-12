use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_mintv2_common::Denomination;

use crate::{SpendableNote, SpendableNoteUndecoded};

#[test]
fn spendable_note_undecoded_encodes_like_spendable_note() {
    let note = SpendableNote {
        denomination: Denomination(10),
        keypair: Keypair::new(SECP256K1, &mut thread_rng()),
        signature: tbs::Signature(bls12_381::G1Affine::generator()),
    };

    let bytes = note.consensus_encode_to_vec();

    let undecoded =
        SpendableNoteUndecoded::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("A spendable note decodes as an undecoded one");

    assert_eq!(undecoded.consensus_encode_to_vec(), bytes);
    assert_eq!(SpendableNoteUndecoded::from(note.clone()), undecoded);
    assert_eq!(undecoded.decode().expect("The signature is valid"), note);
}
