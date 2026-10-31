use std::ops::{Deref, DerefMut};

use bitcoin::Network;
use bitcoin::constants::genesis_block;
use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::txoproof::TxOutProof;
use fedimint_wallet_common::WalletInputV0;
use fedimint_wallet_common::txoproof::PegInProof;

fn peg_in_proof(secret: u8) -> PegInProof {
    let block = genesis_block(Network::Bitcoin);
    let transaction = block.txdata[0].clone();
    let txout_proof = TxOutProof {
        block_header: block.header,
        merkle_proof: PartialMerkleTree::from_txids(&[transaction.compute_txid()], &[true]),
    };
    // Decode to include the serialized Merkle proof's padding bits in equality.
    let txout_proof = TxOutProof::consensus_decode_whole(
        &txout_proof.consensus_encode_to_vec(),
        &ModuleDecoderRegistry::default(),
    )
    .unwrap();
    let key = PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[secret; 32]).unwrap(),
    );
    PegInProof::new(txout_proof, transaction, 0, key).unwrap()
}

#[test]
// The boxed reference is part of the public Deref target being tested.
#[allow(clippy::borrowed_box)]
fn wallet_input_v0_derefs_to_boxed_proof() {
    fn assert_deref_target<T: Deref<Target = Box<PegInProof>> + DerefMut>() {}
    assert_deref_target::<WalletInputV0>();

    let proof = peg_in_proof(1);
    let mut input = WalletInputV0(Box::new(proof.clone()));
    assert!(std::ptr::eq(input.deref(), &input.0));
    let boxed: &Box<PegInProof> = &input;
    assert_eq!(boxed.as_ref(), &proof);
    let borrowed: &PegInProof = &input;
    assert_eq!(borrowed, &proof);
    assert_eq!(input.outpoint(), proof.outpoint());

    assert!(std::ptr::eq(input.deref_mut(), &input.0));
    let replacement = peg_in_proof(2);
    let boxed_mut: &mut Box<PegInProof> = &mut input;
    let original = std::mem::replace(boxed_mut, Box::new(replacement.clone()));
    assert_eq!(original.as_ref(), &proof);
    assert_eq!(input.0.as_ref(), &replacement);

    let borrowed_mut: &mut PegInProof = &mut input;
    *borrowed_mut = proof.clone();
    assert_eq!(input.0.as_ref(), &proof);
}

#[test]
fn wallet_input_v0_preserves_proof_consensus_encoding() {
    let proof = peg_in_proof(1);
    let input = WalletInputV0(Box::new(proof.clone()));
    let bytes = input.consensus_encode_to_vec();
    assert_eq!(bytes, proof.consensus_encode_to_vec());
    assert_eq!(
        WalletInputV0::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default()).unwrap(),
        input
    );
}
