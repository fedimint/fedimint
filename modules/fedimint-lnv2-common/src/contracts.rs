use bitcoin30::hashes::sha256;
use bitcoin30::secp256k1;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::Amount;
use secp256k1::schnorr::Signature;
use secp256k1::{Message, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use tpe::{
    create_decryption_key_share, decrypt_preimage, encrypt_preimage, verify_agg_decryption_key,
    verify_ciphertext, verify_decryption_key_share, AggregateDecryptionKey, AggregatePublicKey,
    CipherText, DecryptionKeyShare, PublicKeyShare, SecretKeyShare,
};

use crate::ContractId;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum PaymentImage {
    Hash(sha256::Hash),
    Point(PublicKey),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContract {
    pub commitment: Commitment,
    pub ciphertext: CipherText,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Commitment {
    pub payment_image: PaymentImage,
    pub amount: Amount,
    pub expiration: u64,
    pub claim_pk: PublicKey,
    pub refund_pk: PublicKey,
    pub ephemeral_pk: PublicKey,
}

impl IncomingContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agg_pk: AggregatePublicKey,
        encryption_seed: [u8; 32],
        preimage: [u8; 32],
        payment_image: PaymentImage,
        amount: Amount,
        expiration: u64,
        claim_pk: PublicKey,
        refund_pk: PublicKey,
        ephemeral_pk: PublicKey,
    ) -> Self {
        let commitment = Commitment {
            payment_image,
            amount,
            expiration,
            claim_pk,
            refund_pk,
            ephemeral_pk,
        };

        let ciphertext = encrypt_preimage(
            &agg_pk,
            &encryption_seed,
            &preimage,
            &commitment.consensus_hash_bitcoin30(),
        );

        IncomingContract {
            commitment,
            ciphertext,
        }
    }

    pub fn contract_id(&self) -> ContractId {
        ContractId(self.consensus_hash_bitcoin30())
    }

    pub fn verify(&self) -> bool {
        verify_ciphertext(
            &self.ciphertext,
            &self.commitment.consensus_hash_bitcoin30(),
        )
    }

    pub fn verify_decryption_share(
        &self,
        pk: &PublicKeyShare,
        dk_share: &DecryptionKeyShare,
    ) -> bool {
        verify_decryption_key_share(
            pk,
            dk_share,
            &self.ciphertext,
            &self.commitment.consensus_hash_bitcoin30(),
        )
    }

    pub fn verify_agg_decryption_key(
        &self,
        agg_pk: &AggregatePublicKey,
        agg_decryption_key: &AggregateDecryptionKey,
    ) -> bool {
        verify_agg_decryption_key(
            agg_pk,
            agg_decryption_key,
            &self.ciphertext,
            &self.commitment.consensus_hash_bitcoin30(),
        )
    }

    pub fn verify_preimage(&self, preimage: &[u8; 32]) -> bool {
        verify_preimage(&self.commitment.payment_image, preimage)
    }

    pub fn decrypt_preimage(
        &self,
        agg_decryption_key: &AggregateDecryptionKey,
    ) -> Option<[u8; 32]> {
        let preimage = decrypt_preimage(&self.ciphertext, agg_decryption_key);

        if self.verify_preimage(&preimage) {
            Some(preimage)
        } else {
            None
        }
    }

    pub fn create_decryption_key_share(&self, sk: &SecretKeyShare) -> DecryptionKeyShare {
        create_decryption_key_share(sk, &self.ciphertext)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutgoingContract {
    pub payment_image: PaymentImage,
    pub amount: Amount,
    pub expiration: u64,
    pub claim_pk: PublicKey,
    pub refund_pk: PublicKey,
    pub ephemeral_pk: PublicKey,
}

impl OutgoingContract {
    pub fn contract_id(&self) -> ContractId {
        ContractId(self.consensus_hash_bitcoin30())
    }

    pub fn forfeit_message(&self) -> Message {
        Message::from(self.contract_id().0)
    }

    pub fn verify_preimage(&self, preimage: &[u8; 32]) -> bool {
        verify_preimage(&self.payment_image, preimage)
    }

    pub fn verify_forfeit_signature(&self, signature: &Signature) -> bool {
        secp256k1::global::SECP256K1
            .verify_schnorr(
                signature,
                &self.forfeit_message(),
                &self.claim_pk.x_only_public_key().0,
            )
            .is_ok()
    }

    pub fn verify_gateway_response(&self, gateway_response: &Result<[u8; 32], Signature>) -> bool {
        match gateway_response {
            Ok(preimage) => self.verify_preimage(preimage),
            Err(signature) => self.verify_forfeit_signature(signature),
        }
    }

    pub fn verify_invoice_auth(&self, message: sha256::Hash, signature: &Signature) -> bool {
        secp256k1::global::SECP256K1
            .verify_schnorr(
                signature,
                &message.into(),
                &self.refund_pk.x_only_public_key().0,
            )
            .is_ok()
    }
}

fn verify_preimage(payment_image: &PaymentImage, preimage: &[u8; 32]) -> bool {
    match payment_image {
        PaymentImage::Hash(hash) => preimage.consensus_hash_bitcoin30::<sha256::Hash>() == *hash,
        PaymentImage::Point(pk) => match SecretKey::from_slice(preimage) {
            Ok(sk) => sk.public_key(secp256k1::SECP256K1) == *pk,
            Err(..) => false,
        },
    }
}

#[test]
fn test_verify_preimage() {
    use bitcoin30::hashes::Hash;

    assert!(verify_preimage(
        &PaymentImage::Hash(bitcoin30::hashes::sha256::Hash::hash(&[42; 32])),
        &[42; 32]
    ));

    let (secret_key, public_key) = secp256k1::generate_keypair(&mut secp256k1::rand::thread_rng());

    assert!(verify_preimage(
        &PaymentImage::Point(public_key),
        &secret_key.secret_bytes()
    ));
}
