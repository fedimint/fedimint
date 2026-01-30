use bitcoin::hashes::sha256;
use bitcoin::secp256k1;
use fedimint_core::Amount;
use fedimint_core::encoding::{Decodable, Encodable};
use secp256k1::schnorr::Signature;
use secp256k1::{Message, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use tpe::{
    AggregateDecryptionKey, AggregatePublicKey, CipherText, DecryptionKeyShare, PublicKeyShare,
    SecretKeyShare, create_dk_share, decrypt_preimage, encrypt_preimage, verify_agg_dk,
    verify_ciphertext, verify_dk_share,
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
            &commitment.consensus_hash(),
        );

        IncomingContract {
            commitment,
            ciphertext,
        }
    }

    pub fn contract_id(&self) -> ContractId {
        ContractId(self.consensus_hash())
    }

    pub fn verify(&self) -> bool {
        verify_ciphertext(&self.ciphertext, &self.commitment.consensus_hash())
    }

    pub fn verify_decryption_share(
        &self,
        pk: &PublicKeyShare,
        dk_share: &DecryptionKeyShare,
    ) -> bool {
        verify_dk_share(
            pk,
            dk_share,
            &self.ciphertext,
            &self.commitment.consensus_hash(),
        )
    }

    pub fn verify_agg_decryption_key(
        &self,
        agg_pk: &AggregatePublicKey,
        agg_decryption_key: &AggregateDecryptionKey,
    ) -> bool {
        verify_agg_dk(
            agg_pk,
            agg_decryption_key,
            &self.ciphertext,
            &self.commitment.consensus_hash(),
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
        create_dk_share(sk, &self.ciphertext)
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
        ContractId(self.consensus_hash())
    }

    pub fn forfeit_message(&self) -> Message {
        Message::from_digest(*self.contract_id().0.as_ref())
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
                &Message::from_digest(*message.as_ref()),
                &self.refund_pk.x_only_public_key().0,
            )
            .is_ok()
    }
}

fn verify_preimage(payment_image: &PaymentImage, preimage: &[u8; 32]) -> bool {
    match payment_image {
        PaymentImage::Hash(hash) => preimage.consensus_hash::<sha256::Hash>() == *hash,
        PaymentImage::Point(pk) => match SecretKey::from_slice(preimage) {
            Ok(sk) => sk.public_key(secp256k1::SECP256K1) == *pk,
            Err(..) => false,
        },
    }
}

/// Contract data stored per outpoint for looking up input amounts
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
#[allow(clippy::large_enum_variant)] // Not on any hot path, not worth the boxing
pub enum LightningContract {
    Incoming(IncomingContract),
    Outgoing(OutgoingContract),
}

impl LightningContract {
    pub fn amount(&self) -> Amount {
        match self {
            LightningContract::Incoming(c) => c.commitment.amount,
            LightningContract::Outgoing(c) => c.amount,
        }
    }
}

#[test]
fn test_verify_preimage() {
    use bitcoin::hashes::Hash;

    assert!(verify_preimage(
        &PaymentImage::Hash(bitcoin::hashes::sha256::Hash::hash(&[42; 32])),
        &[42; 32]
    ));

    let (secret_key, public_key) = secp256k1::generate_keypair(&mut secp256k1::rand::thread_rng());

    assert!(verify_preimage(
        &PaymentImage::Point(public_key),
        &secret_key.secret_bytes()
    ));
}
