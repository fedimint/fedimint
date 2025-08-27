use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use fedimint_core::base32;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub trait Encryptable {
    fn encrypt(&self, key: &[u8; 32]) -> EncryptedData;
}

impl<T: Encodable> Encryptable for T {
    fn encrypt(&self, key: &[u8; 32]) -> EncryptedData {
        let nonce = rand::thread_rng().r#gen::<[u8; 12]>();

        let plaintext = self.consensus_encode_to_vec();

        let ciphertext = ChaCha20Poly1305::new(Key::from_slice(key))
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .unwrap();

        EncryptedData { nonce, ciphertext }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct EncryptedData {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    pub fn decrypt<T: Decodable>(&self, key: &[u8; 32]) -> Option<T> {
        let plaintext = ChaCha20Poly1305::new(Key::from_slice(key))
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_slice())
            .ok()?;

        T::consensus_decode_whole(&plaintext, &ModuleDecoderRegistry::default()).ok()
    }

    pub fn encode_base32(&self) -> String {
        base32::encode(&self.consensus_encode_to_vec())
    }

    pub fn decode_base32(s: &str) -> Option<Self> {
        Self::consensus_decode_whole(&base32::decode(s).ok()?, &ModuleDecoderRegistry::default())
            .ok()
    }
}
