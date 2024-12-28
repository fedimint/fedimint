use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_core::Amount;
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_mintv2_common::{MintOutput, MintOutputV0};
use tbs::{
    blind_message, unblind_signature, BlindedMessage, BlindedSignature, BlindingKey, Message,
};

use crate::SpendableNote;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
pub struct NoteIssuanceRequest {
    pub amount: Amount,
    pub tweak: [u8; 8],
}

impl NoteIssuanceRequest {
    pub fn new(amount: Amount, tweak: [u8; 8]) -> NoteIssuanceRequest {
        NoteIssuanceRequest { amount, tweak }
    }

    pub fn recover(
        output: MintOutputV0,
        root_secret: &DerivableSecret,
    ) -> Option<NoteIssuanceRequest> {
        let request = NoteIssuanceRequest {
            amount: output.amount,
            tweak: output.tweak,
        };

        if request.blinded_message(root_secret) != output.nonce {
            return None;
        }

        Some(request)
    }

    fn secret(&self, root_secret: &DerivableSecret) -> DerivableSecret {
        root_secret
            .child_key(ChildId(self.amount.msats))
            .child_key(ChildId(u64::from_be_bytes(self.tweak)))
    }

    pub fn blinded_message(&self, root_secret: &DerivableSecret) -> BlindedMessage {
        blind_message(self.message(root_secret), self.blinding_key(root_secret))
    }

    pub fn keypair(&self, root_secret: &DerivableSecret) -> Keypair {
        self.secret(root_secret).to_secp_key(SECP256K1)
    }

    fn blinding_key(&self, root_secret: &DerivableSecret) -> BlindingKey {
        BlindingKey(self.secret(root_secret).to_bls12_381_key())
    }

    fn message(&self, root_secret: &DerivableSecret) -> Message {
        Message::from_bytes_sha256(&self.keypair(root_secret).public_key().serialize())
    }

    pub fn output(&self, root_secret: &DerivableSecret) -> MintOutput {
        MintOutput::new_v0(self.amount, self.blinded_message(root_secret), self.tweak)
    }

    pub fn finalize(
        &self,
        root_secret: &DerivableSecret,
        blinded_signature: BlindedSignature,
    ) -> SpendableNote {
        SpendableNote {
            amount: self.amount,
            signature: unblind_signature(self.blinding_key(root_secret), blinded_signature),
            keypair: self.keypair(root_secret),
        }
    }
}
