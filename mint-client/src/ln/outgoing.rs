use minimint::modules::ln::contracts::outgoing::OutgoingContract;
use minimint_api::encoding::{Decodable, Encodable};

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractData {
    pub recovery_key: secp256k1_zkp::schnorrsig::KeyPair,
    pub contract: OutgoingContract,
}
