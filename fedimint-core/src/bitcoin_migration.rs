use std::str::FromStr;

use bitcoin30::hashes::Hash as Bitcoin30Hash;
use bitcoin_hashes::Hash as Bitcoin29Hash;

pub fn bitcoin29_to_bitcoin30_public_key(pk: bitcoin::PublicKey) -> bitcoin30::PublicKey {
    bitcoin30::PublicKey::from_slice(&pk.to_bytes())
        .expect("Failed to convert bitcoin v29 public key to bitcoin v30 public key")
}

pub fn bitcoin29_to_bitcoin30_network(network: bitcoin::Network) -> bitcoin30::Network {
    match network {
        bitcoin::Network::Bitcoin => bitcoin30::Network::Bitcoin,
        bitcoin::Network::Testnet => bitcoin30::Network::Testnet,
        bitcoin::Network::Signet => bitcoin30::Network::Signet,
        bitcoin::Network::Regtest => bitcoin30::Network::Regtest,
    }
}

pub fn bitcoin30_to_bitcoin29_script(script: bitcoin30::ScriptBuf) -> bitcoin::Script {
    script.to_bytes().into()
}

pub fn bitcoin30_to_bitcoin29_address(address: bitcoin30::Address) -> bitcoin::Address {
    bitcoin::Address::from_str(&address.to_string())
        .expect("Failed to convert bitcoin v30 address to bitcoin v29 address")
}

pub fn bitcoin29_to_bitcoin30_ripemd160_hash(
    hash: bitcoin::hashes::ripemd160::Hash,
) -> bitcoin30::hashes::ripemd160::Hash {
    bitcoin30::hashes::ripemd160::Hash::from_byte_array(hash.into_inner())
}

pub fn bitcoin29_to_bitcoin30_hash160_hash(
    hash: bitcoin::hashes::hash160::Hash,
) -> bitcoin30::hashes::hash160::Hash {
    bitcoin30::hashes::hash160::Hash::from_byte_array(hash.into_inner())
}

pub fn bitcoin29_to_bitcoin30_sha256_hash(
    hash: bitcoin::hashes::sha256::Hash,
) -> bitcoin30::hashes::sha256::Hash {
    bitcoin30::hashes::sha256::Hash::from_byte_array(hash.into_inner())
}

#[cfg(test)]
mod tests {
    use bitcoin_hashes::hex::FromHex;
    use rand::thread_rng;

    use super::*;

    fn bitcoin30_to_bitcoin29_public_key(pk: bitcoin30::PublicKey) -> bitcoin::PublicKey {
        bitcoin::PublicKey::from_slice(&pk.to_bytes())
            .expect("Failed to convert bitcoin v30 public key to bitcoin v29 public key")
    }

    fn bitcoin29_to_bitcoin30_script(script: bitcoin::Script) -> bitcoin30::ScriptBuf {
        bitcoin30::ScriptBuf::from_bytes(script.into_bytes())
    }

    #[test]
    fn test_bitcoin29_to_bitcoin30_and_back_public_key() {
        let bitcoin29_pk: bitcoin::PublicKey =
            "037703ba67395870e5237787f380708f1b13751f7bdd97682e8f5af3f3a10a0a52"
                .parse()
                .expect("Failed to parse bitcoin v29 public key");

        let bitcoin30_pk = bitcoin29_to_bitcoin30_public_key(bitcoin29_pk);
        let bitcoin29_pk_back = bitcoin30_to_bitcoin29_public_key(bitcoin30_pk);

        assert_eq!(bitcoin29_pk, bitcoin29_pk_back);
    }

    #[test]
    fn test_bitcoin30_to_bitcoin29_and_back_public_key() {
        let bitcoin30_pk: bitcoin30::PublicKey =
            "0355aba9599a27e71eb515c813252f630c5914eb76b199b11db4265107619e8dcc"
                .parse()
                .expect("Failed to parse bitcoin v30 public key");

        let bitcoin29_pk = bitcoin30_to_bitcoin29_public_key(bitcoin30_pk);
        let bitcoin30_pk_back = bitcoin29_to_bitcoin30_public_key(bitcoin29_pk);

        assert_eq!(bitcoin30_pk, bitcoin30_pk_back);
    }

    #[test]
    fn test_network_conversions() {
        assert_eq!(
            bitcoin30::Network::Bitcoin,
            bitcoin29_to_bitcoin30_network(bitcoin::Network::Bitcoin)
        );
    }

    #[test]
    fn test_script_conversions() {
        let bitcoin29_public_key = bitcoin::PublicKey::new(
            bitcoin::secp256k1::Secp256k1::new()
                .generate_keypair(&mut thread_rng())
                .1,
        );
        let bitcoin29_script: bitcoin::Script = bitcoin::Script::new_p2pk(&bitcoin29_public_key);

        let bitcoin30_public_key = bitcoin29_to_bitcoin30_public_key(bitcoin29_public_key);
        let bitcoin30_script: bitcoin30::ScriptBuf =
            bitcoin30::ScriptBuf::new_p2pk(&bitcoin30_public_key);

        // Assert that bitcoin30->bitcoin29 script is the same as native bitcoin29
        // script.
        assert_eq!(
            bitcoin29_script,
            bitcoin30_to_bitcoin29_script(bitcoin30_script.clone())
        );
        // Assert that bitcoin29->bitcoin30 script is the same as native bitcoin30
        // script.
        assert_eq!(
            bitcoin30_script,
            bitcoin29_to_bitcoin30_script(bitcoin29_script)
        );
    }

    #[test]
    fn test_bitcoin30_to_bitcoin29_address() {
        let bitcoin29_public_key = bitcoin::PublicKey::new(
            bitcoin::secp256k1::Secp256k1::new()
                .generate_keypair(&mut thread_rng())
                .1,
        );
        let bitcoin29_address: bitcoin::Address =
            bitcoin::Address::p2pkh(&bitcoin29_public_key, bitcoin::Network::Bitcoin);

        let bitcoin30_public_key = bitcoin29_to_bitcoin30_public_key(bitcoin29_public_key);
        let bitcoin30_address: bitcoin30::Address =
            bitcoin30::Address::p2pkh(&bitcoin30_public_key, bitcoin30::Network::Bitcoin);

        // Assert that bitcoin30->bitcoin29 address is the same as native bitcoin29
        // address.
        assert_eq!(
            bitcoin29_address,
            bitcoin30_to_bitcoin29_address(bitcoin30_address)
        );
    }

    #[test]
    fn test_bitcoin29_to_bitcoin30_ripemd160_hash() {
        let bitcoin29_hash =
            bitcoin::hashes::ripemd160::Hash::from_hex("0123456789012345678901234567890123456789")
                .expect("Failed to parse bitcoin v29 ripemd160 hash");
        let bitcoin30_hash = bitcoin30::hashes::ripemd160::Hash::from_str(
            "0123456789012345678901234567890123456789",
        )
        .expect("Failed to parse bitcoin v30 ripemd160 hash");

        // Assert that bitcoin29->bitcoin30 ripemd160 hash is the same as native
        // bitcoin30 ripemd160 hash.
        assert_eq!(
            bitcoin30_hash,
            bitcoin29_to_bitcoin30_ripemd160_hash(bitcoin29_hash)
        );
    }

    #[test]
    fn test_bitcoin29_to_bitcoin30_hash160_hash() {
        let bitcoin29_hash =
            bitcoin::hashes::hash160::Hash::from_hex("0123456789012345678901234567890123456789")
                .expect("Failed to parse bitcoin v29 hash160 hash");
        let bitcoin30_hash =
            bitcoin30::hashes::hash160::Hash::from_str("0123456789012345678901234567890123456789")
                .expect("Failed to parse bitcoin v30 hash160 hash");

        // Assert that bitcoin29->bitcoin30 hash160 hash is the same as native bitcoin30
        // hash160 hash.
        assert_eq!(
            bitcoin30_hash,
            bitcoin29_to_bitcoin30_hash160_hash(bitcoin29_hash)
        );
    }

    #[test]
    fn test_bitcoin29_to_bitcoin30_sha256_hash() {
        let bitcoin29_hash = bitcoin::hashes::sha256::Hash::from_hex(
            "0123456789012345678901234567890123456789012345678901234567890123",
        )
        .expect("Failed to parse bitcoin v29 sha256 hash");
        let bitcoin30_hash = bitcoin30::hashes::sha256::Hash::from_str(
            "0123456789012345678901234567890123456789012345678901234567890123",
        )
        .expect("Failed to parse bitcoin v30 sha256 hash");

        // Assert that bitcoin29->bitcoin30 sha256 hash is the same as native bitcoin30
        // sha256 hash.
        assert_eq!(
            bitcoin30_hash,
            bitcoin29_to_bitcoin30_sha256_hash(bitcoin29_hash)
        );
    }
}
