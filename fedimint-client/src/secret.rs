use std::fmt::Debug;
use std::io::{Read, Write};

use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_derive_secret::{ChildId, DerivableSecret};
use rand::{CryptoRng, Rng, RngCore};

// Derived from pre-root-secret (pre-federation-derived)
const TYPE_PRE_ROOT_SECRET_HASH: ChildId = ChildId(0);

// Derived from federation-root-secret
const TYPE_MODULE: ChildId = ChildId(0);
const TYPE_BACKUP: ChildId = ChildId(1);

pub trait DeriveableSecretClientExt {
    fn derive_module_secret(&self, module_instance_id: ModuleInstanceId) -> DerivableSecret;
    fn derive_backup_secret(&self) -> DerivableSecret;
    fn derive_pre_root_secret_hash(&self) -> [u8; 8];
}

impl DeriveableSecretClientExt for DerivableSecret {
    fn derive_module_secret(&self, module_instance_id: ModuleInstanceId) -> DerivableSecret {
        assert_eq!(self.level(), 0);
        self.child_key(TYPE_MODULE)
            .child_key(ChildId(u64::from(module_instance_id)))
    }

    fn derive_backup_secret(&self) -> DerivableSecret {
        assert_eq!(self.level(), 0);
        self.child_key(TYPE_BACKUP)
    }

    fn derive_pre_root_secret_hash(&self) -> [u8; 8] {
        // Note: this hash is derived from a pre-root-secret: one passed from the
        // outside, before the federation ID is used to derive the
        // federation-specific-root-secret, which gets level reset to 0.
        // Because of that we don't care about asserting the level.
        self.child_key(TYPE_PRE_ROOT_SECRET_HASH).to_random_bytes()
    }
}

/// Trait defining a way to generate, serialize and deserialize a root secret.
/// It defines a `Encoding` associated type which represents a specific
/// representation of a secret (e.g. a bip39, slip39, CODEX32, … struct) and
/// then defines the methods necessary for the client to interact with it.
///
/// We use a strategy pattern (i.e. implementing the trait on a zero sized type
/// with the actual secret struct as an associated type instead of implementing
/// the necessary functions directly on the secret struct) to allow external
/// implementations on third-party types without wrapping them in newtypes.
pub trait RootSecretStrategy: Debug {
    /// Type representing the secret
    type Encoding: Clone;

    /// Conversion function from the external encoding to the internal one
    fn to_root_secret(secret: &Self::Encoding) -> DerivableSecret;

    /// Serialization function for the external encoding
    fn consensus_encode(
        secret: &Self::Encoding,
        writer: &mut impl std::io::Write,
    ) -> std::io::Result<usize>;

    /// Deserialization function for the external encoding
    fn consensus_decode(reader: &mut impl std::io::Read) -> Result<Self::Encoding, DecodeError>;

    /// Random generation function for the external secret type
    fn random<R>(rng: &mut R) -> Self::Encoding
    where
        R: rand::RngCore + rand::CryptoRng;
}

/// Just uses 64 random bytes and derives the secret from them
#[derive(Debug)]
pub struct PlainRootSecretStrategy;

impl RootSecretStrategy for PlainRootSecretStrategy {
    type Encoding = [u8; 64];

    fn to_root_secret(secret: &Self::Encoding) -> DerivableSecret {
        const FEDIMINT_CLIENT_NONCE: &[u8] = b"Fedimint Client Salt";
        DerivableSecret::new_root(secret.as_ref(), FEDIMINT_CLIENT_NONCE)
    }

    fn consensus_encode(
        secret: &Self::Encoding,
        writer: &mut impl Write,
    ) -> std::io::Result<usize> {
        secret.consensus_encode(writer)
    }

    fn consensus_decode(reader: &mut impl Read) -> Result<Self::Encoding, DecodeError> {
        Self::Encoding::consensus_decode(reader, &ModuleRegistry::default())
    }

    fn random<R>(rng: &mut R) -> Self::Encoding
    where
        R: RngCore + CryptoRng,
    {
        let mut secret = [0u8; 64];
        rng.fill(&mut secret);
        secret
    }
}

/// Convenience function to derive fedimint-client root secret
/// using the default (0) wallet number, given a global root secret
/// that's managed externally by a consumer of fedimint-client.
///
/// See docs/secret_derivation.md
///
/// `global_root_secret/<key-type=per-federation=0>/<federation-id>/
/// <wallet-number=0>/<key-type=fedimint-client=0>`
pub fn get_default_client_secret(
    global_root_secret: &DerivableSecret,
    federation_id: &FederationId,
) -> DerivableSecret {
    let multi_federation_root_secret = global_root_secret.child_key(ChildId(0));
    let federation_root_secret = multi_federation_root_secret.federation_key(federation_id);
    let federation_wallet_root_secret = federation_root_secret.child_key(ChildId(0)); // wallet-number=0
    federation_wallet_root_secret.child_key(ChildId(0)) // key-type=fedimint-client=0
}
