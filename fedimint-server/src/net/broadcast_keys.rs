//! Deterministic key derivation from the broadcast secret key.
//!
//! Every key derived from the broadcast secret uses HKDF via
//! [`DerivableSecret`].  Each derivation uses a unique *domain tag*
//! (the second argument to [`DerivableSecret::new_root`]) so the
//! resulting key trees are completely independent.  Within a single
//! domain, child keys are selected by [`ChildId`].
//!
//! All derivations are collected here so that domain tags and child
//! IDs can be audited in one place and accidental collisions are
//! impossible.

use fedimint_core::secp256k1::SecretKey;
use fedimint_derive_secret::{ChildId, DerivableSecret};

/// Protocol version string for the iroh-next dual-stack endpoints.
pub const IROH_NEXT_VERSION: &str = "0.90";

// ── Domain: fedimint-pkarr ──────────────────────────────────────────

const PKARR_DOMAIN: &[u8] = b"fedimint-pkarr";
const PKARR_IDENTITY_CHILD_ID: ChildId = ChildId(0);

/// Derive a pkarr keypair for DNS TXT record publishing.
pub fn derive_pkarr_keypair(broadcast_sk: &SecretKey) -> pkarr::Keypair {
    let root = DerivableSecret::new_root(&broadcast_sk.secret_bytes(), PKARR_DOMAIN);
    let seed: [u8; 32] = root.child_key(PKARR_IDENTITY_CHILD_ID).to_random_bytes();
    pkarr::Keypair::from_secret_key(&seed)
}

// ── Domain: fedimint-iroh-next ──────────────────────────────────────

const IROH_NEXT_DOMAIN: &[u8] = b"fedimint-iroh-next";
const IROH_NEXT_API_CHILD_ID: ChildId = ChildId(0);
const IROH_NEXT_P2P_CHILD_ID: ChildId = ChildId(1);

fn derive_iroh_next_sk(broadcast_sk: &SecretKey, child_id: ChildId) -> iroh_next::SecretKey {
    let root = DerivableSecret::new_root(&broadcast_sk.secret_bytes(), IROH_NEXT_DOMAIN);
    let seed: [u8; 32] = root.child_key(child_id).to_random_bytes();
    iroh_next::SecretKey::from_bytes(&seed)
}

/// Derive the iroh-next secret key used by the **API** endpoint.
pub fn derive_iroh_next_api_sk(broadcast_sk: &SecretKey) -> iroh_next::SecretKey {
    derive_iroh_next_sk(broadcast_sk, IROH_NEXT_API_CHILD_ID)
}

/// Derive the iroh-next secret key used by the **P2P** endpoint.
pub fn derive_iroh_next_p2p_sk(broadcast_sk: &SecretKey) -> iroh_next::SecretKey {
    derive_iroh_next_sk(broadcast_sk, IROH_NEXT_P2P_CHILD_ID)
}
