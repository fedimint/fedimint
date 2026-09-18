use bitcoin::hashes::{Hash as _, sha256};
use subtle::ConstantTimeEq as _;

/// Authorization value a client presents before receiving an LNv1 preimage.
#[derive(Clone, Copy)]
pub struct PreimageAuth(sha256::Hash);

impl PreimageAuth {
    /// Creates an authorization verifier for a stored LNv1 preimage
    /// authorization value.
    pub const fn new(expected: sha256::Hash) -> Self {
        Self(expected)
    }

    /// Returns whether the supplied value authorizes access to the LNv1
    /// preimage.
    pub fn verifies(self, supplied: sha256::Hash) -> bool {
        bool::from(self.0.as_byte_array().ct_eq(supplied.as_byte_array()))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;

    use super::PreimageAuth;

    #[test]
    fn accepts_matching_preimage_auth() {
        let preimage_auth = bitcoin::hashes::sha256::Hash::hash(b"preimage auth");

        assert!(PreimageAuth::new(preimage_auth).verifies(preimage_auth));
    }

    #[test]
    fn rejects_non_matching_preimage_auth() {
        let expected = bitcoin::hashes::sha256::Hash::hash(b"expected preimage auth");
        let supplied = bitcoin::hashes::sha256::Hash::hash(b"supplied preimage auth");

        assert!(!PreimageAuth::new(expected).verifies(supplied));
    }
}
