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
mod tests;
