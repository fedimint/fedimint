use bip445::{AggregatePublicKey, PublicKeyShare, SecretKeyShare};
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::{Hash, sha256};
use miniscript::descriptor::Tr;
use secp256k1::{Parity, PublicKey, SECP256K1, Scalar, SecretKey};

/// One x-only tweak step: negate to the even-y point if needed, then add
/// `tweak·G`. Applied to the aggregate key, every public key share and our
/// secret key share alike, so the shares keep combining to the tweaked key —
/// adding the same constant to every share works because the Lagrange
/// multipliers of any signing set sum to one.
#[derive(Debug, Clone, Copy)]
struct XOnlyTweak {
    negate: bool,
    tweak: Scalar,
}

impl XOnlyTweak {
    /// The step that lifts `key` to even y before adding `tweak·G`, together
    /// with the tweaked key.
    fn new(key: PublicKey, tweak: Scalar) -> (Self, PublicKey) {
        let step = Self {
            negate: key.x_only_public_key().1 == Parity::Odd,
            tweak,
        };

        (step, step.point(key))
    }

    fn point(&self, point: PublicKey) -> PublicKey {
        let point = if self.negate {
            point.negate(SECP256K1)
        } else {
            point
        };

        point
            .add_exp_tweak(SECP256K1, &self.tweak)
            .expect("The tweaked point is infinity only if the tweak is its negated discrete log")
    }

    fn secret(&self, secret: SecretKey) -> SecretKey {
        let secret = if self.negate { secret.negate() } else { secret };

        secret
            .add_tweak(&self.tweak)
            .expect("The tweaked secret is zero only if the tweak is its negation")
    }
}

/// The tweak of the FROST key for one federation UTXO: the per-UTXO tweak
/// that every walletv2 descriptor applies to its keys, followed by the BIP-341
/// tap tweak committing to the script tree. Both steps are x-only, so with
/// `g = ±1` lifting a key to even y the output key is
///
/// `Q = g₂·(g₁·P + t_utxo·G) + t_tap·G`
///
/// and a key share `s` becomes `g₂·(g₁·s + t_utxo) + t_tap`. The parity of
/// `Q` itself is handled by bip445, which negates the share when signing for
/// an odd-y aggregate key.
pub(crate) struct FrostTweak {
    utxo: XOnlyTweak,
    tap: XOnlyTweak,
    aggregate: AggregatePublicKey,
}

impl FrostTweak {
    /// Tweaks the aggregate key `aggregate_key` for the UTXO with tweak
    /// `utxo_tweak`, whose descriptor is `tr`.
    ///
    /// # Panics
    /// If the tweaked key doesn't match the output key of `tr`, which means
    /// `tr` isn't the FROST descriptor of this UTXO.
    pub(crate) fn new(
        aggregate_key: PublicKey,
        utxo_tweak: &sha256::Hash,
        tr: &Tr<XOnlyPublicKey>,
    ) -> Self {
        // See `tweak_xonly_public_key` for why the hash-to-scalar load is an
        // invariant.
        let utxo_tweak =
            Scalar::from_be_bytes(utxo_tweak.to_byte_array()).expect("Hash is within field order");

        let (utxo, internal_key) = XOnlyTweak::new(aggregate_key, utxo_tweak);

        let spend_info = tr.spend_info();

        let (tap, output_key) = XOnlyTweak::new(internal_key, spend_info.tap_tweak().to_scalar());

        assert_eq!(
            output_key.x_only_public_key().0,
            spend_info.output_key().to_x_only_public_key(),
            "The tweaked FROST key must be the output key of the UTXO's descriptor"
        );

        Self {
            utxo,
            tap,
            aggregate: AggregatePublicKey(output_key),
        }
    }

    /// The tweaked aggregate key the UTXO's key-path signature verifies under.
    pub(crate) fn aggregate(&self) -> &AggregatePublicKey {
        &self.aggregate
    }

    /// Tweaks a peer's public key share.
    pub(crate) fn public_share(&self, share: PublicKey) -> PublicKeyShare {
        PublicKeyShare(self.tap.point(self.utxo.point(share)))
    }

    /// Tweaks our secret key share.
    pub(crate) fn secret_share(&self, share: SecretKey) -> SecretKeyShare {
        SecretKeyShare(self.tap.secret(self.utxo.secret(share)))
    }
}
