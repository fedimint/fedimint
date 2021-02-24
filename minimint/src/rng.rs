use rand::{CryptoRng, RngCore};

/// Cheaply generates a new random number generator. Since these need to be generated often to avoid
/// locking them when used by different threads the construction should be rather cheap.
pub trait RngGenerator {
    type Rng: RngCore + CryptoRng;

    fn get_rng(&self) -> Self::Rng;
}
