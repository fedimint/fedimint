use fedimint_core::hex::ToHex;
use fedimint_core::secp256k1::rand::{Rng, thread_rng};

/// Generic state for both setup and dashboard UIs
#[derive(Clone)]
pub struct UiState<T> {
    pub api: T,
    pub auth_cookie_name: String,
    pub auth_cookie_value: String,
}

impl<T> UiState<T> {
    pub fn new(api: T) -> Self {
        Self {
            api,
            auth_cookie_name: thread_rng().r#gen::<[u8; 4]>().encode_hex(),
            auth_cookie_value: thread_rng().r#gen::<[u8; 32]>().encode_hex(),
        }
    }
}
