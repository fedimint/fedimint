use fedimint_core::module::{ApiEndpointContext, ApiError, ApiResult};

/// A token proving the the API call was authenticated
///
/// Api handlers are encouraged to take it as an argument to avoid sensitive
/// guardian-only logic being accidentally unauthenticated.
pub struct GuardianAuthToken {
    _marker: (), // private field just to make creating it outside impossible
}

impl GuardianAuthToken {
    /// Creates a token without verifying authentication.
    ///
    /// # Safety
    /// The caller must ensure that authentication has already been verified
    /// through other means before calling this function.
    pub fn new_unchecked() -> Self {
        Self { _marker: () }
    }
}

pub fn check_auth(context: &mut ApiEndpointContext) -> ApiResult<GuardianAuthToken> {
    if context.has_auth() {
        Ok(GuardianAuthToken { _marker: () })
    } else {
        Err(ApiError::unauthorized())
    }
}
