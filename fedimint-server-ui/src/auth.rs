use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::Redirect;
use axum_extra::extract::CookieJar;

use crate::{LOGIN_ROUTE, UiState};

/// Extractor that validates user authentication
pub struct UserAuth;

impl<Api> FromRequestParts<UiState<Api>> for UserAuth
where
    Api: Send + Sync + 'static,
{
    type Rejection = Redirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &UiState<Api>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| Redirect::to(LOGIN_ROUTE))?;

        // Check if the auth cookie exists and has the correct value
        match jar.get(&state.auth_cookie_name) {
            Some(cookie) if cookie.value() == state.auth_cookie_value => Ok(UserAuth),
            _ => Err(Redirect::to(LOGIN_ROUTE)),
        }
    }
}
