use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::Redirect;
use axum_extra::extract::CookieJar;

use crate::{LOGIN_ROUTE, UiState};

/// Extractor that validates user authentication
pub struct UserAuth;

impl FromRequestParts<UiState> for UserAuth {
    type Rejection = Redirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &UiState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| Redirect::to(LOGIN_ROUTE))?;

        tracing::info!(cookie_name = %state.auth_cookie_name, state_cookie_value = %state.auth_cookie_value, ?jar, "check if auth cookie exists...");
        // Check if the auth cookie exists and has the correct value
        match jar.get(&state.auth_cookie_name) {
            Some(cookie) if cookie.value() == state.auth_cookie_value => {
                tracing::info!(cookie_value = %cookie.value(), "Found cookie in cookie jar, matches, we are authenticated!");
                Ok(UserAuth {})
            }
            _ => {
                tracing::info!("No cookie in cookie jar");
                Err(Redirect::to(LOGIN_ROUTE))
            }
        }
    }
}
