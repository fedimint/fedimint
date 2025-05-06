use std::convert::Infallible;

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
        if MaybeUserAuth::from_request_parts(parts, state)
            .await
            .is_ok_and(|auth| auth.is_authenticated)
        {
            Ok(UserAuth)
        } else {
            Err(Redirect::to(LOGIN_ROUTE))
        }
    }
}

pub struct MaybeUserAuth {
    is_authenticated: bool,
}

impl<Api> FromRequestParts<UiState<Api>> for MaybeUserAuth
where
    Api: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &UiState<Api>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state).await?;

        // Check if the auth cookie exists and has the correct value
        match jar.get(&state.auth_cookie_name) {
            Some(cookie) if cookie.value() == state.auth_cookie_value => Ok(MaybeUserAuth {
                is_authenticated: true,
            }),
            _ => Ok(MaybeUserAuth {
                is_authenticated: false,
            }),
        }
    }
}
