use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Redirect, Response};
use axum_extra::extract::CookieJar;
use fedimint_core::net::auth::GuardianAuthToken;

use crate::{LOGIN_ROUTE, UiState};

/// Extractor that validates user authentication
pub struct UserAuth {
    /// UserAuth is an axum extractor guaranteeing when the admin password was
    /// verified. This implies we can grant logic holding it access to
    /// fedimint-core internals that require `GuardianAuthToken`, which is a
    /// very similar mechanism.
    pub guardian_auth_token: GuardianAuthToken,
}

impl UserAuth {
    fn authenticated() -> Self {
        Self {
            guardian_auth_token: GuardianAuthToken::new_unchecked(),
        }
    }
}

/// Middleware that rejects state-changing cross-origin browser requests,
/// protecting cookie-authenticated UI routes against CSRF.
///
/// The auth cookie is `HttpOnly` + `SameSite=Lax`, which already keeps
/// browsers from attaching it to cross-site POSTs. This adds an independent
/// layer based on metadata browsers attach automatically:
///
/// - `Sec-Fetch-Site` (all modern browsers): only same-origin and
///   user-initiated (`none`) requests are allowed. Unlike `SameSite=Lax`, this
///   also rejects requests from sibling subdomains (`same-site`).
/// - `Origin` (legacy browsers send it on all cross-site POSTs): its authority
///   must match the request's `Host`.
///
/// Requests carrying neither header (curl and other non-browser clients)
/// pass through; they don't attach cookies ambiently, so CSRF does not
/// apply to them.
pub async fn csrf_protection_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if is_request_origin_allowed(&request) {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn is_request_origin_allowed(request: &Request) -> bool {
    let method = request.method();
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return true;
    }

    let headers = request.headers();

    if let Some(site) = headers.get("sec-fetch-site") {
        return site
            .to_str()
            .is_ok_and(|site| site == "same-origin" || site == "none");
    }

    if let Some(origin) = headers.get(header::ORIGIN) {
        // An opaque origin ("null") or a non-http(s) scheme is never
        // acceptable for a state-changing request
        let Some(origin_authority) = origin.to_str().ok().and_then(|origin| {
            origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"))
        }) else {
            return false;
        };

        let Some(host) = headers
            .get(header::HOST)
            .and_then(|host| host.to_str().ok())
            .or_else(|| {
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str())
            })
        else {
            return false;
        };

        return origin_authority.eq_ignore_ascii_case(host);
    }

    true
}

impl<Api> FromRequestParts<UiState<Api>> for UserAuth
where
    Api: Send + Sync + 'static,
{
    type Rejection = Redirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &UiState<Api>,
    ) -> Result<Self, Self::Rejection> {
        if !state.requires_auth {
            return Ok(UserAuth::authenticated());
        }

        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| Redirect::to(LOGIN_ROUTE))?;

        // Check if the auth cookie exists and has the correct value
        match jar.get(&state.auth_cookie_name) {
            Some(cookie) if cookie.value() == state.auth_cookie_value => {
                Ok(UserAuth::authenticated())
            }
            _ => Err(Redirect::to(LOGIN_ROUTE)),
        }
    }
}
