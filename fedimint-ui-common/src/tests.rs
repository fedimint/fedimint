use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;

use super::UiState;

#[test]
fn authentication_requires_matching_cookie() {
    let state = UiState {
        api: (),
        auth_cookie_name: "session".to_owned(),
        auth_cookie_value: "expected-value".to_owned(),
        requires_auth: true,
    };

    let valid = CookieJar::new().add(Cookie::new("session", "expected-value"));
    let wrong_value = CookieJar::new().add(Cookie::new("session", "wrong-value"));
    let wrong_name = CookieJar::new().add(Cookie::new("other", "expected-value"));

    assert!(state.has_valid_auth_cookie(&valid));
    assert!(!state.has_valid_auth_cookie(&wrong_value));
    assert!(!state.has_valid_auth_cookie(&wrong_name));
    assert!(!state.has_valid_auth_cookie(&CookieJar::new()));
}
