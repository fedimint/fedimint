use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, header};

use super::is_request_origin_allowed;

#[test]
fn browser_writes_allow_same_origin_and_reject_other_sites() {
    for (site, allowed) in [
        ("same-origin", true),
        ("none", true),
        ("same-site", false),
        ("cross-site", false),
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .header("sec-fetch-site", site)
            .body(Body::empty())
            .expect("valid request");

        assert_eq!(is_request_origin_allowed(&request), allowed, "{site}");
    }
}

#[test]
fn legacy_browser_writes_compare_origin_to_host() {
    for (origin, allowed) in [
        ("https://guardian.example", true),
        ("https://other.example", false),
        ("null", false),
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .header(header::HOST, "guardian.example")
            .header(header::ORIGIN, origin)
            .body(Body::empty())
            .expect("valid request");

        assert_eq!(is_request_origin_allowed(&request), allowed, "{origin}");
    }
}
