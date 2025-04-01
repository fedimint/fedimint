use axum::Router;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

pub(crate) fn get_static_asset(content_type: &'static str, body: &'static [u8]) -> Response {
    (
        [(CONTENT_TYPE, content_type)],
        [(CACHE_CONTROL, format!("public, max-age={}", 60 * 60))],
        body,
    )
        .into_response()
}

pub(crate) fn get_static_css(body: &'static str) -> Response {
    get_static_asset("text/css", body.as_bytes())
}

pub(crate) fn get_static_png(body: &'static [u8]) -> Response {
    get_static_asset("image/png", body)
}

pub(crate) fn get_static_js(body: &'static str) -> Response {
    get_static_asset("application/javascript", body.as_bytes())
}

pub(crate) trait WithStaticRoutesExt {
    fn with_static_routes(self) -> Self;
}

impl<S> WithStaticRoutesExt for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn with_static_routes(self) -> Self {
        self.route(
            "/assets/bootstrap.min.css",
            get(|| async move { get_static_css(include_str!("../assets/bootstrap.min.css")) }),
        )
        .route(
            "/assets/bootstrap.bundle.min.js",
            get(|| async move { get_static_js(include_str!("../assets/bootstrap.bundle.min.js")) }),
        )
        .route(
            "/assets/htmx.org-2.0.4.min.js",
            get(|| async move { get_static_js(include_str!("../assets/htmx.org-2.0.4.min.js")) }),
        )
        .route(
            "/assets/style.css",
            get(|| async move { get_static_css(include_str!("../assets/style.css")) }),
        )
        .route(
            "/assets/logo.png",
            get(|| async move { get_static_png(include_bytes!("../assets/logo.png")) }),
        )
    }
}
