use axum::Router;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

// Asset route constants
pub const BOOTSTRAP_CSS_ROUTE: &str = "/assets/bootstrap.min.css";
pub const BOOTSTRAP_JS_ROUTE: &str = "/assets/bootstrap.bundle.min.js";
pub const HTMX_JS_ROUTE: &str = "/assets/htmx.org-2.0.4.min.js";
pub const HTML5_QRCODE_JS_ROUTE: &str = "/assets/html5-qrcode.min.js";
pub const CHARTJS_ROUTE: &str = "/assets/chart.umd.min.js";
pub const STYLE_CSS_ROUTE: &str = "/assets/style.css";
pub const LOGO_PNG_ROUTE: &str = "/assets/logo.png";

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

pub trait WithStaticRoutesExt {
    fn with_static_routes(self) -> Self;
}

impl<S> WithStaticRoutesExt for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn with_static_routes(self) -> Self {
        self.route(
            BOOTSTRAP_CSS_ROUTE,
            get(|| async move { get_static_css(include_str!("../assets/bootstrap.min.css")) }),
        )
        .route(
            BOOTSTRAP_JS_ROUTE,
            get(|| async move { get_static_js(include_str!("../assets/bootstrap.bundle.min.js")) }),
        )
        .route(
            HTMX_JS_ROUTE,
            get(|| async move { get_static_js(include_str!("../assets/htmx.org-2.0.4.min.js")) }),
        )
        .route(
            HTML5_QRCODE_JS_ROUTE,
            get(|| async move { get_static_js(include_str!("../assets/html5-qrcode.min.js")) }),
        )
        .route(
            CHARTJS_ROUTE,
            get(|| async move { get_static_js(include_str!("../assets/chart.umd.min.js")) }),
        )
        .route(
            STYLE_CSS_ROUTE,
            get(|| async move { get_static_css(include_str!("../assets/style.css")) }),
        )
        .route(
            LOGO_PNG_ROUTE,
            get(|| async move { get_static_png(include_bytes!("../assets/logo.png")) }),
        )
    }
}
