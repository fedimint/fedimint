use std::sync::Arc;

use fedimint_core::module::GatewayErrorCode;
use fedimint_core::util::SafeUrl;
use reqwest::Method;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::{GATEWAY_ERROR_READ_TIMEOUT, HttpConnection, MAX_GATEWAY_ERROR_BYTES};
use crate::IGatewayConnection as _;
use crate::error::ServerError;

async fn request_with_body(body: &str) -> Result<serde_json::Value, ServerError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has address");
    let body = body.to_string();
    fedimint_core::runtime::spawn("structured gateway HTTP test server", async move {
        let (mut stream, _) = listener.accept().await.expect("request connects");
        let mut request = [0; 4096];
        let _ = stream
            .read(&mut request)
            .await
            .expect("request can be read");
        let response = format!(
            "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response can be written");
    });

    HttpConnection {
        client: Arc::new(reqwest::Client::new()),
        base_url: SafeUrl::parse(&format!("http://{address}/")).expect("test URL is safe"),
    }
    .request(None, Method::GET, "pay_invoice", None)
    .await
}

#[tokio::test]
async fn http_gateway_response_preserves_only_recognized_structured_errors() {
    assert!(matches!(
        request_with_body(r#"{"version":1,"error":"federation_unreachable"}"#).await,
        Err(ServerError::GatewayResponse {
            status: 503,
            response
        }) if response.error == GatewayErrorCode::FederationUnreachable
    ));

    for body in [
        r#"{"version":2,"error":"federation_unreachable"}"#,
        r#"{"version":1,"error":"future_error"}"#,
        r#"{"version":1}"#,
        "legacy plaintext",
    ] {
        assert!(matches!(
            request_with_body(body).await,
            Err(ServerError::InvalidRequest(_))
        ));
    }
}

#[tokio::test]
async fn oversized_error_envelope_uses_generic_fallback() {
    let body = format!(
        r#"{{"version":1,"error":"federation_unreachable","padding":"{}"}}"#,
        "x".repeat(MAX_GATEWAY_ERROR_BYTES)
    );
    assert!(matches!(
        request_with_body(&body).await,
        Err(ServerError::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn stalled_error_envelope_uses_generic_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (release, wait) = tokio::sync::oneshot::channel::<()>();
    let server = fedimint_core::runtime::spawn("stalled error response", async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert_ne!(stream.read(&mut request).await.unwrap(), 0);
        // No Content-Length shortcut: exercise the deadline while reading a
        // chunked response whose next chunk never arrives.
        stream
            .write_all(
                b"HTTP/1.1 503 Service Unavailable\r\ntransfer-encoding: chunked\r\n\r\n1\r\n{\r\n",
            )
            .await
            .unwrap();
        wait.await.unwrap();
    });
    let result = fedimint_core::task::timeout(
        GATEWAY_ERROR_READ_TIMEOUT + std::time::Duration::from_secs(5),
        HttpConnection {
            client: Arc::new(reqwest::Client::new()),
            base_url: SafeUrl::parse(&format!("http://{address}/")).unwrap(),
        }
        .request(None, Method::GET, "pay_invoice", None),
    )
    .await
    .expect("error-body deadline must bound the request");
    assert!(matches!(result, Err(ServerError::InvalidRequest(_))));
    release.send(()).unwrap();
    server.await.unwrap();
}
