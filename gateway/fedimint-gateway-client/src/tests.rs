use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::FederationStatusResponse;
use fedimint_ln_common::client::GatewayApi;
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::{get_federation_status, validate_federation_status};

fn current_response() -> FederationStatusResponse {
    FederationStatusResponse::unserved(FederationId::dummy())
}

#[test]
fn response_cannot_escape_the_requested_federation_scope() {
    let response =
        FederationStatusResponse::unserved("01".repeat(32).parse().expect("valid federation id"));

    assert!(validate_federation_status(response, FederationId::dummy()).is_err());
}

#[tokio::test]
async fn http_client_sends_exact_public_scoped_request() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has address");
    let (request_tx, request_rx) = oneshot::channel();
    let response = serde_json::to_vec(&current_response()).expect("response serializes");
    let server = fedimint_core::runtime::spawn("gateway status client test server", async move {
        let (mut stream, _) = listener.accept().await.expect("request connects");
        let mut request = Vec::new();
        let header_end = loop {
            let mut chunk = [0; 1024];
            let read = stream.read(&mut chunk).await.expect("request is readable");
            assert_ne!(read, 0, "request ended before headers");
            request.extend_from_slice(&chunk[..read]);
            if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .expect("request has content length");
        while request.len() < header_end + content_length {
            let mut chunk = [0; 1024];
            let read = stream.read(&mut chunk).await.expect("request is readable");
            assert_ne!(read, 0, "request ended before body");
            request.extend_from_slice(&chunk[..read]);
        }
        request_tx.send(request).expect("test receives request");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response.len()
                )
                .as_bytes(),
            )
            .await
            .expect("response headers write");
        stream
            .write_all(&response)
            .await
            .expect("response body writes");
    });
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await;
    let client = GatewayApi::new(None, connectors);
    let base_url = SafeUrl::parse(&format!("http://{address}/")).expect("valid test URL");

    assert_eq!(
        get_federation_status(&client, &base_url, FederationId::dummy())
            .await
            .expect("status request succeeds"),
        current_response()
    );
    let request = request_rx.await.expect("request was captured");
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("request has headers")
        + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    assert!(headers.starts_with("POST /federation_status HTTP/1.1\r\n"));
    assert!(!headers.to_ascii_lowercase().contains("authorization:"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request[header_end..])
            .expect("request body is JSON"),
        json!({"federation_id": FederationId::dummy()})
    );
    server.await.expect("server task completes");
}
