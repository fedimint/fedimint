use std::sync::Arc;

use fedimint_core::util::SafeUrl;
use reqwest::Method;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::HttpConnection;
use crate::IGatewayConnection as _;
use crate::error::ServerError;

async fn request_status(status: u16) -> ServerError {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has address");
    let server = fedimint_core::runtime::spawn("gateway status test server", async move {
        let (mut stream, _) = listener.accept().await.expect("request connects");
        let mut request = vec![0; 4096];
        let _ = stream
            .read(&mut request)
            .await
            .expect("request is readable");
        let response = format!(
            "HTTP/1.1 {status} Test\r\ncontent-length: 15\r\nconnection: close\r\n\r\nsecret-details!"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response writes");
    });
    let connection = HttpConnection {
        client: Arc::new(reqwest::Client::new()),
        base_url: SafeUrl::parse(&format!("http://{address}/")).expect("valid test URL"),
    };

    let error = connection
        .request(None, Method::POST, "/missing", None)
        .await
        .expect_err("404 is not successful");
    server.await.expect("server task completes");
    error
}

#[tokio::test]
async fn gateway_response_retains_non_success_status_without_retaining_body() {
    for status in [400, 404, 429, 500, 503] {
        let error = request_status(status).await;
        assert!(matches!(
            error,
            ServerError::GatewayStatus {
                status: actual_status
            } if actual_status.as_u16() == status
        ));
        assert!(!error.to_string().contains("secret-details"));
    }
}
