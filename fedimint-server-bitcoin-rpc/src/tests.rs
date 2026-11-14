use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fedimint_core::util::SafeUrl;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::task::JoinHandle;

use super::BitcoindClientWithFallback;

/// Exercise the real Core and Esplora adapters without external services.
async fn endpoint(
    core: bool,
    response: &'static str,
) -> (SafeUrl, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = calls.clone();
    let server = fedimint_core::runtime::spawn("fee-estimate-test-http", async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            let header_end = loop {
                let len = socket.read(&mut chunk).await.unwrap();
                assert_ne!(len, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..len]);
                assert!(request.len() <= 64 * 1024);
                if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            assert!(content_length <= 64 * 1024);
            assert!(headers.starts_with(if core {
                "POST / "
            } else {
                "GET /fee-estimates "
            }));
            while request.len() < header_end + content_length {
                let len = socket.read(&mut chunk).await.unwrap();
                assert_ne!(len, 0, "request ended before body");
                request.extend_from_slice(&chunk[..len]);
            }
            let (status, body) = if core {
                let request: serde_json::Value =
                    serde_json::from_slice(&request[header_end..]).unwrap();
                assert_eq!(request["method"], "estimatesmartfee");
                assert_eq!(request["params"], serde_json::json!([1, "CONSERVATIVE"]));
                (
                    "200 OK",
                    if response == "failure" {
                        serde_json::json!({
                            "result": null,
                            "error": {"code": -1, "message": "primary fee failure"},
                            "id": request["id"],
                        })
                    } else {
                        serde_json::json!({
                            "result": serde_json::from_str::<serde_json::Value>(response).unwrap(),
                            "error": null,
                            "id": request["id"],
                        })
                    }
                    .to_string(),
                )
            } else if response == "failure" {
                ("400 Bad Request", "{}".to_owned())
            } else {
                ("200 OK", response.to_owned())
            };
            server_calls.fetch_add(1, Ordering::SeqCst);
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    (url, calls, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hybrid_fee_estimate_fallback() {
    // Core's successful response can omit feerate during IBD or while collecting
    // fee history. An empty successful Esplora response retains its existing
    // 1 sat/vB policy, unlike a failed Esplora request.
    for (primary, fallback, expected, fallback_calls) in [
        (
            r#"{"feerate":0.00002,"blocks":1}"#,
            r#"{"1":3}"#,
            Ok(Some(2000)),
            0,
        ),
        (
            r#"{"errors":["Insufficient data"],"blocks":0}"#,
            r#"{"1":3}"#,
            Ok(Some(3000)),
            1,
        ),
        (r#"{"blocks":0}"#, "{}", Ok(Some(1000)), 1),
        (r#"{"blocks":0}"#, "failure", Ok(None), 1),
        ("failure", r#"{"1":3}"#, Ok(Some(3000)), 1),
        ("failure", "{}", Ok(Some(1000)), 1),
        ("failure", "failure", Err("primary fee failure"), 1),
    ] {
        let (primary_url, primary_calls, primary_server) = endpoint(true, primary).await;
        let (fallback_url, calls, fallback_server) = endpoint(false, fallback).await;
        let rpc = BitcoindClientWithFallback::new(
            "user".to_owned(),
            "password".to_owned(),
            &primary_url,
            &fallback_url,
        )
        .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), rpc.get_feerate())
            .await
            .unwrap();
        match expected {
            Ok(feerate) => assert_eq!(result.unwrap().map(|f| f.sats_per_kvb), feerate),
            Err(message) => assert!(result.unwrap_err().to_string().contains(message)),
        }
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), fallback_calls);
        primary_server.abort();
        fallback_server.abort();
    }
}
