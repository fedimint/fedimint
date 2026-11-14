use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fedimint_core::util::SafeUrl;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tokio::task::JoinHandle;

use super::{BitcoindClientWithFallback, scripted_endpoint};

/// A complete getblockchaininfo reply exercises bitcoincore-rpc
/// deserialization.
fn chain_info(height: u64, ibd: bool) -> String {
    serde_json::json!({
        "chain": "regtest",
        "blocks": height,
        "headers": 100,
        "bestblockhash": "00".repeat(32),
        "difficulty": 1,
        "mediantime": 0,
        "verificationprogress": 0.5,
        "initialblockdownload": ibd,
        "chainwork": "00",
        "size_on_disk": 0,
        "pruned": false,
        "warnings": "",
    })
    .to_string()
}

/// bitcoincore-rpc queries Core's version to decode historical softfork fields.
async fn core_endpoint(
    responses: Vec<(&'static str, String)>,
) -> (SafeUrl, Arc<AtomicUsize>, JoinHandle<()>) {
    let mut script = Vec::new();
    for (method, response) in responses {
        let needs_version = method == "getblockchaininfo" && response != "failure";
        script.push((method, response));
        if needs_version {
            script.push(("getnetworkinfo", r#"{"version":290000}"#.to_owned()));
        }
    }
    scripted_endpoint(true, script).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_count_fallback() {
    for (primary, fallback, expected, fallback_calls) in [
        // A responsive IBD Core must not mask a usable fallback count.
        (chain_info(0, true), "100", Ok(101), 1),
        (chain_info(9, true), "0", Ok(1), 1),
        // Never accept an IBD count when fallback is unavailable.
        (
            chain_info(9, true),
            "failure",
            Err("Bitcoind is in initial block download"),
            1,
        ),
        // Non-IBD Core stays first even when Esplora advertises a higher tip.
        (chain_info(0, false), "100", Ok(1), 0),
        (chain_info(9, false), "failure", Ok(10), 0),
        ("failure".to_owned(), "100", Ok(101), 1),
        // Invalid blockchain info must also use fallback, not latch completion.
        ("{}".to_owned(), "100", Ok(101), 1),
        (
            "failure".to_owned(),
            "failure",
            Err("primary RPC failure"),
            1,
        ),
    ] {
        let expected_primary_calls = if primary == "failure" { 1 } else { 2 };
        let (primary_url, primary_calls, primary_server) =
            core_endpoint(vec![("getblockchaininfo", primary)]).await;
        let (fallback_url, calls, fallback_server) =
            scripted_endpoint(false, vec![("/blocks/tip/height", fallback.to_owned())]).await;
        let rpc = BitcoindClientWithFallback::new(
            "user".to_owned(),
            "password".to_owned(),
            &primary_url,
            &fallback_url,
        )
        .unwrap();
        // Construction must remain synchronous and must not query endpoints.
        assert_eq!(primary_calls.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let result = tokio::time::timeout(Duration::from_secs(5), rpc.get_block_count())
            .await
            .unwrap();
        match expected {
            Ok(count) => assert_eq!(result.unwrap(), count),
            Err(message) => assert!(result.unwrap_err().to_string().contains(message)),
        }
        assert_eq!(primary_calls.load(Ordering::SeqCst), expected_primary_calls);
        assert_eq!(calls.load(Ordering::SeqCst), fallback_calls);
        primary_server.abort();
        fallback_server.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_completion_is_remembered_but_errors_still_fall_back() {
    let (primary_url, primary_calls, primary_server) = core_endpoint(vec![
        ("getblockchaininfo", chain_info(9, true)),
        ("getblockchaininfo", "failure".to_owned()),
        ("getblockchaininfo", chain_info(19, true)),
        ("getblockchaininfo", chain_info(29, false)),
        ("getblockcount", "30".to_owned()),
        ("getblockcount", "failure".to_owned()),
        ("getblockcount", "failure".to_owned()),
        ("getblockcount", "31".to_owned()),
    ])
    .await;
    let (fallback_url, calls, fallback_server) = scripted_endpoint(
        false,
        ["100", "100", "100", "100", "failure"]
            .into_iter()
            .map(|reply| ("/blocks/tip/height", reply.to_owned()))
            .collect(),
    )
    .await;
    let rpc = BitcoindClientWithFallback::new(
        "user".to_owned(),
        "password".to_owned(),
        &primary_url,
        &fallback_url,
    )
    .unwrap();
    // Recheck IBD after both IBD and RPC errors. After false, ordinary reads
    // resume without consulting getblockchaininfo or comparing endpoint tips.
    for (expected, fallback_calls) in [
        (Ok(101), 1),
        (Ok(101), 2),
        (Ok(101), 3),
        (Ok(30), 3),
        (Ok(31), 3),
        (Ok(101), 4),
        (Err("primary RPC failure"), 5),
        (Ok(32), 5),
    ] {
        let result = tokio::time::timeout(Duration::from_secs(5), rpc.get_block_count())
            .await
            .unwrap();
        match expected {
            Ok(count) => assert_eq!(result.unwrap(), count),
            Err(message) => assert!(result.unwrap_err().to_string().contains(message)),
        }
        assert_eq!(calls.load(Ordering::SeqCst), fallback_calls);
    }
    assert_eq!(primary_calls.load(Ordering::SeqCst), 11);
    primary_server.abort();
    fallback_server.abort();
}
