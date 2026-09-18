use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use fedimint_core::util::SafeUrl;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{EsploraClient, validate_block};

#[test]
fn accepts_matching_block() {
    let block = genesis_block(Network::Bitcoin);
    assert_eq!(
        validate_block(block.clone(), &block.block_hash()).unwrap(),
        block
    );
}

#[test]
fn rejects_different_header() {
    let block = genesis_block(Network::Bitcoin);
    let requested = genesis_block(Network::Testnet).block_hash();
    assert!(validate_block(block, &requested).is_err());
}

#[test]
fn rejects_modified_transactions_under_matching_header() {
    let mut block = genesis_block(Network::Bitcoin);
    let requested = block.block_hash();
    block.txdata[0].output[0].value = bitcoin::Amount::ZERO;
    assert!(validate_block(block, &requested).is_err());
}

#[test]
fn rejects_empty_transactions_under_matching_header() {
    let mut block = genesis_block(Network::Bitcoin);
    let requested = block.block_hash();
    block.txdata.clear();
    assert!(validate_block(block, &requested).is_err());
}

#[test]
fn rejects_merkle_mutation() {
    let mut block = genesis_block(Network::Bitcoin);
    let mut second = block.txdata[0].clone();
    second.output[0].value = bitcoin::Amount::from_sat(1);
    let mut third = second.clone();
    third.output[0].value = bitcoin::Amount::from_sat(2);
    block.txdata.extend([second, third.clone()]);
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let requested = block.block_hash();
    assert!(validate_block(block.clone(), &requested).is_ok());
    block.txdata.push(third);
    assert!(block.check_merkle_root(), "mutation preserves merkle root");
    assert!(validate_block(block, &requested).is_err());
}

/// Exercise the HTTP adapter, not only its validation helper.
#[tokio::test]
async fn rejects_malformed_http_block_responses() {
    let valid = genesis_block(Network::Bitcoin);
    let requested = valid.block_hash();
    let mut modified = valid.clone();
    modified.txdata.clear();
    for (block, accepted) in [
        (valid, true),
        (genesis_block(Network::Testnet), false),
        (modified, false),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: SafeUrl = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let response = bitcoin::consensus::serialize(&block);
        let server = fedimint_core::runtime::spawn("esplora-test-http", async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0; 4096];
                let len = socket.read(&mut chunk).await.unwrap();
                assert_ne!(len, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..len]);
            }
            assert!(
                String::from_utf8_lossy(&request)
                    .starts_with(&format!("GET /block/{requested}/raw "))
            );
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&response).await.unwrap();
        });
        let result = EsploraClient::new(&url)
            .unwrap()
            .get_block(&requested)
            .await;
        assert_eq!(result.is_ok(), accepted, "{result:?}");
        server.await.unwrap();
    }
}
