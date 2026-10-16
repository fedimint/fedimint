use fedimint_core::runtime::spawn;
use fedimint_core::util::SafeUrl;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::BitcoindClient;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_uses_core_flag_not_nearly_complete_verification_progress() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url: SafeUrl = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = spawn("core-test-http", async move {
        let info = r#"{"result":{
            "chain":"main","blocks":100,"headers":200,
            "bestblockhash":"0000000000000000000000000000000000000000000000000000000000000000",
            "difficulty":1,"mediantime":0,"verificationprogress":0.9999999,
            "initialblockdownload":true,"chainwork":"00","size_on_disk":0,
            "pruned":false,"warnings":""
        },"error":null,"id":1}"#;
        for (method, response) in [
            ("getblockchaininfo", info),
            (
                "getnetworkinfo",
                r#"{"result":{"version":280000},"error":null,"id":2}"#,
            ),
        ] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !String::from_utf8_lossy(&request).contains(method) {
                let mut chunk = [0; 4096];
                let len = socket.read(&mut chunk).await.unwrap();
                assert_ne!(len, 0, "request ended before method");
                request.extend_from_slice(&chunk[..len]);
            }
            socket.write_all(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        ).as_bytes()).await.unwrap();
        }
    });
    let rpc = BitcoindClient::new("user".to_owned(), "pass".to_owned(), &url).unwrap();
    assert_eq!(
        rpc.get_block_count_and_initial_block_download()
            .await
            .unwrap(),
        (101, true)
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn already_in_chain_is_success() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url: SafeUrl = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = spawn("core-test-http", async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !String::from_utf8_lossy(&request).contains("sendrawtransaction") {
            let mut chunk = [0; 4096];
            let len = socket.read(&mut chunk).await.unwrap();
            assert_ne!(len, 0, "request ended before method");
            request.extend_from_slice(&chunk[..len]);
        }
        let response = r#"{"result":null,"error":{"code":-27,"message":"Transaction already in block chain"},"id":1}"#;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let rpc = BitcoindClient::new("user".to_owned(), "pass".to_owned(), &url).unwrap();
    rpc.submit_transaction(
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin)
            .txdata
            .remove(0),
    )
    .await
    .unwrap();
    server.await.unwrap();
}
