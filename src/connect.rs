use crate::config::Config;
use futures::future::try_join_all;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;
use tokio::time::sleep;
use tracing::{debug, error, info};

pub async fn connect_to_all(cfg: &Config) -> HashMap<u16, TcpStream> {
    info!("Starting mint {}", cfg.identity);
    let listener = spawn(await_peers(cfg.get_my_port(), cfg.get_incoming_count()));

    sleep(Duration::from_millis(5000)).await;

    debug!("Beginning to connect to peers");

    let out_conns = try_join_all(
        (cfg.identity + 1..cfg.federation_size).map(|peer| connect_to_peer(cfg.base_port, peer)),
    )
    .await
    .expect("Failed to connect to peer");

    let in_conns = listener
        .await
        .unwrap()
        .expect("Failed to accept connection");

    let identity = &cfg.identity;
    let handshakes = out_conns.into_iter().chain(in_conns).map(
        async move |mut stream| -> Result<_, std::io::Error> {
            stream.write_u16(*identity).await?;
            let peer = stream.read_u16().await?;
            Ok((peer, stream))
        },
    );

    let peers = try_join_all(handshakes)
        .await
        .expect("Error during peer handshakes")
        .into_iter()
        .collect::<HashMap<_, _>>();

    info!("Successfully connected to all peers");

    peers
}

async fn await_peers(port: u16, num_awaited: u16) -> Result<Vec<TcpStream>, std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("Couldn't bind to port.");

    debug!("Listening for incoming connections on port {}", port);

    let peers = (0..num_awaited).map(|_| listener.accept());
    Ok(try_join_all(peers)
        .await?
        .into_iter()
        .map(|(socket, _)| socket)
        .collect())
}

async fn connect_to_peer(base_port: u16, peer: u16) -> Result<TcpStream, std::io::Error> {
    debug!("Connecting to peer {}", peer);
    let res = TcpStream::connect(("127.0.0.1", base_port + peer)).await;
    if res.is_err() {
        error!("Could not connect to peer {}", peer);
    }
    res
}
