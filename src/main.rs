#![feature(async_closure)]

use futures::future::try_join_all;
use futures::StreamExt;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;
use tokio_stream::iter;

mod config;

#[tokio::main]
async fn main() {
    let cfg: config::Config = StructOpt::from_args();

    let listener = spawn(await_peers(cfg.get_my_port(), cfg.get_incoming_count()));

    let out_conns = try_join_all(
        (cfg.identity..cfg.federation_size)
            .map(|peer| TcpStream::connect(("127.0.0.1", cfg.base_port + peer))),
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
}

async fn await_peers(port: u16, num_awaited: u16) -> Result<Vec<TcpStream>, std::io::Error> {
    let mut listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("Couldn't bind to port.");

    let peers = (0..num_awaited).map(|_| listener.accept());
    Ok(try_join_all(peers)
        .await?
        .into_iter()
        .map(|(socket, _)| socket)
        .collect())
}
