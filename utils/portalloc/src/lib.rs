//! A simple port allocation library for Fedimint tests

// from https://github.com/one-chain-labs/onechain/blob/580efae3893e7ac79dbcc5f401699642e9834d67/crates/sui-pg-temp-db/src/lib.rs#L288-L300

use tokio::net::{TcpListener, TcpStream};

/// Allocate a single available port
///
/// Return an ephemeral, available port. On unix systems, the port returned will
/// be in the TIME_WAIT state ensuring that the OS won't hand out this port for
/// some grace period. Callers should be able to bind to this port given they
/// use SO_REUSEADDR.
pub async fn port_alloc() -> u16 {
    const MAX_PORT_RETRIES: u32 = 1000;

    for _ in 0..MAX_PORT_RETRIES {
        if let Ok(port) = get_ephemeral_port().await {
            return port;
        }
    }

    panic!("Error: could not find an available port");
}

async fn get_ephemeral_port() -> std::io::Result<u16> {
    // Request a random available port from the OS
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;

    // Create and accept a connection (which we'll promptly drop) in order to force
    // the port into the TIME_WAIT state, ensuring that the port will be
    // reserved from some limited amount of time (roughly 60s on some Linux
    // systems)
    let _stream = TcpStream::connect(addr).await?;
    let (_socket, _) = listener.accept().await?;

    Ok(addr.port())
}

/// Allocate multiple available ports
///
/// Returns a vector of `count` available ports. Each port is independently
/// verified to be available.
pub async fn port_alloc_multi(count: usize) -> Vec<u16> {
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
        ports.push(port_alloc().await);
    }
    ports
}
