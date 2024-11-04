use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_client_rpc::RpcGlobalState;
use fedimint_core::{apply, async_trait_maybe_send};

struct StdoutResponseHandler;

impl fedimint_client_rpc::RpcResponseHandler for StdoutResponseHandler {
    fn handle_response(&self, response: fedimint_client_rpc::RpcResponse) {
        let response_json = serde_json::to_string(&response).unwrap();
        println!("{response_json}");
    }
}

struct RocksDbFactory {
    base_dir: PathBuf,
}

#[apply(async_trait_maybe_send!)]
impl fedimint_client_rpc::DatabaseFactory for RocksDbFactory {
    async fn create_database(&self, name: &str) -> anyhow::Result<fedimint_core::db::Database> {
        let path = self.base_dir.join(format!("{name}.db"));
        let db = fedimint_rocksdb::RocksDb::open(path)?;
        Ok(db.into())
    }
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <database-dir>", args[0]);
        std::process::exit(1);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio");

    let rpc_state = Arc::new(RpcGlobalState::new(RocksDbFactory {
        base_dir: PathBuf::from(&args[1]),
    }));

    let stdin = io::stdin();
    let handle = stdin.lock();

    for line in handle.lines() {
        match line {
            Ok(input) => {
                let inner = rpc_state.clone();
                let Ok(request) = serde_json::from_str(&input) else {
                    eprintln!("Failed to parse JSON request");
                    continue;
                };
                let handled = inner.handle_rpc(request, StdoutResponseHandler);
                if let Some(task) = handled.task {
                    rt.spawn(task);
                }
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }
}
