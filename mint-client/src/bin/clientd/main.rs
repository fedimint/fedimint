use tide;
use mint_client::{MintClient};
use std::sync::Arc;
use std::path::PathBuf;
use minimint::config::{load_from_file, ClientConfig};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use tide::Response;
use tracing::info;
use bitcoin_hashes::hex::ToHex;

/*
1. Spawn RPC server Y
2. Process requests with the Client struct (shared ownership ?) :
    2.1 parse req json -> call client command TODO
    parse json to enum and then match ?
3. Implement reissue first and test with cURL
 */

/*
#[derive(Debug, Deserialize)]
struct Config {
    client: ClientConfig,
}
*/
#[derive(Clone)]
pub struct State {
    mint_client: Arc<MintClient>,
}

#[derive(StructOpt)]
struct Opts {
    workdir: PathBuf,
}

#[tokio::main]
async fn main() -> tide::Result<()>{
    //Instanciate CLient
    let opts: Opts = StructOpt::from_args();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    //why use Config in ln-gateway
    let cfg: ClientConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();
    //why did ln-gateway use client.cfg ? (not in config.json)
    let client = MintClient::new(cfg, Arc::new(db), Default::default()); //Why Arc ?

    //Spawn server
    let state = State {
        mint_client: Arc::new(client),
    };

    let mut app = tide::with_state(state);
    /*
        As far as I understood use with_state is needed to get the client into scope or to share it respectively
        Arc is used because we can use reference-counted smart pointers (multi-threaded)
        (thx https://www.sitepoint.com/rust-global-variables/)
     */
    app.at("/fetch").post(fetch);
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}

async fn fetch(mut req: tide::Request<State>) -> tide::Result{
    let State {
        ref mint_client,
    } = req.state();
    for id in mint_client.fetch_all_coins().await.unwrap() {
        info!("Fetched coins from issuance {}", id.to_hex());
    }
    Ok(Response::new(200))
}