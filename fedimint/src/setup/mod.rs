mod configgen;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use askama::Template;
use axum::extract::{Extension, Form};
use axum::response::Redirect;
use axum::{
    routing::{get, post},
    Router,
};
use fedimint_core::config::load_from_file;
use http::StatusCode;
use qrcode_generator::QrCodeEcc;
use rand::rngs::OsRng;
use serde::Deserialize;
use tokio::sync::mpsc::Sender;

use crate::setup::configgen::configgen;
use mint_client::api::WsFederationConnect;
use mint_client::UserClientConfig;

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct Peer {
    name: String,
    connection_string: String,
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate {
    running: bool,
    connection_string: String,
}

async fn home(Extension(state): Extension<MutableState>) -> HomeTemplate {
    HomeTemplate {
        running: state.read().unwrap().running.clone(),
        connection_string: state.read().unwrap().connection_string.clone(),
    }
}

#[derive(Template)]
#[template(path = "guardians.html")]
struct GuardiansTemplate {
    peers: Vec<Peer>,
}

async fn guardians(Extension(state): Extension<MutableState>) -> GuardiansTemplate {
    GuardiansTemplate {
        peers: state.read().unwrap().peers.clone(),
    }
}

async fn add_guardian(
    Extension(state): Extension<MutableState>,
    Form(input): Form<Peer>,
) -> Result<Redirect, (StatusCode, String)> {
    state.write().unwrap().peers.push(Peer {
        connection_string: input.connection_string,
        name: input.name,
    });
    Ok(Redirect::to("/guardians".parse().unwrap()))
}

async fn start_federation(
    Extension(state): Extension<MutableState>,
) -> Result<Redirect, (StatusCode, String)> {
    let mut state = state.write().unwrap();
    configgen(state.out_dir.clone(), state.peers.clone().len() as u16);
    println!("generated configs");

    // FIXME: don't hardcode. this needs to be able to find this guardian's db path.
    let server_filename = "server-0";
    let cfg_path = state.out_dir.join(format!("{}.json", server_filename));
    if Path::new(&cfg_path).is_file() {
        let db_path = state.out_dir.join(format!("{}.db", server_filename));
        state.sender.send((cfg_path, db_path)); // FIXME: it won't let me await this
        state.running = true;
    }
    Ok(Redirect::to("/".parse().unwrap()))
}

async fn qr(Extension(state): Extension<MutableState>) -> impl axum::response::IntoResponse {
    let client_cfg_path = state.read().unwrap().out_dir.join("client.json");
    let cfg: UserClientConfig = load_from_file(&client_cfg_path);
    let connect_info = WsFederationConnect::from(cfg.as_ref());
    let png_bytes: Vec<u8> = qrcode_generator::to_png_to_vec(
        serde_json::to_string(&connect_info).unwrap(),
        QrCodeEcc::Low,
        1024,
    )
    .unwrap();
    (
        axum::response::Headers([(axum::http::header::CONTENT_TYPE, "image/png")]),
        png_bytes,
    )
}

#[derive(Debug)]
struct State {
    peers: Vec<Peer>,
    running: bool,
    out_dir: PathBuf,
    connection_string: String,
    sender: Sender<(PathBuf, PathBuf)>,
}
type MutableState = Arc<RwLock<State>>;

pub async fn run_setup(out_dir: PathBuf, port: u16, sender: Sender<(PathBuf, PathBuf)>) {
    let mut rng = OsRng::new().unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (_, pubkey) = secp.generate_keypair(&mut rng);
    let our_ip = "127.0.0.1"; // TODO: get our actual IP
    let connection_string = format!("{}@{}:{}", pubkey, our_ip, port);

    let state = Arc::new(RwLock::new(State {
        peers: vec![],
        running: false,
        out_dir,
        connection_string,
        sender,
    }));

    let app = Router::new()
        .route("/", get(home))
        .route("/guardians", get(guardians).post(add_guardian))
        .route("/start-federation", post(start_federation))
        .route("/qr", get(qr))
        .layer(Extension(state));

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
