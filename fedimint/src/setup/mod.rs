mod configgen;

use crate::setup::configgen::configgen;
use askama::Template;
use axum::extract::{Extension, Form};
use axum::response::Redirect;
use axum::{
    routing::{get, post},
    Router,
};
use http::StatusCode;
use rand::rngs::OsRng;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct Peer {
    name: String,
    connection_string: String,
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate {
    connection_string: String,
}

async fn home(Extension(state): Extension<MutableState>) -> HomeTemplate {
    HomeTemplate {
        connection_string: state.read().unwrap().connection_string.clone(),
    }
}

#[derive(Template)]
#[template(path = "generate.html")]
struct GenerateTemplate {
    peers: Vec<Peer>,
}

#[derive(Deserialize, Debug)]
struct State {
    peers: Vec<Peer>,
    running: bool, // this should probably be handle or something ...
    out_dir: PathBuf,
    connection_string: String,
}

async fn generate(Extension(state): Extension<MutableState>) -> GenerateTemplate {
    GenerateTemplate {
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
    println!("TODO: run fedimintd!");

    state.running = true;
    Ok(Redirect::to("/dashboard".parse().unwrap()))
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate;

async fn dashboard() -> DashboardTemplate {
    DashboardTemplate
}

type MutableState = Arc<RwLock<State>>;

pub async fn run_setup(out_dir: PathBuf, port: u16) {
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
    }));

    let app = Router::new()
        .route("/", get(home))
        .route("/guardians", get(generate).post(add_guardian))
        .route("/start-federation", post(start_federation))
        .route("/dashboard", get(dashboard))
        .layer(Extension(state));

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
