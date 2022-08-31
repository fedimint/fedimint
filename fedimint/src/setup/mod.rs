use askama::Template;
use axum::extract::{Extension, Form};
use axum::response::Redirect;
use axum::{
    routing::{get, post},
    Router,
};
use http::StatusCode;
use serde::Deserialize;
use std::sync::{Arc, RwLock};

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct Peer {
    name: String,
    connection_string: String,
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate;

async fn home() -> HomeTemplate {
    HomeTemplate
}

#[derive(Template)]
#[template(path = "generate.html")]
struct GenerateTemplate {
    peers: Vec<Peer>,
}

#[derive(Deserialize, Debug)]
struct State {
    peers: Vec<Peer>,
    configs: Vec<String>,
    running: bool, // this should probably be handle or something ...
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
    dbg!(&state);
    dbg!(&input);
    state.write().unwrap().peers.push(Peer {
        connection_string: input.connection_string,
        name: input.name,
    });
    Ok(Redirect::to("/guardians".parse().unwrap()))
}

async fn generate_configs(
    Extension(state): Extension<MutableState>,
) -> Result<Redirect, (StatusCode, String)> {
    println!("todo: actually generate configs");
    let mut state = state.write().unwrap();
    state.configs = state
        .peers
        .iter()
        .enumerate()
        .map(|(i, peer)| format!("config for peer {}", i))
        .collect::<Vec<String>>();
    Ok(Redirect::to("/configs".parse().unwrap()))
}

#[derive(Template)]
#[template(path = "configs.html")]
struct ConfigsTemplate {
    pairs: Vec<(Peer, String)>,
}

async fn configs(Extension(state): Extension<MutableState>) -> ConfigsTemplate {
    let s = state.read().unwrap();
    let pairs = s
        .peers
        .clone()
        .into_iter()
        .zip(s.configs.clone().into_iter())
        .collect();
    ConfigsTemplate { pairs }
}

async fn start_federation(
    Extension(state): Extension<MutableState>,
) -> Result<Redirect, (StatusCode, String)> {
    Ok(Redirect::to("/dashboard".parse().unwrap()))
}

#[derive(Template)]
#[template(path = "upload.html")]
struct UploadTemplate;

async fn upload() -> UploadTemplate {
    UploadTemplate
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate;

async fn dashboard() -> DashboardTemplate {
    DashboardTemplate
}

type MutableState = Arc<RwLock<State>>;

pub async fn run_setup() {
    // build our application with a single route
    // let app = Router::new().route("/", get(|| async { "Hello, World!" }));
    let state = Arc::new(RwLock::new(State {
        peers: vec![],
        configs: vec![],
        running: false,
    }));

    let app = Router::new()
        .route("/", get(home))
        .route("/guardians", get(generate).post(add_guardian))
        .route("/generate-configs", post(generate_configs))
        .route("/configs", get(configs))
        .route("/start-federation", post(start_federation))
        .route("/dashboard", get(dashboard))
        .route("/upload", get(upload))
        .layer(Extension(state));

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
