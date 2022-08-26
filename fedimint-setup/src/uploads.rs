use askama::Template;
use axum::{routing::get, Router};

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate;

async fn home() -> HomeTemplate {
    HomeTemplate
}

#[derive(Template)]
#[template(path = "generate.html")]
struct GenerateTemplate;

async fn generate() -> GenerateTemplate {
    GenerateTemplate
}

#[derive(Template)]
#[template(path = "upload.html")]
struct UploadTemplate;

async fn upload() -> UploadTemplate {
    UploadTemplate
}

pub async fn run_setup() {
    // build our application with a single route
    // let app = Router::new().route("/", get(|| async { "Hello, World!" }));
    let app = Router::new()
        .route("/", get(home))
        .route("/generate", get(generate))
        .route("/upload", get(upload));

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
