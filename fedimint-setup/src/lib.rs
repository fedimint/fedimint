use askama::Template;
use axum::{routing::get, Router};

#[derive(Template)]
#[template(path = "hello.html")]
struct HelloTemplate<'a> {
    name: &'a str,
}

async fn hello() -> HelloTemplate<'static> {
    HelloTemplate { name: "world" }
}
pub async fn run_setup() {
    // build our application with a single route
    // let app = Router::new().route("/", get(|| async { "Hello, World!" }));
    let app = Router::new().route("/", get(hello));

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
