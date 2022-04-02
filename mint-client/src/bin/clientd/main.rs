use tide::{Request, Response};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct State();

#[tokio::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let state = State();
    let mut app = tide::with_state(state);

    app.at("/info").post(info);
    app.at("/spend").post(spend);
    app.at("/reissue").post(reissue);
    app.at("/reissue_validate").post(reissue_validate);
    app.at("/pending").post(pending);
    app.at("/events").post(events);
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}
async fn info(_req: Request<State>) -> tide::Result {
    let mut res = Response::new(200);
    res.set_body(String::from("info"));
    Ok(res)
}
async fn spend(_req: Request<State>) -> tide::Result {
    let mut res = Response::new(200);
    res.set_body(String::from("spend"));
    Ok(res)
}
async fn reissue(_req: Request<State>) -> tide::Result {
    let mut res = Response::new(200);
    res.set_body(String::from("reissue"));
    Ok(res)
}
async fn reissue_validate(_req: Request<State>) -> tide::Result {
    let mut res = Response::new(200);
    res.set_body(String::from("reissue_validate"));
    Ok(res)
}
async fn pending(_req: Request<State>) -> tide::Result {
    let mut res = Response::new(200);
    res.set_body(String::from("pending"));
    Ok(res)
}
async fn events(_req: Request<State>) -> tide::Result {
    let mut res = Response::new(200);
    res.set_body(String::from("events"));
    Ok(res)
}
