use clap::Parser;
use minimint_api::PeerId;
use mint_client::api::WsFederationApi;

#[derive(Parser)]
struct ApiCall {
    url: String,
    method: String,
    #[clap(default_value = "null")]
    arg: String,
}

#[tokio::main]
async fn main() {
    let call = ApiCall::parse();
    let arg: serde_json::Value = serde_json::from_str(&call.arg).unwrap();
    let api = WsFederationApi::new(0, vec![(PeerId::from(0), call.url)]);
    let response: serde_json::Value = api.request(&call.method, arg).await.unwrap();
    let formatted = serde_json::to_string_pretty(&response).unwrap();
    print!("{}", formatted);
}
