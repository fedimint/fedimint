use clap::Parser;
use fedimint_api::PeerId;
use mint_client::api::WsFederationApi;
use mint_client::query::TrustAllPeers;
use url::Url;

#[derive(Parser)]
struct ApiCall {
    url: Url,
    method: String,
    #[clap(default_value = "null")]
    arg: String,
}

#[tokio::main]
async fn main() {
    let call = ApiCall::parse();
    let arg: serde_json::Value = serde_json::from_str(&call.arg).unwrap();
    let api = WsFederationApi::new(0, vec![(PeerId::from(0), call.url)]);
    let response: serde_json::Value = api.request(&call.method, arg, TrustAllPeers).await.unwrap();
    let formatted = serde_json::to_string_pretty(&response).unwrap();
    print!("{}", formatted);
}
