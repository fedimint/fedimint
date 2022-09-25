use clap::{Parser, Subcommand};
use fedimint_api::PeerId;
use mint_client::api::WsFederationApi;
use mint_client::query::TrustAllPeers;
use url::Url;

#[derive(Parser)]
#[clap(version)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the latest git commit hash this bin. was build with
    VersionHash,
    ApiCall {
        /// The url to use for the api call
        url: Url,
        /// The rpc method
        method: String,
        /// Args that will be serialized and send with the request
        #[clap(default_value = "null")]
        arg: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::VersionHash => {
            println!("{}", env!("GIT_HASH"));
        }
        Commands::ApiCall { url, method, arg } => {
            let arg: serde_json::Value = serde_json::from_str(&arg).unwrap();
            let api = WsFederationApi::new(0, vec![(PeerId::from(0), url)]);
            let response: serde_json::Value =
                api.request(&method, arg, TrustAllPeers).await.unwrap();
            let formatted = serde_json::to_string_pretty(&response).unwrap();
            print!("{}", formatted);
        }
    }
}
