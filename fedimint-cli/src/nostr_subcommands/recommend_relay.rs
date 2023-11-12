use clap::Args;
use nostr_sdk::{EventBuilder, Result, UnsignedEvent};

#[derive(Args, Debug, Clone)]
pub struct RecommendRelaySubCommand {
    /// Relay URL to recommend
    #[arg(short, long)]
    url: String,
}
impl RecommendRelaySubCommand {
    pub fn url(self) -> String {
        self.url
    }
}
