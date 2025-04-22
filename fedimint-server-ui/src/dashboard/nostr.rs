use std::collections::BTreeMap;
use std::str::FromStr;

use axum::Form;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::CookieJar;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use fedimint_wallet_server::Wallet;
use maud::{Markup, html};
use nostr_sdk::prelude::Keys;
use nostr_sdk::{
    Alphabet, Client, EventBuilder, JsonUtil, Kind, SingleLetterTag, Tag, TagKind, ToBech32,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::{AuthState, LOGIN_ROUTE, ROOT_ROUTE, check_auth};

pub const NOSTR_BROADCAST: &str = "/nostr/broadcast";

pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.nostr.band",
    "wss://nostr-pub.wellorder.net",
    "wss://relay.plebstr.com",
    "wss://relayer.fiatjaf.com",
    "wss://nostr-01.bolt.observer",
    "wss://nostr.bitcoiner.social",
    "wss://relay.nostr.info",
    "wss://relay.damus.io",
];

#[derive(Debug)]
pub struct NostrForm {
    pub about: Option<String>,
    pub picture: Option<SafeUrl>,
    pub relays: Vec<String>,
}

impl<'de> Deserialize<'de> for NostrForm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map: BTreeMap<String, String> = BTreeMap::deserialize(deserializer)?;
        let about = map.get("about").and_then(|s| {
            if s.trim().is_empty() {
                None
            } else {
                Some(s.clone())
            }
        });

        let picture = map.get("picture").and_then(|s| SafeUrl::parse(s).ok());

        let relays = map
            .get("relays")
            .map(|s| {
                s.lines()
                    .map(|line| line.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(NostrForm {
            about,
            picture,
            relays,
        })
    }
}

pub async fn render() -> Markup {
    let relays = DEFAULT_RELAYS.join("\n");
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" {
                img src="/assets/nostr.png" class="logo" style="height: 30px; margin-right: 10px;";
                "NIP87: Broadcast Federation via Nostr"
            }

            div class="text-center p-4" {
                p {
                    "Advertise your federation using Nostr! Fill in the following fields to provide details about your federation, such as a description and a valid picture URL. Once submitted, the information will be broadcasted using "
                    a href="https://github.com/nostr-protocol/nips/pull/1110" target="_blank" { "NIP87" }
                    " and will be discoverable to users."
                }
            }

            div class="card-body" {
                form action=(NOSTR_BROADCAST) method="post" {
                    div class="mb-3" {
                        label for="about" class="form-label" { "About" }
                        input type="text" class="form-control" id="about" name="about" placeholder="Enter federation description";
                    }
                    div class="mb-3" {
                        label for="picture" class="form-label" { "Picture" }
                        input type="url" class="form-control" id="picture" name="picture" placeholder="Enter picture URL";
                    }
                    div class="mb-3" {
                        label for="relays" class="form-label" { "Relays" }
                        textarea class="form-control" id="relays" name="relays" rows="8" {
                            (relays)
                        }
                    }
                    button type="submit" class="btn btn-primary" { "Broadcast to Nostr" }
                }
            }
        }
    }
}

pub async fn post_broadcast(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(form): Form<NostrForm>,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to(LOGIN_ROUTE).into_response();
    }

    let federation_name = state.api.federation_name().await;
    let invite = state.api.federation_invite_code().await;
    let invite_code = InviteCode::from_str(&invite).expect("Could not parse invite code");
    let modules = state.api.supported_modules();
    let picture = form.picture;
    let about = form.about;
    let relays = form.relays;
    let wallet = state
        .api
        .get_module::<fedimint_wallet_server::Wallet>()
        .expect("Could not get wallet");

    match broadcast_federation_announcement(
        federation_name,
        invite_code,
        wallet,
        modules,
        picture,
        about,
        relays,
    )
    .await
    {
        Ok(event_id) => {
            let bech32 = event_id.to_bech32().expect("Could not convert to bech32");
            info!(event_id = %bech32, "Successfully broadcasted event");
            Redirect::to(format!("https://nostr.at/{bech32}").as_str()).into_response()
        }
        Err(e) => {
            warn!(?e, "Error broadcasting event");
            Redirect::to(ROOT_ROUTE).into_response()
        }
    }
}

pub async fn broadcast_federation_announcement(
    federation_name: String,
    invite_code: InviteCode,
    wallet: &Wallet,
    modules: Vec<String>,
    picture: Option<SafeUrl>,
    about: Option<String>,
    relays: Vec<String>,
) -> anyhow::Result<nostr_sdk::EventId> {
    let federation_id = invite_code.federation_id();
    let network = wallet.network_ui();

    let mut metadata = nostr_sdk::Metadata::default();
    metadata = metadata.name(federation_name);
    if let Some(pic) = picture {
        metadata = metadata.picture(pic.to_unsafe());
    }
    if let Some(about) = about {
        metadata = metadata.about(about);
    }

    let d_tag = Tag::identifier(federation_id.to_string());
    let n_tag = Tag::custom(
        TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::N)),
        vec![network.to_string()],
    );

    let modules_tag = Tag::custom(
        TagKind::custom("modules".to_string()),
        vec![modules.join(",")],
    );

    let invite_codes: Vec<String> = vec![invite_code.to_string()];
    let u_tags = invite_codes.into_iter().map(|code| {
        Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::U)),
            vec![code],
        )
    });

    let mut tags = vec![d_tag, n_tag, modules_tag];
    tags.extend(u_tags);

    let builder = EventBuilder::new(Kind::from(38173), metadata.as_json()).tags(tags);
    let client = create_nostr_client();
    for relay in relays {
        add_relay(&client, relay.as_str()).await;
    }
    client.connect().await;
    Ok(*client.send_event_builder(builder).await?.id())
}

fn create_nostr_client() -> Client {
    // Generate new random keys to broadcast announcement
    let keys = Keys::generate();
    Client::builder().signer(keys.clone()).build()
}

async fn add_relay(client: &Client, relay: &str) {
    if let Err(err) = client.add_relay(relay).await {
        warn!(err = %err.fmt_compact(), "Could not add relay {}", relay);
    }
}
