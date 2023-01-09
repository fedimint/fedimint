use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Extension, Form};
use axum::response::Redirect;
use axum::{
    routing::{get, post},
    Router,
};
use axum_macros::debug_handler;
use bitcoin::Network;
use fedimint_api::config::ClientConfig;
use fedimint_api::module::ModuleInit;
use fedimint_api::task::TaskGroup;
use fedimint_api::Amount;
use fedimint_ln::LightningModuleConfigGen;
use fedimint_mint::MintConfigGenerator;
use fedimint_server::config::ModuleInitRegistry;
use fedimint_wallet::WalletConfigGenerator;
use http::StatusCode;
use mint_client::api::WsFederationConnect;
use qrcode_generator::QrCodeEcc;
use serde::Deserialize;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio_rustls::rustls;
use url::Url;

use crate::distributedgen::{create_cert, parse_peer_params, run_dkg};
use crate::encrypt::{encrypted_read, get_key};
use crate::{
    encrypted_json_write, write_nonprivate_configs, CONSENSUS_CONFIG, JSON_EXT, PRIVATE_CONFIG,
    SALT_FILE, TLS_PK,
};

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct Guardian {
    name: String,
    tls_connect_string: String,
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate {}

async fn home_page(Extension(_): Extension<MutableState>) -> HomeTemplate {
    HomeTemplate {}
}

#[derive(Template)]
#[template(path = "run.html")]
struct RunTemplate {
    connection_string: String,
    has_connection_string: bool,
}

async fn run_page(Extension(state): Extension<MutableState>) -> RunTemplate {
    let state = state.lock().await;
    let path = state.cfg_path.join("client.json");
    let connection_string: String = match std::fs::File::open(path) {
        Ok(file) => {
            let cfg: ClientConfig =
                serde_json::from_reader(file).expect("Could not parse cfg file.");
            let connect_info = WsFederationConnect::from(&cfg);
            serde_json::to_string(&connect_info).expect("should deserialize")
        }
        Err(_) => "".into(),
    };

    RunTemplate {
        connection_string: connection_string.clone(),
        has_connection_string: !connection_string.is_empty(),
    }
}

#[derive(Template)]
#[template(path = "add_guardians.html")]
struct AddGuardiansTemplate {
    num_guardians: u32,
    connect_string: String,
}

async fn add_guardians_page(Extension(state): Extension<MutableState>) -> AddGuardiansTemplate {
    let state = state.lock().await;
    let params = state.params.clone().expect("invalid state");
    AddGuardiansTemplate {
        num_guardians: params.num_guardians,
        connect_string: params.guardian.tls_connect_string,
    }
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct GuardiansForm {
    connection_strings: String,
}

#[debug_handler]
async fn post_guardians(
    Extension(state): Extension<MutableState>,
    Form(form): Form<GuardiansForm>,
) -> Result<Redirect, (StatusCode, String)> {
    let mut state = state.lock().await;
    let params = state.params.clone().expect("invalid state");
    let mut connection_strings: Vec<String> =
        serde_json::from_str(&form.connection_strings).expect("not json");
    connection_strings.push(params.guardian.tls_connect_string);

    // Don't allow re-running DKG if configs already exist
    let consensus_path = state
        .cfg_path
        .join(CONSENSUS_CONFIG)
        .with_extension(JSON_EXT);
    if std::path::Path::new(&consensus_path).exists() {
        return Ok(Redirect::to("/run".parse().unwrap()));
    }

    // Make vec of guardians
    let params = state.params.clone().expect("invalid state");
    let mut guardians = vec![params.guardian.clone()];
    for connection_string in connection_strings.clone().into_iter() {
        guardians.push(Guardian {
            name: parse_peer_params(connection_string.clone()).name,
            tls_connect_string: connection_string,
        });
    }

    // Actually run DKG
    let key = get_key(Some(state.password.clone()), state.cfg_path.join(SALT_FILE));
    let pk_bytes = encrypted_read(&key, state.cfg_path.join(TLS_PK));
    let max_denomination = Amount::from_msats(100000000000);
    let (dkg_sender, dkg_receiver) = tokio::sync::oneshot::channel::<UiMessage>();
    let module_config_gens = ModuleInitRegistry::from([
        (
            "wallet",
            Arc::new(WalletConfigGenerator) as Arc<dyn ModuleInit + Send + Sync>,
        ),
        ("mint", Arc::new(MintConfigGenerator)),
        ("ln", Arc::new(LightningModuleConfigGen)),
    ]);
    let dir_out_path = state.cfg_path.clone();
    let fedimintd_sender = state.sender.clone();

    let mut dkg_task_group = state.task_group.make_subgroup().await;
    state
        .task_group
        .spawn("admin UI running DKG", move |_| async move {
            tracing::info!("Running DKG");
            match run_dkg(
                params.listen_p2p,
                params.listen_api,
                &dir_out_path,
                max_denomination,
                params.federation_name,
                connection_strings,
                params.bitcoind_rpc,
                params.network,
                params.finality_delay,
                rustls::PrivateKey(pk_bytes),
                &mut dkg_task_group,
            )
            .await
            {
                Ok(server_config) => {
                    tracing::info!("DKG succeeded");
                    encrypted_json_write(
                        &server_config.private,
                        &key,
                        dir_out_path.join(PRIVATE_CONFIG),
                    );
                    write_nonprivate_configs(&server_config, dir_out_path, &module_config_gens);
                    // Shut down DKG to prevent port collisions
                    dkg_task_group
                        .shutdown_join_all()
                        .await
                        .expect("couldn't shut down DKG task group");
                    // Tell this route that DKG succeeded
                    dkg_sender
                        .send(UiMessage::DKGSuccess)
                        .expect("failed to send over channel");
                    // Tell this fedimintd that DKG succeeded
                    fedimintd_sender
                        .send(UiMessage::DKGSuccess)
                        .await
                        .expect("failed to send over channel");
                }
                Err(e) => {
                    tracing::info!("DKG failed {:?}", e);
                    dkg_sender
                        // TODO: include the error in the message
                        .send(UiMessage::DKGFailure)
                        .expect("failed to send over channel");
                }
            };
        })
        .await;
    match dkg_receiver.await.expect("failed to read over channel") {
        UiMessage::DKGSuccess => Ok(Redirect::to("/run".parse().unwrap())),
        // TODO: flash a message that it failed
        UiMessage::DKGFailure => Ok(Redirect::to("/add_guardians".parse().unwrap())),
    }
}

#[derive(Template)]
#[template(path = "params.html")]
struct UrlConnection {}

async fn params_page(Extension(_state): Extension<MutableState>) -> UrlConnection {
    UrlConnection {}
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct ParamsForm {
    /// Our node name, must be unique among peers
    guardian_name: String,
    /// Federation name, same for all peers
    federation_name: String,
    /// Our API address for clients to connect to us
    url_api: Url,
    /// Our external address for communicating with our peers
    url_p2p: Url,
    /// Address we bind to for exposing the API
    listen_api: SocketAddr,
    /// Address we bind to for federation communication
    listen_p2p: SocketAddr,
    /// `bitcoind` json rpc endpoint
    bitcoind_rpc: String,
    /// How many participants in federation consensus
    guardians_count: u32,
    /// Which bitcoin network the federation is using
    network: Network,
    /// The number of confirmations a deposit transaction requires before accepted by the
    /// federation
    finality_delay: u32,
}

#[debug_handler]
async fn post_federation_params(
    Extension(state): Extension<MutableState>,
    Form(form): Form<ParamsForm>,
) -> Result<Redirect, (StatusCode, String)> {
    let mut state = state.lock().await;

    // FIXME: this should return Result
    let tls_connect_string = create_cert(
        state.cfg_path.clone(),
        form.url_p2p.clone(),
        form.url_api.clone(),
        form.guardian_name.clone(),
        Some(state.password.clone()),
    );

    // Update state
    state.params = Some(FederationParameters {
        federation_name: form.federation_name,
        // TODO: check that bitcoinrpc actually works here
        bitcoind_rpc: form.bitcoind_rpc,
        num_guardians: form.guardians_count,
        listen_api: form.listen_api,
        listen_p2p: form.listen_p2p,
        guardian: Guardian {
            name: form.guardian_name,
            tls_connect_string,
        },
        finality_delay: form.finality_delay,
        network: form.network,
    });

    Ok(Redirect::to("/add_guardians".parse().unwrap()))
}

async fn qr(Extension(state): Extension<MutableState>) -> impl axum::response::IntoResponse {
    let state = state.lock().await;
    let path = state.cfg_path.join("client.json");
    let connection_string: String = match std::fs::File::open(path) {
        Ok(file) => {
            let cfg: ClientConfig =
                serde_json::from_reader(file).expect("Could not parse cfg file.");
            let connect_info = WsFederationConnect::from(&cfg);
            serde_json::to_string(&connect_info).expect("should deserialize")
        }
        Err(_) => "".into(),
    };
    let png_bytes: Vec<u8> =
        qrcode_generator::to_png_to_vec(connection_string, QrCodeEcc::Low, 1024).unwrap();
    (
        axum::response::Headers([(axum::http::header::CONTENT_TYPE, "image/png")]),
        png_bytes,
    )
}

// FIXME: this is so similar to ParamsForm ...
#[derive(Clone)]
struct FederationParameters {
    federation_name: String,
    guardian: Guardian,
    num_guardians: u32,
    bitcoind_rpc: String,
    finality_delay: u32,
    network: Network,
    listen_api: SocketAddr,
    listen_p2p: SocketAddr,
}

struct State {
    params: Option<FederationParameters>,
    cfg_path: PathBuf,
    sender: Sender<UiMessage>,
    password: String,
    task_group: TaskGroup,
}
type MutableState = Arc<Mutex<State>>;

#[derive(Debug)]
pub enum UiMessage {
    DKGSuccess,
    DKGFailure,
}

pub async fn run_ui(
    cfg_path: PathBuf,
    sender: Sender<UiMessage>,
    listen_ui: SocketAddr,
    password: String,
    task_group: TaskGroup,
) {
    let state = Arc::new(Mutex::new(State {
        params: None,
        cfg_path,
        sender,
        password,
        task_group,
    }));

    let app = Router::new()
        .route("/", get(home_page))
        .route("/federation_params", get(params_page))
        .route("/post_federation_params", post(post_federation_params))
        .route("/add_guardians", get(add_guardians_page))
        .route("/post_guardians", post(post_guardians))
        .route("/run", get(run_page))
        .route("/qr", get(qr))
        .layer(Extension(state));

    axum::Server::bind(&listen_ui)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
