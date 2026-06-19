use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::iter::once;
use std::mem::discriminant;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr as _;
use std::sync::Arc;

use anyhow::{Context, ensure};
use async_trait::async_trait;
use fedimint_core::admin_client::{SetLocalParamsRequest, SetupStatus};
use fedimint_core::base32::FEDIMINT_PREFIX;
use fedimint_core::config::META_FEDERATION_NAME_KEY;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::endpoint_constants::{
    ADD_PEER_SETUP_CODE_ENDPOINT, GET_SETUP_CODE_ENDPOINT, RESET_PEER_SETUP_CODES_ENDPOINT,
    SET_LOCAL_PARAMS_ENDPOINT, SETUP_STATUS_ENDPOINT, START_DKG_ENDPOINT,
};
use fedimint_core::envs::{
    FM_DISABLE_BASE_FEES_ENV, FM_IROH_API_SECRET_KEY_OVERRIDE_ENV,
    FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV, is_env_var_set,
};
use fedimint_core::module::{
    ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiVersion, api_endpoint,
};
use fedimint_core::net::auth::check_auth;
use fedimint_core::setup_code::PeerEndpoints;
use fedimint_core::{PeerId, base32, runtime};
use fedimint_server_core::setup_ui::ISetupApi;
use iroh_next::SecretKey;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, oneshot};
use tokio_rustls::rustls;

use crate::config::io::{
    CONSENSUS_CONFIG, ENCRYPTED_EXT, JSON_EXT, LOCAL_CONFIG, PRIVATE_CONFIG, SALT_FILE,
    parse_legacy_encrypted_backup, parse_plaintext_backup,
};
use crate::config::{ConfigGenParams, ConfigGenSettings, PeerSetupCode, ServerConfig};
use crate::net::api::HasApiContext;
use crate::net::p2p_connector::gen_cert_and_key;

/// Result sent from the setup API task to the main setup driver.
///
/// Normal DKG sends generated params directly. Restore sends the parsed config
/// plus a oneshot acknowledgement so the HTTP handler can report success only
/// after the main setup driver validates and writes the restored config.
pub enum ConfigGenOutcome {
    Generated(Box<ConfigGenParams>),
    Restored(Box<ServerConfig>, oneshot::Sender<Result<(), String>>),
}

/// State held by the API after receiving a `ConfigGenConnectionsRequest`
#[derive(Debug, Clone, Default)]
pub struct SetupState {
    /// Our local connection
    local_params: Option<LocalParams>,
    /// Connection info received from other guardians
    setup_codes: BTreeSet<PeerSetupCode>,
    /// Set while a backup restore is being processed
    restore_in_progress: bool,
}

#[derive(Clone, Debug)]
/// Connection information sent between peers in order to start config gen
pub struct LocalParams {
    /// Our TLS private key
    tls_key: Option<Arc<rustls::pki_types::PrivateKeyDer<'static>>>,
    /// Optional secret key for our iroh api endpoint
    iroh_api_sk: Option<iroh_next::SecretKey>,
    /// Optional secret key for our iroh p2p endpoint
    iroh_p2p_sk: Option<iroh_next::SecretKey>,
    /// Our api and p2p endpoint
    endpoints: PeerEndpoints,
    /// Name of the peer, used in TLS auth
    name: String,
    /// Federation name set by the leader
    federation_name: Option<String>,
    /// Whether to disable base fees, set by the leader
    disable_base_fees: Option<bool>,
    /// Modules enabled by the leader (if None, all available modules are
    /// enabled)
    enabled_modules: Option<BTreeSet<ModuleKind>>,
    /// Total number of guardians (including the one who sets this), set by the
    /// leader
    federation_size: Option<u32>,
    /// Bitcoin network configured locally
    network: bitcoin::Network,
    /// Fedimint `x.y.z` cargo release version configured locally
    fedimint_version: String,
}

impl LocalParams {
    pub fn setup_code(&self) -> PeerSetupCode {
        PeerSetupCode {
            name: self.name.clone(),
            endpoints: self.endpoints.clone(),
            federation_name: self.federation_name.clone(),
            disable_base_fees: self.disable_base_fees,
            enabled_modules: self.enabled_modules.clone(),
            federation_size: self.federation_size,
            network: self.network,
            fedimint_version: self.fedimint_version.clone(),
        }
    }
}

fn ensure_fedimint_version_matches(
    peer_setup_code: &PeerSetupCode,
    local_fedimint_version: &str,
) -> anyhow::Result<()> {
    let peer_fedimint_version =
        fedimint_core::version::release_version(&peer_setup_code.fedimint_version);

    ensure!(
        peer_fedimint_version == local_fedimint_version,
        "Guardian uses Fedimint version {peer_fedimint_version} but we use {local_fedimint_version}",
    );

    Ok(())
}

/// Serves the config gen API endpoints
#[derive(Clone)]
pub struct SetupApi {
    /// Our config gen settings configured locally
    settings: ConfigGenSettings,
    /// In-memory state machine
    state: Arc<Mutex<SetupState>>,
    /// DB not really used
    db: Database,
    /// Triggers config generation or config restore
    sender: Sender<ConfigGenOutcome>,
    /// Version of the running fedimintd binary
    code_version_str: String,
    /// Git hash of the running fedimintd binary
    code_version_hash: String,
    /// Password protecting the setup UI login form. `None` ⇒ no login.
    auth_ui: Option<ApiAuth>,
    /// Password protecting setup admin RPCs over WS/iroh. `None` ⇒ 401.
    auth_api: Option<ApiAuth>,
}

impl SetupApi {
    pub fn new(
        settings: ConfigGenSettings,
        db: Database,
        sender: Sender<ConfigGenOutcome>,
        code_version_str: String,
        code_version_hash: String,
        auth_ui: Option<ApiAuth>,
        auth_api: Option<ApiAuth>,
    ) -> Self {
        Self {
            settings,
            state: Arc::new(Mutex::new(SetupState::default())),
            db,
            sender,
            code_version_str,
            code_version_hash,
            auth_ui,
            auth_api,
        }
    }

    pub async fn setup_status(&self) -> SetupStatus {
        match self.state.lock().await.local_params {
            Some(..) => SetupStatus::SharingConnectionCodes,
            None => SetupStatus::AwaitingLocalParams,
        }
    }
}

fn is_expected_backup_path(path: &Path) -> bool {
    let expected_paths = [
        PathBuf::from(LOCAL_CONFIG).with_extension(JSON_EXT),
        PathBuf::from(CONSENSUS_CONFIG).with_extension(JSON_EXT),
        PathBuf::from(PRIVATE_CONFIG).with_extension(JSON_EXT),
        PathBuf::from(PRIVATE_CONFIG).with_extension(ENCRYPTED_EXT),
        PathBuf::from(SALT_FILE),
    ];

    expected_paths.iter().any(|expected| expected == path)
}

/// Parse a guardian backup tar into a [`ServerConfig`] entirely in memory.
///
/// Validates archive paths and rejects missing, unexpected, duplicate, or
/// non-file entries. Two backup formats are supported: the current plaintext
/// format (containing `private.json`) and the legacy encrypted format
/// (containing `private.encrypt` + `private.salt`), which requires the guardian
/// password used when the backup was created. Nothing is written to disk; the
/// caller writes the validated config into the data directory just like a
/// freshly generated config.
fn parse_backup(backup: &[u8], password: Option<&str>) -> anyhow::Result<ServerConfig> {
    let mut archive = tar::Archive::new(backup);
    let mut files: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();

    for entry in archive.entries().context("Reading backup archive")? {
        let mut entry = entry.context("Reading backup archive entry")?;
        let path = entry
            .path()
            .context("Reading backup archive entry path")?
            .into_owned();
        ensure!(
            path.components()
                .all(|component| matches!(component, Component::Normal(_))),
            "Backup archive contains an invalid path"
        );
        ensure!(
            is_expected_backup_path(&path),
            "Backup archive contains unexpected file {}",
            path.display()
        );
        ensure!(
            entry.header().entry_type().is_file(),
            "Backup archive contains non-file entry {}",
            path.display()
        );

        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .context("Reading backup archive entry contents")?;
        ensure!(
            files.insert(path.clone(), bytes).is_none(),
            "Backup archive contains duplicate file {}",
            path.display()
        );
    }

    let local_config = PathBuf::from(LOCAL_CONFIG).with_extension(JSON_EXT);
    let consensus_config = PathBuf::from(CONSENSUS_CONFIG).with_extension(JSON_EXT);
    let private_config_json = PathBuf::from(PRIVATE_CONFIG).with_extension(JSON_EXT);
    let private_config_encrypted = PathBuf::from(PRIVATE_CONFIG).with_extension(ENCRYPTED_EXT);
    let salt_file = PathBuf::from(SALT_FILE);

    let local = files
        .get(&local_config)
        .with_context(|| format!("Backup archive is missing {}", local_config.display()))?;
    let consensus = files
        .get(&consensus_config)
        .with_context(|| format!("Backup archive is missing {}", consensus_config.display()))?;

    // Both formats are parsed into a plaintext config in memory, which the
    // caller then writes out exactly like a freshly generated config, so a
    // restored guardian looks like a fresh post-migration setup.
    if let Some(private) = files.get(&private_config_json) {
        // Current plaintext format. No password is needed; any supplied
        // password is ignored.
        parse_plaintext_backup(local, consensus, private).context("Reading restored config")
    } else if let Some(private) = files.get(&private_config_encrypted) {
        // Legacy encrypted format. Requires the salt file and the password used
        // when the backup was created.
        let salt = files
            .get(&salt_file)
            .with_context(|| format!("Backup archive is missing {}", salt_file.display()))?;
        let password = password.context(
            "This backup is encrypted, please provide the guardian password used when it was created",
        )?;
        parse_legacy_encrypted_backup(local, consensus, private, salt, password)
            .context("Reading restored config")
    } else {
        anyhow::bail!("Backup archive is missing the private config");
    }
}

#[async_trait]
impl ISetupApi for SetupApi {
    async fn setup_code(&self) -> Option<String> {
        self.state
            .lock()
            .await
            .local_params
            .as_ref()
            .map(|lp| base32::encode_prefixed(FEDIMINT_PREFIX, &lp.setup_code()))
    }

    async fn guardian_name(&self) -> Option<String> {
        self.state
            .lock()
            .await
            .local_params
            .as_ref()
            .map(|lp| lp.name.clone())
    }

    fn auth_ui(&self) -> Option<ApiAuth> {
        self.auth_ui.clone()
    }

    async fn connected_peers(&self) -> Vec<String> {
        self.state
            .lock()
            .await
            .setup_codes
            .clone()
            .into_iter()
            .map(|info| info.name)
            .collect()
    }

    fn available_modules(&self) -> BTreeSet<ModuleKind> {
        self.settings.available_modules.clone()
    }

    fn default_modules(&self) -> BTreeSet<ModuleKind> {
        self.settings.default_modules.clone()
    }

    async fn reset_setup_codes(&self) {
        self.state.lock().await.setup_codes.clear();
    }

    async fn set_local_parameters(
        &self,
        name: String,
        federation_name: Option<String>,
        disable_base_fees: Option<bool>,
        enabled_modules: Option<BTreeSet<ModuleKind>>,
        federation_size: Option<u32>,
    ) -> anyhow::Result<String> {
        if let Some(existing_local_parameters) = self.state.lock().await.local_params.clone()
            && existing_local_parameters.name == name
            && existing_local_parameters.federation_name == federation_name
            && existing_local_parameters.disable_base_fees == disable_base_fees
            && existing_local_parameters.enabled_modules == enabled_modules
            && existing_local_parameters.federation_size == federation_size
        {
            return Ok(base32::encode_prefixed(
                FEDIMINT_PREFIX,
                &existing_local_parameters.setup_code(),
            ));
        }

        ensure!(!name.is_empty(), "The guardian name is empty");

        if let Some(federation_name) = federation_name.as_ref() {
            ensure!(!federation_name.is_empty(), "The federation name is empty");
        }

        if federation_name.is_some() {
            ensure!(
                federation_size.is_some(),
                "The leader must set the federation size"
            );
        }

        if let Some(size) = federation_size {
            ensure!(
                size == 1 || 4 <= size,
                "Federation size must be 1 or at least 4"
            );
        }

        let mut state = self.state.lock().await;

        ensure!(
            state.local_params.is_none(),
            "Local parameters have already been set"
        );

        ensure!(
            !state.restore_in_progress,
            "A restore is already in progress"
        );

        let lp = if self.settings.enable_iroh {
            let iroh_api_sk = if let Ok(var) = std::env::var(FM_IROH_API_SECRET_KEY_OVERRIDE_ENV) {
                SecretKey::from_str(&var)
                    .with_context(|| format!("Parsing {FM_IROH_API_SECRET_KEY_OVERRIDE_ENV}"))?
            } else {
                SecretKey::generate()
            };

            let iroh_p2p_sk = if let Ok(var) = std::env::var(FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV) {
                SecretKey::from_str(&var)
                    .with_context(|| format!("Parsing {FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV}"))?
            } else {
                SecretKey::generate()
            };

            LocalParams {
                tls_key: None,
                iroh_api_sk: Some(iroh_api_sk.clone()),
                iroh_p2p_sk: Some(iroh_p2p_sk.clone()),
                endpoints: PeerEndpoints::Iroh {
                    api_pk: iroh_api_sk.public(),
                    p2p_pk: iroh_p2p_sk.public(),
                },
                name,
                federation_name,
                disable_base_fees,
                enabled_modules,
                federation_size,
                network: self.settings.network,
                fedimint_version: fedimint_core::version::release_version(&self.code_version_str)
                    .to_owned(),
            }
        } else {
            let (tls_cert, tls_key) =
                gen_cert_and_key(&name).expect("Failed to generate TLS for given guardian name");

            LocalParams {
                tls_key: Some(tls_key),
                iroh_api_sk: None,
                iroh_p2p_sk: None,
                endpoints: PeerEndpoints::Tcp {
                    api_url: self
                        .settings
                        .api_url
                        .clone()
                        .ok_or_else(|| anyhow::format_err!("Api URL must be configured"))?,
                    p2p_url: self
                        .settings
                        .p2p_url
                        .clone()
                        .ok_or_else(|| anyhow::format_err!("P2P URL must be configured"))?,

                    cert: tls_cert.as_ref().to_vec(),
                },
                name,
                federation_name,
                disable_base_fees,
                enabled_modules,
                federation_size,
                network: self.settings.network,
                fedimint_version: fedimint_core::version::release_version(&self.code_version_str)
                    .to_owned(),
            }
        };

        state.local_params = Some(lp.clone());

        Ok(base32::encode_prefixed(FEDIMINT_PREFIX, &lp.setup_code()))
    }

    async fn add_peer_setup_code(&self, info: String) -> anyhow::Result<String> {
        let info = base32::decode_prefixed(FEDIMINT_PREFIX, &info)?;

        let mut state = self.state.lock().await;

        if state.setup_codes.contains(&info) {
            return Ok(info.name.clone());
        }

        ensure!(
            !state.restore_in_progress,
            "A restore is already in progress"
        );

        let local_params = state
            .local_params
            .clone()
            .expect("The endpoint is authenticated.");

        ensure!(
            info != local_params.setup_code(),
            "You cannot add your own setup code"
        );

        ensure!(
            discriminant(&info.endpoints) == discriminant(&local_params.endpoints),
            "Guardian has different endpoint variant (TCP/Iroh) than us.",
        );

        ensure_fedimint_version_matches(&info, &local_params.fedimint_version)?;

        ensure!(
            info.network == local_params.network,
            "Guardian uses Bitcoin network {} but we use {}",
            info.network,
            local_params.network,
        );

        if let Some(federation_name) = state
            .setup_codes
            .iter()
            .chain(once(&local_params.setup_code()))
            .find_map(|info| info.federation_name.clone())
        {
            ensure!(
                info.federation_name.is_none(),
                "Federation name has already been set to {federation_name}"
            );
        }

        if let Some(disable_base_fees) = state
            .setup_codes
            .iter()
            .chain(once(&local_params.setup_code()))
            .find_map(|info| info.disable_base_fees)
        {
            ensure!(
                info.disable_base_fees.is_none(),
                "Base fees setting has already been configured to disabled={disable_base_fees}"
            );
        }

        if state
            .setup_codes
            .iter()
            .chain(once(&local_params.setup_code()))
            .any(|info| info.enabled_modules.is_some())
        {
            ensure!(
                info.enabled_modules.is_none(),
                "Enabled modules have already been configured by another guardian"
            );
        }

        if let Some(federation_size) = state
            .setup_codes
            .iter()
            .chain(once(&local_params.setup_code()))
            .find_map(|info| info.federation_size)
        {
            ensure!(
                info.federation_size.is_none(),
                "Federation size has already been set to {federation_size}"
            );
        }

        state.setup_codes.insert(info.clone());

        Ok(info.name)
    }

    async fn start_dkg(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await.clone();

        ensure!(
            !state.restore_in_progress,
            "A restore is already in progress"
        );

        let local_params = state
            .local_params
            .clone()
            .expect("The endpoint is authenticated.");

        let our_setup_code = local_params.setup_code();

        state.setup_codes.insert(our_setup_code.clone());

        for setup_code in &state.setup_codes {
            ensure_fedimint_version_matches(setup_code, &local_params.fedimint_version)?;
        }

        ensure!(
            state.setup_codes.len() == 1 || 4 <= state.setup_codes.len(),
            "The number of guardians is invalid"
        );

        if let Some(federation_size) = state
            .setup_codes
            .iter()
            .find_map(|info| info.federation_size)
        {
            ensure!(
                state.setup_codes.len() == federation_size as usize,
                "Expected {federation_size} guardians but got {}",
                state.setup_codes.len()
            );
        }

        let federation_name = state
            .setup_codes
            .iter()
            .find_map(|info| info.federation_name.clone())
            .context("We need one guardian to configure the federations name")?;

        let disable_base_fees = state
            .setup_codes
            .iter()
            .find_map(|info| info.disable_base_fees)
            .unwrap_or(is_env_var_set(FM_DISABLE_BASE_FEES_ENV));

        let enabled_modules = state
            .setup_codes
            .iter()
            .find_map(|info| info.enabled_modules.clone())
            .unwrap_or_else(|| self.settings.default_modules.clone());

        let our_id = state
            .setup_codes
            .iter()
            .position(|info| info == &our_setup_code)
            .expect("We inserted the key above.");

        let params = ConfigGenParams {
            identity: PeerId::from(our_id as u16),
            tls_key: local_params.tls_key,
            iroh_api_sk: local_params.iroh_api_sk,
            iroh_p2p_sk: local_params.iroh_p2p_sk,
            peers: (0..)
                .map(|i| PeerId::from(i as u16))
                .zip(state.setup_codes.clone())
                .collect(),
            meta: BTreeMap::from_iter(vec![(
                META_FEDERATION_NAME_KEY.to_string(),
                federation_name,
            )]),
            disable_base_fees,
            enabled_modules,
            network: local_params.network,
        };

        self.sender
            .send(ConfigGenOutcome::Generated(Box::new(params)))
            .await
            .context("Failed to send config gen params")?;

        Ok(())
    }

    async fn restore_from_backup(
        &self,
        password: Option<String>,
        backup: Vec<u8>,
    ) -> anyhow::Result<()> {
        if let Some(password) = &password {
            ensure!(!password.is_empty(), "The password is empty");
            ensure!(
                password.trim() == password,
                "The password contains leading/trailing whitespace",
            );
        }
        {
            let mut state = self.state.lock().await;
            ensure!(
                state.local_params.is_none(),
                "Local parameters have already been set"
            );
            ensure!(
                !state.restore_in_progress,
                "A restore is already in progress"
            );
            state.restore_in_progress = true;
        }

        let state = self.state.clone();
        let sender = self.sender.clone();
        runtime::spawn("restore guardian backup", async move {
            let result = async {
                let cfg =
                    tokio::task::spawn_blocking(move || parse_backup(&backup, password.as_deref()))
                        .await
                        .context("Restore backup task panicked")??;
                let (restore_result_sender, restore_result_receiver) = oneshot::channel();
                let restored = ConfigGenOutcome::Restored(Box::new(cfg), restore_result_sender);
                if sender.send(restored).await.is_err() {
                    return Err(anyhow::format_err!("Failed to send restored config"));
                }
                restore_result_receiver
                    .await
                    .context("Restore result sender dropped")?
                    .map_err(anyhow::Error::msg)?;
                Ok(())
            }
            .await;

            if result.is_err() {
                state.lock().await.restore_in_progress = false;
            }
            // On success, the setup task consumes the restored config and exits setup mode,
            // so there is no setup API left that could observe or reset
            // `restore_in_progress`.

            result
        })
        .await
        .context("Restore task panicked")?
    }

    async fn federation_size(&self) -> Option<u32> {
        let state = self.state.lock().await;
        let local_setup_code = state.local_params.as_ref().map(LocalParams::setup_code);
        state
            .setup_codes
            .iter()
            .chain(local_setup_code.iter())
            .find_map(|info| info.federation_size)
    }

    async fn cfg_federation_name(&self) -> Option<String> {
        let state = self.state.lock().await;
        let local_setup_code = state.local_params.as_ref().map(LocalParams::setup_code);
        state
            .setup_codes
            .iter()
            .chain(local_setup_code.iter())
            .find_map(|info| info.federation_name.clone())
    }

    async fn cfg_base_fees_disabled(&self) -> Option<bool> {
        let state = self.state.lock().await;
        let local_setup_code = state.local_params.as_ref().map(LocalParams::setup_code);
        state
            .setup_codes
            .iter()
            .chain(local_setup_code.iter())
            .find_map(|info| info.disable_base_fees)
    }

    async fn cfg_enabled_modules(&self) -> Option<BTreeSet<ModuleKind>> {
        let state = self.state.lock().await;
        let local_setup_code = state.local_params.as_ref().map(LocalParams::setup_code);
        state
            .setup_codes
            .iter()
            .chain(local_setup_code.iter())
            .find_map(|info| info.enabled_modules.clone())
    }

    async fn fedimintd_version(&self) -> String {
        self.code_version_str.clone()
    }

    async fn fedimintd_version_hash(&self) -> Option<String> {
        fedimint_core::version::non_zero_version_hash(&self.code_version_hash).map(str::to_owned)
    }
}

#[async_trait]
impl HasApiContext<SetupApi> for SetupApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&SetupApi, ApiEndpointContext) {
        assert!(id.is_none());

        let db = self.db.clone();

        let is_authenticated = match (&self.auth_api, &request.auth) {
            (Some(server_auth), Some(req_auth)) => server_auth.verify(req_auth.as_str()),
            _ => false,
        };

        let context = ApiEndpointContext::new(db, is_authenticated, request.auth.clone());

        (self, context)
    }
}

pub fn server_endpoints() -> Vec<ApiEndpoint<SetupApi>> {
    vec![
        api_endpoint! {
            SETUP_STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, _c, _v: ()| -> SetupStatus {
                Ok(config.setup_status().await)
            }
        },
        api_endpoint! {
            SET_LOCAL_PARAMS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, request: SetLocalParamsRequest| -> String {
                check_auth(context)?;

                 config.set_local_parameters(request.name, request.federation_name, request.disable_base_fees, request.enabled_modules, request.federation_size)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))
            }
        },
        api_endpoint! {
            ADD_PEER_SETUP_CODE_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, info: String| -> String {
                check_auth(context)?;

                config.add_peer_setup_code(info.clone())
                    .await
                    .map_err(|e|ApiError::bad_request(e.to_string()))
            }
        },
        api_endpoint! {
            RESET_PEER_SETUP_CODES_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, _v: ()| -> () {
                check_auth(context)?;

                config.reset_setup_codes().await;

                Ok(())
            }
        },
        api_endpoint! {
            GET_SETUP_CODE_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, _request: ()| -> Option<String> {
                check_auth(context)?;

                Ok(config.setup_code().await)
            }
        },
        api_endpoint! {
            START_DKG_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, _v: ()| -> () {
                check_auth(context)?;

                config.start_dkg().await.map_err(|e| ApiError::server_error(e.to_string()))
            }
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use base64::Engine as _;
    use bitcoin::Network;
    use fedimint_core::db::IRawDatabaseExt;
    use fedimint_core::db::mem_impl::MemDatabase;
    use tokio::sync::mpsc;

    use super::*;

    fn setup_api(network: Network) -> SetupApi {
        setup_api_with_version(network, "1.2.3-alpha")
    }

    fn setup_api_with_version(network: Network, version: &str) -> SetupApi {
        let (sender, _receiver) = mpsc::channel(1);
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        SetupApi::new(
            ConfigGenSettings {
                p2p_bind: bind,
                api_bind: bind,
                ui_bind: bind,
                p2p_url: None,
                api_url: None,
                enable_iroh: true,
                iroh_dns: None,
                iroh_relays: Vec::new(),
                network,
                available_modules: BTreeSet::new(),
                default_modules: BTreeSet::new(),
            },
            MemDatabase::new().into_database(),
            sender,
            version.to_owned(),
            String::new(),
            None,
            None,
        )
    }

    const INVALID_RESTORE_BACKUP_FIXTURE_B64: &str =
        include_str!("../test_fixtures/guardian-backup-invalid-config.tar.b64");

    async fn setup_code(api: &SetupApi, name: &str) -> String {
        api.set_local_parameters(name.to_string(), None, None, None, None)
            .await
            .expect("setting local parameters should succeed")
    }

    #[tokio::test]
    async fn accepts_peer_setup_code_with_matching_network() {
        let api = setup_api(Network::Regtest);
        let peer_api = setup_api(Network::Regtest);

        setup_code(&api, "local").await;
        let peer_code = setup_code(&peer_api, "peer").await;

        let added_peer = api
            .add_peer_setup_code(peer_code)
            .await
            .expect("peer setup code with matching network should be accepted");

        assert_eq!(added_peer, "peer");
    }

    #[test]
    fn checked_in_backup_fixture_reaches_config_validation() {
        let backup = base64::prelude::BASE64_STANDARD
            .decode(INVALID_RESTORE_BACKUP_FIXTURE_B64.trim())
            .expect("checked-in backup fixture base64 should decode");
        let Err(err) = parse_backup(&backup, Some("pass")) else {
            panic!("invalid checked-in backup fixture should not restore");
        };

        assert!(
            err.to_string().contains("Reading restored config"),
            "unexpected restore error: {err:#}"
        );
    }

    #[test]
    fn backup_restore_rejects_non_file_entries() {
        let mut backup = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut backup);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    PathBuf::from(LOCAL_CONFIG).with_extension(JSON_EXT),
                    std::io::empty(),
                )
                .expect("writing tar entry should succeed");
            archive.finish().expect("finishing tar should succeed");
        }

        let Err(err) = parse_backup(&backup, None) else {
            panic!("non-file backup entries should be rejected");
        };

        assert!(
            err.to_string().contains("non-file entry"),
            "unexpected restore error: {err:#}"
        );
    }

    #[tokio::test]
    async fn rejects_peer_setup_code_with_different_network() {
        let api = setup_api(Network::Regtest);
        let peer_api = setup_api(Network::Signet);

        setup_code(&api, "local").await;
        let peer_code = setup_code(&peer_api, "peer").await;

        let err = api
            .add_peer_setup_code(peer_code)
            .await
            .expect_err("peer setup code with different network should be rejected");

        assert!(
            err.to_string()
                .contains("Guardian uses Bitcoin network signet but we use regtest")
        );
    }

    #[tokio::test]
    async fn rejects_peer_setup_code_with_different_fedimint_version() {
        let api = setup_api_with_version(Network::Regtest, "1.2.3-alpha");
        let peer_api = setup_api_with_version(Network::Regtest, "1.2.4-beta");

        setup_code(&api, "local").await;
        let peer_code = setup_code(&peer_api, "peer").await;

        let err = api
            .add_peer_setup_code(peer_code)
            .await
            .expect_err("peer setup code with different Fedimint version should be rejected");

        assert!(
            err.to_string()
                .contains("Guardian uses Fedimint version 1.2.4 but we use 1.2.3")
        );
    }

    #[tokio::test]
    async fn accepts_peer_setup_code_with_same_release_fedimint_version() {
        let api = setup_api_with_version(Network::Regtest, "1.2.3-alpha");
        let peer_api = setup_api_with_version(Network::Regtest, "1.2.3-beta");

        setup_code(&api, "local").await;
        let peer_code = setup_code(&peer_api, "peer").await;

        let added_peer = api
            .add_peer_setup_code(peer_code)
            .await
            .expect("peer setup code with same Fedimint release version should be accepted");

        assert_eq!(added_peer, "peer");
    }

    #[tokio::test]
    async fn rejects_wrong_fedimint_version_during_dkg() {
        let api = setup_api_with_version(Network::Regtest, "1.2.3-alpha");
        let peer_api = setup_api_with_version(Network::Regtest, "1.2.4-beta");

        setup_code(&api, "local").await;
        let peer_code = setup_code(&peer_api, "peer").await;
        let peer_code = base32::decode_prefixed(FEDIMINT_PREFIX, &peer_code)
            .expect("peer setup code should decode");

        api.state.lock().await.setup_codes.insert(peer_code);

        let err = api
            .start_dkg()
            .await
            .expect_err("DKG should reject peer setup code with different Fedimint version");

        assert!(
            err.to_string()
                .contains("Guardian uses Fedimint version 1.2.4 but we use 1.2.3")
        );
    }
}
