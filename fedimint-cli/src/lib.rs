#![deny(clippy::pedantic, clippy::unwrap_used)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::ref_option)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::large_futures)]

mod cli;
mod client;
mod db;
pub mod envs;
mod utils;
mod visualize;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::io::{IsTerminal, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, result};

use anyhow::{Context, format_err};
use clap::{CommandFactory, Parser};
use cli::{
    AdminCmd, Command, DatabaseBackend, DecodeType, DevCmd, EncodeType, OOBNotesJson, Opts,
    SetupAdminArgs, SetupAdminCmd, VisualizeCmd,
};
use envs::SALT_FILE;
use fedimint_aead::{encrypted_read, encrypted_write, get_encryption_key};
use fedimint_api_client::api::{DynGlobalApi, FederationApiExt, FederationError};
use fedimint_api_client::download_from_invite_code;
use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::db::ApiSecretKey;
use fedimint_client::module::meta::{FetchKind, LegacyMetaSource, MetaSource};
use fedimint_client::module::module::init::ClientModuleInit;
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_client::{AdminCreds, Client, ClientBuilder, ClientHandleArc, RootSecret};
use fedimint_connectors::{Connectivity, ConnectorRegistry};
use fedimint_core::base32::FEDIMINT_PREFIX;
use fedimint_core::config::{FederationId, FederationIdPrefix};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseValue, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::Decodable;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::setup_code::PeerSetupCode;
use fedimint_core::transaction::Transaction;
use fedimint_core::util::{SafeUrl, backoff_util, handle_version_hash_command, retry};
use fedimint_core::{PeerId, base32, fedimint_build_code_version_env, runtime};
use fedimint_derive_secret::DerivableSecret;
use fedimint_eventlog::EventLogTrimableId;
use fedimint_ln_client::LightningClientInit;
use fedimint_logging::{LOG_CLIENT, TracingSetup};
use fedimint_meta_client::{MetaClientInit, MetaModuleMetaSourceWithFallback};
use fedimint_mint_client::{MintClientInit, MintClientModule, OOBNotes};
use fedimint_wallet_client::api::WalletFederationApi;
use fedimint_wallet_client::{WalletClientInit, WalletClientModule};
use futures::future::{join_all, pending};
use itertools::Itertools;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::client::ClientCmd;
use crate::db::{StoredAdminCreds, load_admin_creds, store_admin_creds};

/// Type of output the cli produces
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
enum CliOutput {
    VersionHash {
        hash: String,
    },

    UntypedApiOutput {
        value: Value,
    },

    WaitBlockCount {
        reached: u64,
    },

    InviteCode {
        invite_code: InviteCode,
    },

    DecodeInviteCode {
        url: SafeUrl,
        federation_id: FederationId,
    },

    Join {
        joined: String,
    },

    DecodeTransaction {
        transaction: String,
    },

    EpochCount {
        count: u64,
    },

    ConfigDecrypt,

    ConfigEncrypt,

    SetupCode {
        setup_code: PeerSetupCode,
    },

    Raw(serde_json::Value),
}

impl fmt::Display for CliOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string_pretty(self).expect("CliOutput is serializable")
        )
    }
}

#[derive(Debug, Serialize)]
struct FederationPrivacyReport {
    federation_id: FederationId,
    guardians: BTreeMap<String, GuardianPrivacyReport>,
    summary: FederationPrivacySummary,
}

#[derive(Debug, Serialize)]
struct GuardianPrivacyReport {
    name: String,
    api_url: SafeUrl,
    addresses: BTreeMap<String, IpInfoReport>,
    iroh: Option<IrohConnectionReport>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct IrohConnectionReport {
    node_id: String,
    connectivity: &'static str,
    direct_addr: Option<String>,
    relay_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct IpInfoReport {
    address_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct FederationPrivacySummary {
    guardian_count: usize,
    iroh_guardian_count: usize,
    resolved_guardian_count: usize,
    iroh_direct_guardian_count: usize,
    iroh_relayed_guardian_count: usize,
    public_ip_count: usize,
    countries: BTreeMap<String, usize>,
    autonomous_systems: BTreeMap<String, usize>,
}

#[derive(Debug, Deserialize)]
struct IpWhoResponse {
    success: Option<bool>,
    message: Option<String>,
    country_code: Option<String>,
    country: Option<String>,
    connection: Option<IpWhoConnection>,
}

#[derive(Debug, Deserialize)]
struct IpWhoConnection {
    asn: Option<u64>,
    org: Option<String>,
    isp: Option<String>,
}

const IP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// `Result` with `CliError` as `Error`
type CliResult<E> = Result<E, CliError>;

/// `Result` with `CliError` as `Error` and `CliOutput` as `Ok`
type CliOutputResult = Result<CliOutput, CliError>;

/// Cli error
#[derive(Serialize, Error)]
#[serde(tag = "error", rename_all(serialize = "snake_case"))]
struct CliError {
    error: String,
}

/// Extension trait making turning Results/Errors into
/// [`CliError`]/[`CliOutputResult`] easier
trait CliResultExt<O, E> {
    /// Map error into `CliError` wrapping the original error message
    fn map_err_cli(self) -> Result<O, CliError>;
    /// Map error into `CliError` using custom error message `msg`
    fn map_err_cli_msg(self, msg: impl fmt::Display + Send + Sync + 'static)
    -> Result<O, CliError>;
}

impl<O, E> CliResultExt<O, E> for result::Result<O, E>
where
    E: Into<anyhow::Error>,
{
    fn map_err_cli(self) -> Result<O, CliError> {
        self.map_err(|e| {
            let e = e.into();
            CliError {
                error: format!("{e:#}"),
            }
        })
    }

    fn map_err_cli_msg(
        self,
        msg: impl fmt::Display + Send + Sync + 'static,
    ) -> Result<O, CliError> {
        self.map_err(|e| Into::<anyhow::Error>::into(e))
            .context(msg)
            .map_err(|e| CliError {
                error: format!("{e:#}"),
            })
    }
}

/// Extension trait to make turning `Option`s into
/// [`CliError`]/[`CliOutputResult`] easier
trait CliOptionExt<O> {
    fn ok_or_cli_msg(self, msg: impl Into<String>) -> Result<O, CliError>;
}

impl<O> CliOptionExt<O> for Option<O> {
    fn ok_or_cli_msg(self, msg: impl Into<String>) -> Result<O, CliError> {
        self.ok_or_else(|| CliError { error: msg.into() })
    }
}

// TODO: Refactor federation API errors to just delegate to this
impl From<FederationError> for CliError {
    fn from(e: FederationError) -> Self {
        CliError {
            error: e.to_string(),
        }
    }
}

impl Debug for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliError")
            .field("error", &self.error)
            .finish()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let json = serde_json::to_value(self).expect("CliError is valid json");
        let json_as_string =
            serde_json::to_string_pretty(&json).expect("valid json is serializable");
        write!(f, "{json_as_string}")
    }
}

impl Opts {
    fn data_dir(&self) -> CliResult<&PathBuf> {
        self.data_dir
            .as_ref()
            .ok_or_cli_msg("`--data-dir=` argument not set.")
    }

    /// Get and create if doesn't exist the data dir
    async fn data_dir_create(&self) -> CliResult<&PathBuf> {
        let dir = self.data_dir()?;

        tokio::fs::create_dir_all(&dir).await.map_err_cli()?;

        Ok(dir)
    }
    fn iroh_enable_dht(&self) -> bool {
        self.iroh_enable_dht.unwrap_or(true)
    }

    fn iroh_enable_next(&self) -> bool {
        self.iroh_enable_next.unwrap_or(true)
    }

    fn use_tor(&self) -> bool {
        #[cfg(feature = "tor")]
        return self.use_tor;
        #[cfg(not(feature = "tor"))]
        false
    }

    async fn admin_client(
        &self,
        peer_urls: &BTreeMap<PeerId, SafeUrl>,
        api_secret: Option<&str>,
    ) -> CliResult<DynGlobalApi> {
        self.admin_client_with_db(peer_urls, api_secret, None).await
    }

    async fn admin_client_with_db(
        &self,
        peer_urls: &BTreeMap<PeerId, SafeUrl>,
        api_secret: Option<&str>,
        db: Option<&Database>,
    ) -> CliResult<DynGlobalApi> {
        // First try CLI argument, then stored credentials
        let our_id = if let Some(id) = self.our_id {
            id
        } else if let Some(db) = db {
            if let Some(stored_creds) = load_admin_creds(db).await {
                stored_creds.peer_id
            } else {
                return Err(CliError {
                    error: "Admin client needs our-id set (no stored credentials found)"
                        .to_string(),
                });
            }
        } else {
            return Err(CliError {
                error: "Admin client needs our-id set".to_string(),
            });
        };

        DynGlobalApi::new_admin(
            self.make_endpoints().await.map_err(|e| CliError {
                error: e.to_string(),
            })?,
            our_id,
            peer_urls
                .get(&our_id)
                .cloned()
                .context("Our peer URL not found in config")
                .map_err_cli()?,
            api_secret,
        )
        .map_err_cli()
    }

    async fn make_endpoints(&self) -> Result<ConnectorRegistry, anyhow::Error> {
        ConnectorRegistry::build_from_client_defaults()
            .iroh_next(self.iroh_enable_next())
            .iroh_pkarr_dht(self.iroh_enable_dht())
            .ws_force_tor(self.use_tor())
            .bind()
            .await
    }

    fn auth(&self) -> CliResult<ApiAuth> {
        let password = self
            .password
            .clone()
            .ok_or_cli_msg("CLI needs password set")?;
        Ok(ApiAuth::new(password))
    }

    async fn load_database(&self) -> CliResult<Database> {
        debug!(target: LOG_CLIENT, "Loading client database");
        let db_path = self.data_dir_create().await?.join("client.db");
        match self.db_backend {
            DatabaseBackend::RocksDb => {
                debug!(target: LOG_CLIENT, "Using RocksDB database backend");
                Ok(fedimint_rocksdb::RocksDb::build(db_path)
                    .open()
                    .await
                    .map_err_cli_msg("could not open rocksdb database")?
                    .into())
            }
            DatabaseBackend::CursedRedb => {
                debug!(target: LOG_CLIENT, "Using CursedRedb database backend");
                Ok(fedimint_cursed_redb::MemAndRedb::new(db_path)
                    .await
                    .map_err_cli_msg("could not open cursed redb database")?
                    .into())
            }
        }
    }
}

fn decode_federation_secret_hex(federation_secret_hex: &str) -> CliResult<DerivableSecret> {
    <DerivableSecret as Decodable>::consensus_decode_hex(
        federation_secret_hex,
        &ModuleRegistry::default(),
    )
    .map_err_cli_msg("invalid federation secret hex")
}

enum RecoverySecret {
    Mnemonic(Mnemonic),
    FederationSecret(DerivableSecret),
}

fn root_secret_from_mnemonic(mnemonic: &Mnemonic) -> RootSecret {
    RootSecret::StandardDoubleDerive(Bip39RootSecretStrategy::<12>::to_root_secret(mnemonic))
}

async fn load_or_generate_mnemonic(db: &Database) -> Result<Mnemonic, CliError> {
    Ok(
        if let Ok(entropy) = Client::load_decodable_client_secret::<Vec<u8>>(db).await {
            Mnemonic::from_entropy(&entropy).map_err_cli()?
        } else {
            debug!(
                target: LOG_CLIENT,
                "Generating mnemonic and writing entropy to client storage"
            );
            let mnemonic = Bip39RootSecretStrategy::<12>::random(&mut thread_rng());
            Client::store_encodable_client_secret(db, mnemonic.to_entropy())
                .await
                .map_err_cli()?;
            mnemonic
        },
    )
}

async fn query_guardian_addresses(
    connectors: &ConnectorRegistry,
    endpoints: &BTreeMap<PeerId, fedimint_core::config::PeerUrl>,
    path_timeout: Duration,
) -> Vec<(PeerId, GuardianPrivacyReport)> {
    join_all(endpoints.iter().map(|(peer_id, peer_url)| async move {
        let mut report = GuardianPrivacyReport {
            name: peer_url.name.clone(),
            api_url: peer_url.url.clone(),
            addresses: BTreeMap::new(),
            iroh: None,
            error: None,
        };

        if peer_url.url.scheme() == "iroh" {
            match connectors.iroh_peer_info(&peer_url.url, path_timeout).await {
                Ok(Some(iroh_info)) => {
                    let direct_addr = iroh_info.direct_addr;
                    let known_direct_addrs = iroh_info.known_direct_addrs;
                    let known_direct_ips = known_direct_addrs
                        .iter()
                        .chain(direct_addr.iter())
                        .map(std::net::SocketAddr::ip)
                        .collect::<BTreeSet<_>>();

                    report.addresses = ip_info_map_from_ips(known_direct_ips);
                    report.iroh = Some(IrohConnectionReport {
                        node_id: iroh_info.node_id,
                        connectivity: connectivity_name(iroh_info.connectivity),
                        direct_addr: direct_addr.map(|addr| addr.to_string()),
                        relay_url: iroh_info.relay_url,
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    report.error = Some(error.to_string());
                }
            }
        } else {
            match resolve_endpoint_ips(&peer_url.url).await {
                Ok(ips) => {
                    report.addresses = ip_info_map_from_ips(ips);
                }
                Err(error) => {
                    report.error = Some(error.to_string());
                }
            }
        }

        (*peer_id, report)
    }))
    .await
}

fn ip_info_map_from_ips(ips: BTreeSet<IpAddr>) -> BTreeMap<String, IpInfoReport> {
    ips.into_iter()
        .map(|ip| {
            (
                ip.to_string(),
                IpInfoReport {
                    address_type: ip_address_type(ip),
                    ..IpInfoReport::default()
                },
            )
        })
        .collect()
}

async fn resolve_endpoint_ips(url: &SafeUrl) -> anyhow::Result<BTreeSet<IpAddr>> {
    let host = url
        .host_str()
        .context("endpoint URL does not contain a host")?;
    if let Ok(ip) = IpAddr::from_str(host) {
        return Ok(BTreeSet::from([ip]));
    }

    let port = endpoint_resolution_port(url).ok_or_else(|| {
        format_err!(
            "endpoint URL scheme {} does not have a known resolution port",
            url.scheme()
        )
    })?;

    let addresses = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve endpoint host {host}"))?
        .map(|addr| addr.ip())
        .collect();

    Ok(addresses)
}

fn endpoint_resolution_port(url: &SafeUrl) -> Option<u16> {
    url.port_or_known_default().or(match url.scheme() {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    })
}

fn all_iroh_guardians_direct(reports: &[(PeerId, GuardianPrivacyReport)]) -> bool {
    reports
        .iter()
        .filter(|(_, report)| report.api_url.scheme() == "iroh")
        .all(|(_, report)| {
            report
                .iroh
                .as_ref()
                .is_some_and(|iroh| matches!(iroh.connectivity, "direct" | "mixed"))
        })
}

async fn enrich_guardian_ip_info(reports: &mut [(PeerId, GuardianPrivacyReport)]) {
    let http_client = reqwest::Client::builder()
        .timeout(IP_LOOKUP_TIMEOUT)
        .build()
        .expect("IP lookup HTTP client config is valid");
    let unique_ips = reports
        .iter()
        .flat_map(|(_, report)| {
            report
                .addresses
                .iter()
                .filter(|(_, ip_info)| ip_info.address_type == "public")
                .filter_map(|(ip, _)| IpAddr::from_str(ip).ok())
        })
        .collect::<BTreeSet<_>>();

    let lookup_cache = join_all(unique_ips.into_iter().map(|ip| {
        let http_client = http_client.clone();
        async move { (ip.to_string(), lookup_ip_info(&http_client, ip).await) }
    }))
    .await
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    for (_, report) in reports {
        for (ip, ip_info) in &mut report.addresses {
            if let Some(lookup) = lookup_cache.get(ip) {
                *ip_info = IpInfoReport {
                    address_type: ip_info.address_type,
                    ..lookup.clone()
                };
            }
        }
    }
}

async fn lookup_ip_info(http_client: &reqwest::Client, ip: IpAddr) -> IpInfoReport {
    let url = format!("https://ipwho.is/{ip}");
    let response = http_client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status);

    let response = match response {
        Ok(response) => response,
        Err(error) => {
            return IpInfoReport {
                address_type: "public",
                country: None,
                asn: None,
                as_name: None,
                org: None,
                error: Some(error.to_string()),
            };
        }
    };

    match response.json::<IpWhoResponse>().await {
        Ok(body) if body.success.unwrap_or(true) => {
            let connection = body.connection;
            let asn = connection
                .as_ref()
                .and_then(|connection| connection.asn)
                .map(|asn| format!("AS{asn}"));
            let org = connection
                .as_ref()
                .and_then(|connection| connection.org.clone());
            let as_name = org
                .clone()
                .or_else(|| connection.and_then(|connection| connection.isp));

            IpInfoReport {
                address_type: "public",
                country: body.country_code.or(body.country),
                asn,
                as_name,
                org,
                error: None,
            }
        }
        Ok(body) => IpInfoReport {
            address_type: "public",
            country: None,
            asn: None,
            as_name: None,
            org: None,
            error: Some(
                body.message
                    .unwrap_or_else(|| "IP lookup service returned an error".to_owned()),
            ),
        },
        Err(error) => IpInfoReport {
            address_type: "public",
            country: None,
            asn: None,
            as_name: None,
            org: None,
            error: Some(error.to_string()),
        },
    }
}

fn summarize_privacy_report<'a>(
    reports: impl IntoIterator<Item = &'a GuardianPrivacyReport>,
) -> FederationPrivacySummary {
    let mut countries = BTreeMap::new();
    let mut autonomous_systems = BTreeMap::new();
    let mut unique_public_ips = BTreeSet::new();
    let reports = reports.into_iter().collect::<Vec<_>>();

    for report in &reports {
        let mut guardian_countries = BTreeSet::new();
        let mut guardian_autonomous_systems = BTreeSet::new();

        unique_public_ips.extend(
            report
                .addresses
                .iter()
                .filter(|(_, ip_info)| ip_info.address_type == "public")
                .map(|(ip, _)| ip.clone()),
        );

        for ip_info in report
            .addresses
            .values()
            .filter(|ip_info| ip_info.address_type == "public")
        {
            if let Some(country) = &ip_info.country {
                guardian_countries.insert(country.clone());
            }
            let as_label = match (&ip_info.asn, &ip_info.as_name) {
                (Some(asn), Some(as_name)) => Some(format!("{asn} {as_name}")),
                (Some(asn), None) => Some(asn.clone()),
                (None, Some(as_name)) => Some(as_name.clone()),
                (None, None) => None,
            };
            if let Some(as_label) = as_label {
                guardian_autonomous_systems.insert(as_label);
            }
        }

        for country in guardian_countries {
            *countries.entry(country).or_insert(0) += 1;
        }
        for autonomous_system in guardian_autonomous_systems {
            *autonomous_systems.entry(autonomous_system).or_insert(0) += 1;
        }
    }

    FederationPrivacySummary {
        guardian_count: reports.len(),
        iroh_guardian_count: reports
            .iter()
            .filter(|report| report.api_url.scheme() == "iroh")
            .count(),
        resolved_guardian_count: reports
            .iter()
            .filter(|report| !report.addresses.is_empty())
            .count(),
        iroh_direct_guardian_count: reports
            .iter()
            .filter(|report| {
                report
                    .iroh
                    .as_ref()
                    .is_some_and(|iroh| matches!(iroh.connectivity, "direct" | "mixed"))
            })
            .count(),
        iroh_relayed_guardian_count: reports
            .iter()
            .filter(|report| {
                report
                    .iroh
                    .as_ref()
                    .is_some_and(|iroh| iroh.connectivity == "relay")
            })
            .count(),
        public_ip_count: unique_public_ips.len(),
        countries,
        autonomous_systems,
    }
}

fn connectivity_name(connectivity: Connectivity) -> &'static str {
    match connectivity {
        Connectivity::Direct => "direct",
        Connectivity::Relay => "relay",
        Connectivity::Mixed => "mixed",
        Connectivity::Tor => "tor",
        Connectivity::Unknown => "unknown",
    }
}

fn ip_address_type(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(ip) => {
            if ip.is_private() {
                "private"
            } else if ip.is_loopback() {
                "loopback"
            } else if ip.is_link_local() {
                "link_local"
            } else if ip.is_broadcast() {
                "broadcast"
            } else if matches!(
                ip.octets(),
                [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
            ) {
                "documentation"
            } else if matches!(ip.octets(), [100, second, _, _] if (64..=127).contains(&second)) {
                "shared"
            } else if matches!(ip.octets(), [198, 18 | 19, _, _]) {
                "benchmark"
            } else if ip.is_multicast() {
                "multicast"
            } else if ip.is_unspecified() {
                "unspecified"
            } else {
                "public"
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() {
                "loopback"
            } else if ip.is_unspecified() {
                "unspecified"
            } else if ip.is_unique_local() {
                "unique_local"
            } else if ip.is_unicast_link_local() {
                "link_local"
            } else if ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8 {
                "documentation"
            } else if ip.is_multicast() {
                "multicast"
            } else {
                "public"
            }
        }
    }
}

pub struct FedimintCli {
    module_inits: ClientModuleInitRegistry,
    cli_args: Opts,
}

impl FedimintCli {
    /// Build a new `fedimintd` with a custom version hash
    pub fn new(version_hash: &str) -> anyhow::Result<FedimintCli> {
        assert_eq!(
            fedimint_build_code_version_env!().len(),
            version_hash.len(),
            "version_hash must have an expected length"
        );

        handle_version_hash_command(version_hash);

        let cli_args = Opts::parse();
        let base_level = if cli_args.verbose { "debug" } else { "info" };
        TracingSetup::default()
            .with_base_level(base_level)
            .init()
            .expect("tracing initializes");

        let version = env!("CARGO_PKG_VERSION");
        debug!(target: LOG_CLIENT, "Starting fedimint-cli (version: {version} version_hash: {version_hash})");

        Ok(Self {
            module_inits: ClientModuleInitRegistry::new(),
            cli_args,
        })
    }

    pub fn with_module<T>(mut self, r#gen: T) -> Self
    where
        T: ClientModuleInit + 'static + Send + Sync,
    {
        self.module_inits.attach(r#gen);
        self
    }

    pub fn with_default_modules(self) -> Self {
        self.with_module(LightningClientInit::default())
            .with_module(MintClientInit)
            .with_module(fedimint_mintv2_client::MintClientInit)
            .with_module(WalletClientInit::default())
            .with_module(MetaClientInit)
            .with_module(fedimint_lnv2_client::LightningClientInit::default())
            .with_module(fedimint_walletv2_client::WalletClientInit)
    }

    pub async fn run(&mut self) {
        match self.handle_command(self.cli_args.clone()).await {
            Ok(output) => {
                // ignore if there's anyone reading the stuff we're writing out
                let _ = writeln!(std::io::stdout(), "{output}");
            }
            Err(err) => {
                debug!(target: LOG_CLIENT, err = %err.error.as_str(), "Command failed");
                let _ = writeln!(std::io::stdout(), "{err}");
                exit(1);
            }
        }
    }

    async fn make_client_builder(&self, cli: &Opts) -> CliResult<(ClientBuilder, Database)> {
        let mut client_builder = Client::builder()
            .await
            .map_err_cli()?
            .with_iroh_enable_dht(cli.iroh_enable_dht())
            .with_iroh_enable_next(cli.iroh_enable_next());
        client_builder.with_module_inits(self.module_inits.clone());

        let db = cli.load_database().await?;
        Ok((client_builder, db))
    }

    async fn client_join(
        &mut self,
        cli: &Opts,
        invite_code: InviteCode,
    ) -> CliResult<ClientHandleArc> {
        let (client_builder, db) = self.make_client_builder(cli).await?;

        let mnemonic = load_or_generate_mnemonic(&db).await?;

        let client = client_builder
            .preview(cli.make_endpoints().await.map_err_cli()?, &invite_code)
            .await
            .map_err_cli()?
            .join(db, root_secret_from_mnemonic(&mnemonic))
            .await
            .map(Arc::new)
            .map_err_cli()?;

        print_welcome_message(&client).await;
        log_expiration_notice(&client).await;

        Ok(client)
    }

    async fn client_open(&self, cli: &Opts) -> CliResult<ClientHandleArc> {
        let (mut client_builder, db) = self.make_client_builder(cli).await?;

        // Use CLI args if provided, otherwise try to load stored credentials
        if let Some(our_id) = cli.our_id {
            client_builder.set_admin_creds(AdminCreds {
                peer_id: our_id,
                auth: cli.auth()?,
            });
        } else if let Some(stored_creds) = load_admin_creds(&db).await {
            debug!(target: LOG_CLIENT, "Using stored admin credentials");
            client_builder.set_admin_creds(AdminCreds {
                peer_id: stored_creds.peer_id,
                auth: ApiAuth::new(stored_creds.auth),
            });
        }

        let existing_mnemonic = Client::load_decodable_client_secret_opt::<Vec<u8>>(&db)
            .await
            .map_err_cli()?;

        let root_secret = match (cli.federation_secret_hex.as_deref(), existing_mnemonic) {
            (Some(_), Some(_)) => {
                return Err(CliError {
                    error: "client secret is already set in DB; --federation-secret-hex open requires a client DB without any stored secret".to_owned(),
                });
            }
            (Some(federation_secret_hex), None) => {
                RootSecret::Custom(decode_federation_secret_hex(federation_secret_hex)?)
            }
            (None, Some(entropy)) => {
                let mnemonic = Mnemonic::from_entropy(&entropy).map_err_cli()?;
                root_secret_from_mnemonic(&mnemonic)
            }
            (None, None) => {
                return Err(CliError {
                    error: "Encoded client secret not present in DB".to_owned(),
                });
            }
        };

        let client = client_builder
            .open(cli.make_endpoints().await.map_err_cli()?, db, root_secret)
            .await
            .map(Arc::new)
            .map_err_cli()?;

        log_expiration_notice(&client).await;

        Ok(client)
    }

    async fn federation_ip_query(
        &self,
        cli: &Opts,
        invite_code: &InviteCode,
        path_timeout: Duration,
        require_direct: bool,
    ) -> CliResult<FederationPrivacyReport> {
        let connectors = cli.make_endpoints().await.map_err_cli()?;
        let (config, _api) = download_from_invite_code(&connectors, invite_code)
            .await
            .map_err_cli_msg("failed to download federation config from invite code")?;

        let federation_id = config.calculate_federation_id();
        let endpoints = config.global.api_endpoints;
        if require_direct
            && !endpoints
                .values()
                .any(|peer_url| peer_url.url.scheme() == "iroh")
        {
            return Err(CliError {
                error: "--require-direct requires at least one iroh guardian endpoint".to_owned(),
            });
        }
        let report_timeout = if require_direct {
            Duration::ZERO
        } else {
            path_timeout
        };
        let mut guardian_reports =
            query_guardian_addresses(&connectors, &endpoints, report_timeout).await;

        if require_direct {
            let deadline = fedimint_core::time::now() + path_timeout;
            while !all_iroh_guardians_direct(&guardian_reports)
                && fedimint_core::time::now() < deadline
            {
                runtime::sleep(Duration::from_millis(250)).await;
                guardian_reports =
                    query_guardian_addresses(&connectors, &endpoints, Duration::ZERO).await;
            }

            if !all_iroh_guardians_direct(&guardian_reports) {
                let not_direct = guardian_reports
                    .iter()
                    .filter(|(_, report)| {
                        report.api_url.scheme() == "iroh"
                            && !report
                                .iroh
                                .as_ref()
                                .is_some_and(|iroh| matches!(iroh.connectivity, "direct" | "mixed"))
                    })
                    .map(|(peer_id, _)| peer_id.to_string())
                    .join(", ");
                return Err(CliError {
                    error: format!(
                        "not all iroh guardians reached a direct path within {path_timeout:?}; pending peers: {not_direct}"
                    ),
                });
            }
        }

        enrich_guardian_ip_info(&mut guardian_reports).await;
        let summary = summarize_privacy_report(guardian_reports.iter().map(|(_, report)| report));
        let guardians = guardian_reports
            .into_iter()
            .map(|(peer_id, report)| (peer_id.to_string(), report))
            .collect();

        Ok(FederationPrivacyReport {
            federation_id,
            guardians,
            summary,
        })
    }

    async fn client_recover(
        &mut self,
        cli: &Opts,
        recovery_secret: RecoverySecret,
        invite_code: InviteCode,
    ) -> CliResult<ClientHandleArc> {
        let (builder, db) = self.make_client_builder(cli).await?;
        let existing_mnemonic = Client::load_decodable_client_secret_opt::<Vec<u8>>(&db)
            .await
            .map_err_cli()?;

        let root_secret = match (recovery_secret, existing_mnemonic) {
            (RecoverySecret::Mnemonic(mnemonic), Some(existing)) => {
                if existing != mnemonic.to_entropy() {
                    Err(anyhow::anyhow!("Previously set mnemonic does not match")).map_err_cli()?;
                }

                root_secret_from_mnemonic(&mnemonic)
            }
            (RecoverySecret::Mnemonic(mnemonic), None) => {
                Client::store_encodable_client_secret(&db, mnemonic.to_entropy())
                    .await
                    .map_err_cli()?;
                root_secret_from_mnemonic(&mnemonic)
            }
            (RecoverySecret::FederationSecret(federation_secret), None) => {
                RootSecret::Custom(federation_secret)
            }
            (RecoverySecret::FederationSecret(_), Some(_)) => {
                return Err(CliError {
                    error: "client secret is already set in DB; --federation-secret-hex restore requires a client DB without any stored secret".to_owned(),
                });
            }
        };

        let preview = builder
            .preview(cli.make_endpoints().await.map_err_cli()?, &invite_code)
            .await
            .map_err_cli()?;

        #[allow(deprecated)]
        let backup = preview
            .download_backup_from_federation(root_secret.clone())
            .await
            .map_err_cli()?;

        let client = preview
            .recover(db, root_secret, backup)
            .await
            .map(Arc::new)
            .map_err_cli()?;

        print_welcome_message(&client).await;
        log_expiration_notice(&client).await;

        Ok(client)
    }

    async fn handle_command(&mut self, cli: Opts) -> CliOutputResult {
        if cli.federation_secret_hex.is_some() && matches!(&cli.command, Command::Join { .. }) {
            return Err(CliError {
                error: "--federation-secret-hex cannot be used with join".to_owned(),
            });
        }

        match cli.command.clone() {
            Command::Join { invite_code } => {
                {
                    let invite_code: InviteCode = InviteCode::from_str(&invite_code)
                        .map_err_cli_msg("invalid invite code")?;

                    // Build client and store config in DB
                    let _client = self.client_join(&cli, invite_code).await?;
                }

                Ok(CliOutput::Join {
                    joined: invite_code,
                })
            }
            Command::VersionHash => Ok(CliOutput::VersionHash {
                hash: fedimint_build_code_version_env!().to_string(),
            }),
            Command::Client(ClientCmd::Restore {
                mnemonic,
                invite_code,
            }) => {
                let invite_code: InviteCode =
                    InviteCode::from_str(&invite_code).map_err_cli_msg("invalid invite code")?;
                let recovery_secret = match (
                    mnemonic.as_deref(),
                    cli.federation_secret_hex.as_deref(),
                ) {
                    (Some(_), Some(_)) => {
                        return Err(CliError {
                            error: "restore accepts either --mnemonic or --federation-secret-hex, not both".to_owned(),
                        });
                    }
                    (Some(mnemonic), None) => {
                        let mnemonic = Mnemonic::from_str(mnemonic).map_err_cli()?;
                        RecoverySecret::Mnemonic(mnemonic)
                    }
                    (None, Some(federation_secret_hex)) => {
                        let federation_secret =
                            decode_federation_secret_hex(federation_secret_hex)?;
                        RecoverySecret::FederationSecret(federation_secret)
                    }
                    (None, None) => {
                        return Err(CliError {
                            error: "restore requires either --mnemonic or --federation-secret-hex"
                                .to_owned(),
                        });
                    }
                };
                let client = self
                    .client_recover(&cli, recovery_secret, invite_code)
                    .await?;

                // TODO: until we implement recovery for other modules we can't really wait
                // for more than this one
                debug!(target: LOG_CLIENT, "Waiting for mint module recovery to finish");
                client.wait_for_all_recoveries().await.map_err_cli()?;

                debug!(target: LOG_CLIENT, "Recovery complete");

                Ok(CliOutput::Raw(
                    serde_json::to_value(()).expect("unit type is serializable"),
                ))
            }
            Command::Client(command) => {
                let client = self.client_open(&cli).await?;
                Ok(CliOutput::Raw(
                    client::handle_command(command, client)
                        .await
                        .map_err_cli()?,
                ))
            }
            Command::Admin(AdminCmd::Auth {
                peer_id,
                password,
                no_verify,
                force,
            }) => {
                let db = cli.load_database().await?;
                let peer_id = PeerId::from(peer_id);
                let auth = ApiAuth::new(password);

                // Check if credentials already exist
                if !force {
                    let existing = load_admin_creds(&db).await;
                    if existing.is_some() {
                        return Err(CliError {
                            error: "Admin credentials already stored. Use --force to overwrite."
                                .to_string(),
                        });
                    }
                }

                // Load client config to get peer endpoints
                let config = Client::get_config_from_db(&db)
                    .await
                    .ok_or_cli_msg("Client not initialized. Please join a federation first.")?;

                // Get the endpoint for the specified peer
                let peer_url =
                    config
                        .global
                        .api_endpoints
                        .get(&peer_id)
                        .ok_or_else(|| CliError {
                            error: format!(
                                "Peer ID {} not found in federation. Valid peer IDs are: {:?}",
                                peer_id,
                                config.global.api_endpoints.keys().collect::<Vec<_>>()
                            ),
                        })?;

                // Interactive verification unless --no-verify is set
                if !no_verify {
                    // Check if stdin is a terminal for interactive prompts
                    if !std::io::stdin().is_terminal() {
                        return Err(CliError {
                            error: "Interactive verification requires a terminal. Use --no-verify to skip.".to_string(),
                        });
                    }

                    eprintln!("Guardian endpoint for peer {}: {}", peer_id, peer_url.url);
                    eprint!("Does this look correct? (y/N): ");
                    std::io::stderr().flush().map_err_cli()?;

                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).map_err_cli()?;
                    let input = input.trim().to_lowercase();

                    if input != "y" && input != "yes" {
                        return Err(CliError {
                            error: "Endpoint verification cancelled by user.".to_string(),
                        });
                    }
                }

                // Verify credentials by making an authenticated API call
                eprintln!("Verifying credentials...");
                let admin_api = DynGlobalApi::new_admin(
                    cli.make_endpoints().await.map_err_cli()?,
                    peer_id,
                    peer_url.url.clone(),
                    db.begin_transaction_nc()
                        .await
                        .get_value(&ApiSecretKey)
                        .await
                        .as_deref(),
                )
                .map_err_cli()?;

                // Use the `auth` endpoint to verify credentials
                admin_api.auth(auth.clone()).await.map_err(|e| CliError {
                    error: format!(
                        "Failed to verify credentials: {e}. Please check your peer ID and password."
                    ),
                })?;

                // Store the credentials in the database
                store_admin_creds(
                    &db,
                    &StoredAdminCreds {
                        peer_id,
                        auth: auth.as_str().to_string(),
                    },
                )
                .await;

                eprintln!("Admin credentials verified and saved successfully.");
                Ok(CliOutput::Raw(json!({
                    "peer_id": peer_id,
                    "endpoint": peer_url.url.to_string(),
                    "status": "saved"
                })))
            }
            Command::Admin(AdminCmd::Audit) => {
                let client = self.client_open(&cli).await?;

                let audit = cli
                    .admin_client(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .audit(cli.auth()?)
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(audit).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Status) => {
                let client = self.client_open(&cli).await?;

                let status = cli
                    .admin_client_with_db(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                        Some(client.db()),
                    )
                    .await?
                    .status()
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(status).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::GuardianConfigBackup) => {
                let client = self.client_open(&cli).await?;

                let guardian_config_backup = cli
                    .admin_client(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .guardian_config_backup(cli.auth()?)
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(guardian_config_backup)
                        .map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Setup(dkg_args)) => self
                .handle_admin_setup_command(cli, dkg_args)
                .await
                .map(CliOutput::Raw)
                .map_err_cli_msg("Config Gen Error"),
            Command::Admin(AdminCmd::SignApiAnnouncement {
                api_url,
                override_url,
            }) => {
                let client = self.client_open(&cli).await?;

                if !["ws", "wss"].contains(&api_url.scheme()) {
                    return Err(CliError {
                        error: format!(
                            "Unsupported URL scheme {}, use ws:// or wss://",
                            api_url.scheme()
                        ),
                    });
                }

                let announcement = cli
                    .admin_client(
                        &override_url
                            .and_then(|url| Some(vec![(cli.our_id?, url)].into_iter().collect()))
                            .unwrap_or(client.get_peer_urls().await),
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .sign_api_announcement(api_url, cli.auth()?)
                    .await?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(announcement).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::SignGuardianMetadata { api_urls, pkarr_id }) => {
                let client = self.client_open(&cli).await?;

                let metadata = fedimint_core::net::guardian_metadata::GuardianMetadata {
                    api_urls,
                    pkarr_id_z32: pkarr_id,
                    timestamp_secs: fedimint_core::time::duration_since_epoch().as_secs(),
                };

                let signed_metadata = cli
                    .admin_client(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .sign_guardian_metadata(metadata, cli.auth()?)
                    .await?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(signed_metadata).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Shutdown { session_idx }) => {
                let client = self.client_open(&cli).await?;

                cli.admin_client(
                    &client.get_peer_urls().await,
                    client.api_secret().as_deref(),
                )
                .await?
                .shutdown(Some(session_idx), cli.auth()?)
                .await?;

                Ok(CliOutput::Raw(json!(null)))
            }
            Command::Admin(AdminCmd::BackupStatistics) => {
                let client = self.client_open(&cli).await?;

                let backup_statistics = cli
                    .admin_client(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .backup_statistics(cli.auth()?)
                    .await?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(backup_statistics).expect("Can be encoded"),
                ))
            }
            Command::Admin(AdminCmd::ChangePassword { new_password }) => {
                let client = self.client_open(&cli).await?;

                cli.admin_client(
                    &client.get_peer_urls().await,
                    client.api_secret().as_deref(),
                )
                .await?
                .change_password(cli.auth()?, &new_password)
                .await?;

                warn!(target: LOG_CLIENT, "Password changed, please restart fedimintd manually");

                Ok(CliOutput::Raw(json!(null)))
            }
            Command::Dev(DevCmd::Api {
                method,
                params,
                peer_id,
                password: auth,
                module,
            }) => {
                //Parse params to JSON.
                //If fails, convert to JSON string.
                let params = serde_json::from_str::<Value>(&params).unwrap_or_else(|err| {
                    debug!(
                        target: LOG_CLIENT,
                        "Failed to serialize params:{}. Converting it to JSON string",
                        err
                    );

                    serde_json::Value::String(params)
                });

                let mut params = ApiRequestErased::new(params);
                if let Some(auth) = auth {
                    params = params.with_auth(ApiAuth::new(auth));
                }
                let client = self.client_open(&cli).await?;

                let api = client.api_clone();

                let module_api = match module {
                    Some(selector) => {
                        Some(api.with_module(selector.resolve(&client).map_err_cli()?))
                    }
                    None => None,
                };

                let response: Value = match (peer_id, module_api) {
                    (Some(peer_id), Some(module_api)) => module_api
                        .request_raw(peer_id.into(), &method, &params)
                        .await
                        .map_err_cli()?,
                    (Some(peer_id), None) => api
                        .request_raw(peer_id.into(), &method, &params)
                        .await
                        .map_err_cli()?,
                    (None, Some(module_api)) => module_api
                        .request_current_consensus(method, params)
                        .await
                        .map_err_cli()?,
                    (None, None) => api
                        .request_current_consensus(method, params)
                        .await
                        .map_err_cli()?,
                };

                Ok(CliOutput::UntypedApiOutput { value: response })
            }
            Command::Dev(DevCmd::AdvanceNoteIdx { count, amount }) => {
                let client = self.client_open(&cli).await?;

                let mint = client
                    .get_first_module::<MintClientModule>()
                    .map_err_cli_msg("can't get mint module")?;

                for _ in 0..count {
                    mint.advance_note_idx(amount)
                        .await
                        .map_err_cli_msg("failed to advance the note_idx")?;
                }

                Ok(CliOutput::Raw(serde_json::Value::Null))
            }
            Command::Dev(DevCmd::ApiAnnouncements) => {
                let client = self.client_open(&cli).await?;
                let announcements = client.get_peer_url_announcements().await;
                Ok(CliOutput::Raw(
                    serde_json::to_value(announcements).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::GuardianMetadata) => {
                let client = self.client_open(&cli).await?;
                let metadata = client.get_guardian_metadata().await;
                Ok(CliOutput::Raw(
                    serde_json::to_value(metadata).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::WaitBlockCount { count: target }) => retry(
                "wait_block_count",
                backoff_util::custom_backoff(
                    Duration::from_millis(100),
                    Duration::from_secs(5),
                    None,
                ),
                || async {
                    let client = self.client_open(&cli).await?;
                    let wallet = client.get_first_module::<WalletClientModule>()?;
                    let count = client
                        .api()
                        .with_module(wallet.id)
                        .fetch_consensus_block_count()
                        .await?;
                    if count >= target {
                        Ok(CliOutput::WaitBlockCount { reached: count })
                    } else {
                        info!(target: LOG_CLIENT, current=count, target, "Block count not reached");
                        Err(format_err!("target not reached"))
                    }
                },
            )
            .await
            .map_err_cli(),

            Command::Dev(DevCmd::WaitComplete) => {
                let client = self.client_open(&cli).await?;
                client
                    .wait_for_all_active_state_machines()
                    .await
                    .map_err_cli_msg("failed to wait for all active state machines")?;
                Ok(CliOutput::Raw(serde_json::Value::Null))
            }
            Command::Dev(DevCmd::Wait { seconds }) => {
                let client = self.client_open(&cli).await?;
                // Since most callers are `wait`ing for something to happen,
                // let's trigger a network call, so any background threads
                // waiting for it starts doing their job.
                client
                    .task_group()
                    .spawn_cancellable("fedimint-cli dev wait: init networking", {
                        let client = client.clone();
                        async move {
                            let _ = client.api().session_count().await;
                        }
                    });

                if let Some(secs) = seconds {
                    runtime::sleep(Duration::from_secs_f32(secs)).await;
                } else {
                    pending::<()>().await;
                }
                Ok(CliOutput::Raw(serde_json::Value::Null))
            }
            Command::Dev(DevCmd::Decode { decode_type }) => match decode_type {
                DecodeType::InviteCode { invite_code } => Ok(CliOutput::DecodeInviteCode {
                    url: invite_code.url(),
                    federation_id: invite_code.federation_id(),
                }),
                DecodeType::Notes { notes, file } => {
                    let notes = if let Some(notes) = notes {
                        notes
                    } else if let Some(file) = file {
                        let notes_str =
                            fs::read_to_string(file).map_err_cli_msg("failed to read file")?;
                        OOBNotes::from_str(&notes_str).map_err_cli_msg("failed to decode notes")?
                    } else {
                        unreachable!("Clap enforces either notes or file being set");
                    };

                    let notes_json = notes
                        .notes_json()
                        .map_err_cli_msg("failed to decode notes")?;
                    Ok(CliOutput::Raw(notes_json))
                }
                DecodeType::Transaction { hex_string } => {
                    let bytes: Vec<u8> = hex::FromHex::from_hex(&hex_string)
                        .map_err_cli_msg("failed to decode transaction")?;

                    let client = self.client_open(&cli).await?;
                    let tx = fedimint_core::transaction::Transaction::from_bytes(
                        &bytes,
                        client.decoders(),
                    )
                    .map_err_cli_msg("failed to decode transaction")?;

                    Ok(CliOutput::DecodeTransaction {
                        transaction: (format!("{tx:?}")),
                    })
                }
                DecodeType::SetupCode { setup_code } => {
                    let setup_code = base32::decode_prefixed(FEDIMINT_PREFIX, &setup_code)
                        .map_err_cli_msg("failed to decode setup code")?;

                    Ok(CliOutput::SetupCode { setup_code })
                }
            },
            Command::Dev(DevCmd::Encode { encode_type }) => match encode_type {
                EncodeType::InviteCode {
                    url,
                    federation_id,
                    peer,
                    api_secret,
                } => Ok(CliOutput::InviteCode {
                    invite_code: InviteCode::new(url, peer, federation_id, api_secret),
                }),
                EncodeType::Notes { notes_json } => {
                    let notes = serde_json::from_str::<OOBNotesJson>(&notes_json)
                        .map_err_cli_msg("invalid JSON for notes")?;
                    let prefix =
                        FederationIdPrefix::from_str(&notes.federation_id_prefix).map_err_cli()?;
                    let notes = OOBNotes::new(prefix, notes.notes);
                    Ok(CliOutput::Raw(notes.to_string().into()))
                }
            },
            Command::Dev(DevCmd::SessionCount) => {
                let client = self.client_open(&cli).await?;
                let count = client.api().session_count().await?;
                Ok(CliOutput::EpochCount { count })
            }
            Command::Dev(DevCmd::QueryFederationIps {
                invite_code,
                path_timeout_seconds,
                require_direct,
            }) => {
                let report = self
                    .federation_ip_query(
                        &cli,
                        &invite_code,
                        Duration::from_secs(path_timeout_seconds),
                        require_direct,
                    )
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(report).expect("privacy report is serializable"),
                ))
            }
            Command::Dev(DevCmd::Config) => {
                let client = self.client_open(&cli).await?;
                let config = client.get_config_json().await;
                Ok(CliOutput::Raw(
                    serde_json::to_value(config).expect("Client config is serializable"),
                ))
            }
            Command::Dev(DevCmd::ConfigDecrypt {
                in_file,
                out_file,
                salt_file,
                password,
            }) => {
                let salt_file = salt_file.unwrap_or_else(|| salt_from_file_path(&in_file));
                let salt = fs::read_to_string(salt_file).map_err_cli()?;
                let key = get_encryption_key(&password, &salt).map_err_cli()?;
                let decrypted_bytes = encrypted_read(&key, in_file).map_err_cli()?;

                let mut out_file_handle = fs::File::options()
                    .create_new(true)
                    .write(true)
                    .open(out_file)
                    .expect("Could not create output cfg file");
                out_file_handle.write_all(&decrypted_bytes).map_err_cli()?;
                Ok(CliOutput::ConfigDecrypt)
            }
            Command::Dev(DevCmd::ConfigEncrypt {
                in_file,
                out_file,
                salt_file,
                password,
            }) => {
                let mut in_file_handle =
                    fs::File::open(in_file).expect("Could not create output cfg file");
                let mut plaintext_bytes = vec![];
                in_file_handle
                    .read_to_end(&mut plaintext_bytes)
                    .expect("Could not read input cfg file");

                let salt_file = salt_file.unwrap_or_else(|| salt_from_file_path(&out_file));
                let salt = fs::read_to_string(salt_file).map_err_cli()?;
                let key = get_encryption_key(&password, &salt).map_err_cli()?;
                encrypted_write(plaintext_bytes, &key, out_file).map_err_cli()?;
                Ok(CliOutput::ConfigEncrypt)
            }
            Command::Dev(DevCmd::ListOperationStates { operation_id }) => {
                #[derive(Serialize)]
                struct ReactorLogState {
                    active: bool,
                    module_instance: ModuleInstanceId,
                    creation_time: String,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    end_time: Option<String>,
                    state: String,
                }

                let client = self.client_open(&cli).await?;

                let (active_states, inactive_states) =
                    client.executor().get_operation_states(operation_id).await;
                let all_states =
                    active_states
                        .into_iter()
                        .map(|(active_state, active_meta)| ReactorLogState {
                            active: true,
                            module_instance: active_state.module_instance_id(),
                            creation_time: crate::client::time_to_iso8601(&active_meta.created_at),
                            end_time: None,
                            state: format!("{active_state:?}",),
                        })
                        .chain(inactive_states.into_iter().map(
                            |(inactive_state, inactive_meta)| ReactorLogState {
                                active: false,
                                module_instance: inactive_state.module_instance_id(),
                                creation_time: crate::client::time_to_iso8601(
                                    &inactive_meta.created_at,
                                ),
                                end_time: Some(crate::client::time_to_iso8601(
                                    &inactive_meta.exited_at,
                                )),
                                state: format!("{inactive_state:?}",),
                            },
                        ))
                        .sorted_by(|a, b| a.creation_time.cmp(&b.creation_time))
                        .collect::<Vec<_>>();

                Ok(CliOutput::Raw(json!({
                    "states": all_states
                })))
            }
            Command::Dev(DevCmd::MetaFields) => {
                let client = self.client_open(&cli).await?;
                let source = MetaModuleMetaSourceWithFallback::<LegacyMetaSource>::default();

                let meta_fields = source
                    .fetch(
                        &client.config().await,
                        &client.api_clone(),
                        FetchKind::Initial,
                        None,
                    )
                    .await
                    .map_err_cli()?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(meta_fields).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::PeerVersion { peer_id }) => {
                let client = self.client_open(&cli).await?;
                let version = client
                    .api()
                    .fedimintd_version(peer_id.into())
                    .await
                    .map_err_cli()?;

                Ok(CliOutput::Raw(json!({ "version": version })))
            }
            Command::Dev(DevCmd::ShowEventLog { pos, limit }) => {
                let client = self.client_open(&cli).await?;

                let events: Vec<_> = client
                    .get_event_log(pos, limit)
                    .await
                    .into_iter()
                    .map(|v| {
                        let id = v.id();
                        let v = v.as_raw();
                        let module_id = v.module.as_ref().map(|m| m.1);
                        let module_kind = v.module.as_ref().map(|m| m.0.clone());
                        serde_json::json!({
                            "id": id,
                            "kind": v.kind,
                            "module_kind": module_kind,
                            "module_id": module_id,
                            "ts": v.ts_usecs,
                            "payload": serde_json::from_slice(&v.payload).unwrap_or_else(|_| hex::encode(&v.payload)),
                        })
                    })
                    .collect();

                Ok(CliOutput::Raw(
                    serde_json::to_value(events).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::ShowEventLogTrimable { pos, limit }) => {
                let client = self.client_open(&cli).await?;

                let events: Vec<_> = client
                    .get_event_log_trimable(
                        pos.map(|id| EventLogTrimableId::from(u64::from(id))),
                        limit,
                    )
                    .await
                    .into_iter()
                    .map(|v| {
                        let id = v.id();
                        let v = v.as_raw();
                        let module_id = v.module.as_ref().map(|m| m.1);
                        let module_kind = v.module.as_ref().map(|m| m.0.clone());
                        serde_json::json!({
                            "id": id,
                            "kind": v.kind,
                            "module_kind": module_kind,
                            "module_id": module_id,
                            "ts": v.ts_usecs,
                            "payload": serde_json::from_slice(&v.payload).unwrap_or_else(|_| hex::encode(&v.payload)),
                        })
                    })
                    .collect();

                Ok(CliOutput::Raw(
                    serde_json::to_value(events).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::NextEventLogId) => {
                let client = self.client_open(&cli).await?;

                let id = client.get_next_event_log_id().await;

                Ok(CliOutput::Raw(
                    serde_json::to_value(id).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::SubmitTransaction { transaction }) => {
                let client = self.client_open(&cli).await?;
                let tx = Transaction::consensus_decode_hex(&transaction, client.decoders())
                    .map_err_cli()?;
                let tx_outcome = client
                    .api()
                    .submit_transaction(tx)
                    .await
                    .try_into_inner(client.decoders())
                    .map_err_cli()?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(tx_outcome.0.map_err_cli()?).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::TestEventLogHandling) => {
                let client = self.client_open(&cli).await?;

                client
                    .handle_events(
                        client.built_in_application_event_log_tracker(),
                        move |_dbtx, event| {
                            Box::pin(async move {
                                info!(target: LOG_CLIENT, "{event:?}");

                                Ok(())
                            })
                        },
                    )
                    .await
                    .map_err_cli()?;
                unreachable!(
                    "handle_events exits only if client shuts down, which we don't do here"
                )
            }
            Command::Dev(DevCmd::Panic) => {
                panic!("This panic is intentional for testing backtrace handling");
            }
            Command::Dev(DevCmd::ChainId) => {
                let client = self.client_open(&cli).await?;
                let chain_id = client
                    .db()
                    .begin_transaction_nc()
                    .await
                    .get_value(&fedimint_client::db::ChainIdKey)
                    .await
                    .ok_or_cli_msg("Chain ID not cached in client database")?;

                Ok(CliOutput::Raw(serde_json::json!({
                    "chain_id": chain_id.to_string()
                })))
            }
            Command::Dev(DevCmd::Visualize { visualize_type }) => {
                let client = self.client_open(&cli).await?;

                match visualize_type {
                    VisualizeCmd::Notes { limit } => {
                        visualize::cmd_notes(&client, limit).await?;
                    }
                    VisualizeCmd::Transactions {
                        operation_id,
                        limit,
                    } => {
                        visualize::cmd_transactions(&client, operation_id, limit).await?;
                    }
                    VisualizeCmd::Operations {
                        operation_id,
                        limit,
                    } => {
                        visualize::cmd_operations(&client, operation_id, limit).await?;
                    }
                }
                Ok(CliOutput::Raw(json!({})))
            }
            Command::Dev(DevCmd::RefreshApiVersions) => {
                let client = self.client_open(&cli).await?;
                let versions = client.refresh_api_versions().await.map_err_cli()?;
                Ok(CliOutput::Raw(json!({ "versions": versions })))
            }
            Command::Completion { shell } => {
                let bin_path = PathBuf::from(
                    std::env::args_os()
                        .next()
                        .expect("Binary name is always provided if we get this far"),
                );
                let bin_name = bin_path
                    .file_name()
                    .expect("path has file name")
                    .to_string_lossy();
                clap_complete::generate(
                    shell,
                    &mut Opts::command(),
                    bin_name.as_ref(),
                    &mut std::io::stdout(),
                );
                // HACK: prints true to stdout which is fine for shells
                Ok(CliOutput::Raw(serde_json::Value::Bool(true)))
            }
        }
    }

    async fn handle_admin_setup_command(
        &self,
        cli: Opts,
        args: SetupAdminArgs,
    ) -> anyhow::Result<Value> {
        let client =
            DynGlobalApi::new_admin_setup(cli.make_endpoints().await?, args.endpoint.clone())?;

        match &args.subcommand {
            SetupAdminCmd::Status => {
                let status = client.setup_status(cli.auth()?).await?;

                Ok(serde_json::to_value(status).expect("JSON serialization failed"))
            }
            SetupAdminCmd::SetLocalParams {
                name,
                federation_name,
                federation_size,
            } => {
                let info = client
                    .set_local_params(
                        name.clone(),
                        federation_name.clone(),
                        None,
                        None,
                        *federation_size,
                        cli.auth()?,
                    )
                    .await?;

                Ok(serde_json::to_value(info).expect("JSON serialization failed"))
            }
            SetupAdminCmd::AddPeer { info } => {
                let name = client
                    .add_peer_connection_info(info.clone(), cli.auth()?)
                    .await?;

                Ok(serde_json::to_value(name).expect("JSON serialization failed"))
            }
            SetupAdminCmd::StartDkg => {
                client.start_dkg(cli.auth()?).await?;

                Ok(Value::Null)
            }
        }
    }
}

async fn log_expiration_notice(client: &Client) {
    client.get_meta_expiration_timestamp().await;
    if let Some(expiration_time) = client.get_meta_expiration_timestamp().await {
        match expiration_time.duration_since(fedimint_core::time::now()) {
            Ok(until_expiration) => {
                let days = until_expiration.as_secs() / (60 * 60 * 24);

                if 90 < days {
                    debug!(target: LOG_CLIENT, %days, "This federation will expire");
                } else if 30 < days {
                    info!(target: LOG_CLIENT, %days, "This federation will expire");
                } else {
                    warn!(target: LOG_CLIENT, %days, "This federation will expire soon");
                }
            }
            Err(_) => {
                tracing::error!(target: LOG_CLIENT, "This federation has expired and might not be safe to use");
            }
        }
    }
}
async fn print_welcome_message(client: &Client) {
    if let Some(welcome_message) = client
        .meta_service()
        .get_field::<String>(client.db(), "welcome_message")
        .await
        .and_then(|v| v.value)
    {
        eprintln!("{welcome_message}");
    }
}

fn salt_from_file_path(file_path: &Path) -> PathBuf {
    file_path
        .parent()
        .expect("File has no parent?!")
        .join(SALT_FILE)
}

/// Convert clap arguments to backup metadata
fn metadata_from_clap_cli(metadata: Vec<String>) -> Result<BTreeMap<String, String>, CliError> {
    let metadata: BTreeMap<String, String> = metadata
        .into_iter()
        .map(|item| {
            match &item
                .splitn(2, '=')
                .map(ToString::to_string)
                .collect::<Vec<String>>()[..]
            {
                [] => Err(format_err!("Empty metadata argument not allowed")),
                [key] => Err(format_err!("Metadata {key} is missing a value")),
                [key, val] => Ok((key.clone(), val.clone())),
                [..] => unreachable!(),
            }
        })
        .collect::<anyhow::Result<_>>()
        .map_err_cli_msg("invalid metadata")?;
    Ok(metadata)
}

#[test]
#[allow(clippy::unwrap_used)]
fn metadata_from_clap_cli_test() {
    for (args, expected) in [
        (
            vec!["a=b".to_string()],
            BTreeMap::from([("a".into(), "b".into())]),
        ),
        (
            vec!["a=b".to_string(), "c=d".to_string()],
            BTreeMap::from([("a".into(), "b".into()), ("c".into(), "d".into())]),
        ),
    ] {
        assert_eq!(metadata_from_clap_cli(args).unwrap(), expected);
    }
}
