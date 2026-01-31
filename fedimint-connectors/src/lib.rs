pub mod error;
pub mod http;
pub mod iroh;
pub mod metrics;
#[cfg(all(feature = "tor", not(target_family = "wasm")))]
pub mod tor;
pub mod ws;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Debug};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use fedimint_core::envs::{FM_WS_API_CONNECT_OVERRIDES_ENV, parse_kv_list_from_env};
use fedimint_core::module::{ApiMethod, ApiRequestErased};
use fedimint_core::util::backoff_util::{FibonacciBackoff, custom_backoff};
use fedimint_core::util::{FmtCompact, FmtCompactAnyhow, SafeUrl};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::{LOG_CLIENT_NET_API, LOG_NET};
use fedimint_metrics::HistogramExt as _;
use reqwest::Method;
use serde_json::Value;
use tokio::sync::{OnceCell, SetOnce, broadcast, watch};
use tracing::trace;

use crate::error::ServerError;
use crate::metrics::{CONNECTION_ATTEMPTS_TOTAL, CONNECTION_DURATION_SECONDS};
use crate::ws::WebsocketConnector;

pub type ServerResult<T> = Result<T, ServerError>;

/// Type for connector initialization functions
type ConnectorInitFn = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = anyhow::Result<DynConnector>> + Send>> + Send + Sync,
>;

/// Builder for [`ConnectorRegistry`]
///
/// See [`ConnectorRegistry::build_from_client_env`] and similar
/// to create.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // Shut up, Clippy
pub struct ConnectorRegistryBuilder {
    /// List of overrides to use when attempting to connect to given url
    ///
    /// This is useful for testing, or forcing non-default network
    /// connectivity.
    connection_overrides: BTreeMap<SafeUrl, SafeUrl>,

    /// Enable Iroh endpoints at all?
    iroh_enable: bool,
    /// Override the Iroh DNS server to use
    iroh_dns: Option<SafeUrl>,
    /// Should start the "next/unstable" Iroh stack
    iroh_next: bool,
    /// Enable Pkarr DHT discovery
    iroh_pkarr_dht: bool,

    /// Enable Websocket API handling at all?
    ws_enable: bool,
    ws_force_tor: bool,

    // Enable HTTP
    http_enable: bool,
}

impl ConnectorRegistryBuilder {
    #[allow(clippy::unused_async)] // Leave room for async in the future
    pub async fn bind(self) -> anyhow::Result<ConnectorRegistry> {
        // Create initialization functions for each connector type
        let mut connectors_lazy: BTreeMap<String, (ConnectorInitFn, OnceCell<DynConnector>)> =
            BTreeMap::new();

        // WS connector init function
        let builder_ws = self.clone();
        let ws_connector_init = Arc::new(move || {
            let builder = builder_ws.clone();
            Box::pin(async move { builder.build_ws_connector().await })
                as Pin<Box<dyn Future<Output = anyhow::Result<DynConnector>> + Send>>
        });
        connectors_lazy.insert("ws".into(), (ws_connector_init.clone(), OnceCell::new()));
        connectors_lazy.insert("wss".into(), (ws_connector_init.clone(), OnceCell::new()));

        // Iroh connector init function
        let builder_iroh = self.clone();
        connectors_lazy.insert(
            "iroh".into(),
            (
                Arc::new(move || {
                    let builder = builder_iroh.clone();
                    Box::pin(async move { builder.build_iroh_connector().await })
                        as Pin<Box<dyn Future<Output = anyhow::Result<DynConnector>> + Send>>
                }),
                OnceCell::new(),
            ),
        );

        let builder_http = self.clone();
        let http_connector_init = Arc::new(move || {
            let builder = builder_http.clone();
            Box::pin(async move { builder.build_http_connector() })
                as Pin<Box<dyn Future<Output = anyhow::Result<DynConnector>> + Send>>
        });

        connectors_lazy.insert(
            "http".into(),
            (http_connector_init.clone(), OnceCell::new()),
        );
        connectors_lazy.insert(
            "https".into(),
            (http_connector_init.clone(), OnceCell::new()),
        );

        Ok(ConnectorRegistry {
            inner: ConnectorRegistryInner {
                connectors_lazy,
                connection_overrides: self.connection_overrides,
                initialized: SetOnce::new(),
            }
            .into(),
        })
    }

    pub async fn build_iroh_connector(&self) -> anyhow::Result<DynConnector> {
        if !self.iroh_enable {
            bail!("Iroh connector not enabled");
        }
        Ok(Arc::new(
            iroh::IrohConnector::new(self.iroh_dns.clone(), self.iroh_pkarr_dht, self.iroh_next)
                .await?,
        ) as DynConnector)
    }

    pub async fn build_ws_connector(&self) -> anyhow::Result<DynConnector> {
        if !self.ws_enable {
            bail!("Websocket connector not enabled");
        }

        match self.ws_force_tor {
            #[cfg(all(feature = "tor", not(target_family = "wasm")))]
            true => {
                use crate::tor::TorConnector;

                Ok(Arc::new(TorConnector::bootstrap().await?) as DynConnector)
            }

            false => Ok(Arc::new(WebsocketConnector::new()) as DynConnector),
            #[allow(unreachable_patterns)]
            _ => bail!("Tor requested, but not support not compiled in"),
        }
    }

    pub fn build_http_connector(&self) -> anyhow::Result<DynConnector> {
        if !self.http_enable {
            bail!("Http connector not enabled");
        }

        Ok(Arc::new(crate::http::HttpConnector::default()) as DynConnector)
    }

    pub fn iroh_pkarr_dht(self, enable: bool) -> Self {
        Self {
            iroh_pkarr_dht: enable,
            ..self
        }
    }

    pub fn iroh_next(self, enable: bool) -> Self {
        Self {
            iroh_next: enable,
            ..self
        }
    }

    pub fn ws_force_tor(self, enable: bool) -> Self {
        Self {
            ws_force_tor: enable,
            ..self
        }
    }

    pub fn set_iroh_dns(self, url: SafeUrl) -> Self {
        Self {
            iroh_dns: Some(url),
            ..self
        }
    }

    /// Apply overrides from env variables
    pub fn with_env_var_overrides(mut self) -> anyhow::Result<Self> {
        // TODO: read rest of the env
        for (k, v) in parse_kv_list_from_env::<_, SafeUrl>(FM_WS_API_CONNECT_OVERRIDES_ENV)? {
            self = self.with_connection_override(k, v);
        }

        Ok(Self { ..self })
    }

    pub fn with_connection_override(
        mut self,
        original_url: SafeUrl,
        replacement_url: SafeUrl,
    ) -> Self {
        self.connection_overrides
            .insert(original_url, replacement_url);
        self
    }
}

/// Actual data shared between copies of [`ConnectorRegistry`] handle
struct ConnectorRegistryInner {
    /// Lazily initialized [`Connector`]s per protocol supported
    connectors_lazy: BTreeMap<String, (ConnectorInitFn, OnceCell<DynConnector>)>,
    /// Connection URL overrides for testing/custom routing
    connection_overrides: BTreeMap<SafeUrl, SafeUrl>,
    /// Set on first connection attempt
    ///
    /// This is used for functionality that wants to avoid making
    /// network connections if nothing else did network request.
    initialized: tokio::sync::SetOnce<()>,
}

/// A set of available connectivity protocols a client can use to make
/// network API requests (typically to federation).
///
/// Maps from connection URL schema to [`Connector`] to use to connect to it.
///
/// See [`ConnectorRegistry::build_from_client_env`] and similar
/// to create.
///
/// [`ConnectorRegistry::connect_guardian`] is the main entry point for making
/// mixed-networking stack connection.
///
/// Responsibilities:
#[derive(Clone)]
pub struct ConnectorRegistry {
    inner: Arc<ConnectorRegistryInner>,
}

impl fmt::Debug for ConnectorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectorRegistry")
            .field("connectors_lazy", &self.inner.connectors_lazy.len())
            .field("connection_overrides", &self.inner.connection_overrides)
            .finish()
    }
}

impl ConnectorRegistry {
    /// Create a builder with recommended defaults intended for client-side
    /// usage
    ///
    /// In particular mobile devices are considered.
    pub fn build_from_client_defaults() -> ConnectorRegistryBuilder {
        ConnectorRegistryBuilder {
            iroh_enable: true,
            iroh_dns: None,
            iroh_pkarr_dht: false,
            iroh_next: true,
            ws_enable: true,
            ws_force_tor: false,
            http_enable: true,

            connection_overrides: BTreeMap::default(),
        }
    }

    /// Create a builder with recommended defaults intended for the server-side
    /// usage
    pub fn build_from_server_defaults() -> ConnectorRegistryBuilder {
        ConnectorRegistryBuilder {
            iroh_enable: true,
            iroh_dns: None,
            iroh_pkarr_dht: true,
            iroh_next: true,
            ws_enable: true,
            ws_force_tor: false,
            http_enable: false,

            connection_overrides: BTreeMap::default(),
        }
    }

    /// Create a builder with recommended defaults intended for testing
    /// usage
    pub fn build_from_testing_defaults() -> ConnectorRegistryBuilder {
        ConnectorRegistryBuilder {
            iroh_enable: true,
            iroh_dns: None,
            iroh_pkarr_dht: false,
            iroh_next: false,
            ws_enable: true,
            ws_force_tor: false,
            http_enable: true,

            connection_overrides: BTreeMap::default(),
        }
    }

    /// Like [`Self::build_from_client_defaults`] build will apply
    /// environment-provided overrides.
    pub fn build_from_client_env() -> anyhow::Result<ConnectorRegistryBuilder> {
        let builder = Self::build_from_client_defaults().with_env_var_overrides()?;
        Ok(builder)
    }

    /// Like [`Self::build_from_server_defaults`] build will apply
    /// environment-provided overrides.
    pub fn build_from_server_env() -> anyhow::Result<ConnectorRegistryBuilder> {
        let builder = Self::build_from_server_defaults().with_env_var_overrides()?;
        Ok(builder)
    }

    /// Like [`Self::build_from_testing_defaults`] build will apply
    /// environment-provided overrides.
    pub fn build_from_testing_env() -> anyhow::Result<ConnectorRegistryBuilder> {
        let builder = Self::build_from_testing_defaults().with_env_var_overrides()?;
        Ok(builder)
    }

    /// Wait until some connections have been made
    pub async fn wait_for_initialized_connections(&self) {
        self.inner.initialized.wait().await;
    }

    /// Connect to a given `url` using matching [`Connector`]
    ///
    /// This is the main function consumed by the downstream use for making
    /// connection.
    pub async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> ServerResult<DynGuaridianConnection> {
        trace!(
            target: LOG_NET,
            %url,
            "Connection requested to guardian"
        );
        let _ = self.inner.initialized.set(());

        let url = match self.inner.connection_overrides.get(url) {
            Some(replacement) => {
                trace!(
                    target: LOG_NET,
                    original_url = %url,
                    replacement_url = %replacement,
                    "Using a connectivity override for connection"
                );

                replacement
            }
            None => url,
        };

        let scheme = url.scheme().to_string();

        let Some(connector_lazy) = self.inner.connectors_lazy.get(&scheme) else {
            return Err(ServerError::InvalidEndpoint(anyhow!(
                "Unsupported scheme: {}; missing endpoint handler",
                url.scheme()
            )));
        };

        // Clone the init function to use in the async block
        let init_fn = connector_lazy.0.clone();

        let timer = CONNECTION_DURATION_SECONDS
            .with_label_values(&[&scheme])
            .start_timer_ext();

        let result = connector_lazy
            .1
            .get_or_try_init(|| async move { init_fn().await })
            .await
            .map_err(|e| {
                ServerError::Transport(anyhow!(
                    "Connector failed to initialize: {}",
                    e.fmt_compact_anyhow()
                ))
            })?
            .connect_guardian(url, api_secret)
            .await;

        timer.observe_duration();

        let result_label = if result.is_ok() { "success" } else { "error" }.to_string();
        CONNECTION_ATTEMPTS_TOTAL
            .with_label_values(&[&scheme, &result_label])
            .inc();

        let conn = result.inspect_err(|err| {
            trace!(
                target: LOG_NET,
                %url,
                err = %err.fmt_compact(),
                "Connection failed"
            );
        })?;

        trace!(
            target: LOG_NET,
            %url,
            "Connection returned"
        );
        Ok(conn)
    }

    /// Connect to a given `url` using matching [`Connector`] to a gateway
    ///
    /// This is the main function consumed by the downstream use for making
    /// connection.
    pub async fn connect_gateway(&self, url: &SafeUrl) -> anyhow::Result<DynGatewayConnection> {
        trace!(
            target: LOG_NET,
            %url,
            "Connection requested to gateway"
        );
        let _ = self.inner.initialized.set(());

        let url = match self.inner.connection_overrides.get(url) {
            Some(replacement) => {
                trace!(
                    target: LOG_NET,
                    original_url = %url,
                    replacement_url = %replacement,
                    "Using a connectivity override for connection"
                );

                replacement
            }
            None => url,
        };

        let scheme = url.scheme().to_string();

        let Some(connector_lazy) = self.inner.connectors_lazy.get(&scheme) else {
            return Err(anyhow!(
                "Unsupported scheme: {}; missing endpoint handler",
                url.scheme()
            ));
        };

        // Clone the init function to use in the async block
        let init_fn = connector_lazy.0.clone();

        let timer = CONNECTION_DURATION_SECONDS
            .with_label_values(&[&scheme])
            .start_timer_ext();

        let result = connector_lazy
            .1
            .get_or_try_init(|| async move { init_fn().await })
            .await
            .map_err(|e| {
                ServerError::Transport(anyhow!(
                    "Connector failed to initialize: {}",
                    e.fmt_compact_anyhow()
                ))
            })?
            .connect_gateway(url)
            .await;

        timer.observe_duration();

        let result_label = if result.is_ok() { "success" } else { "error" }.to_string();
        CONNECTION_ATTEMPTS_TOTAL
            .with_label_values(&[&scheme, &result_label])
            .inc();

        result
    }
}
pub type DynConnector = Arc<dyn Connector>;

#[async_trait]
pub trait Connector: Send + Sync + 'static + Debug {
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> ServerResult<DynGuaridianConnection>;

    async fn connect_gateway(&self, url: &SafeUrl) -> anyhow::Result<DynGatewayConnection>;
}

/// Generic connection trait shared between [`IGuardianConnection`] and
/// [`IGatewayConnection`]
#[apply(async_trait_maybe_send!)]
pub trait IConnection: Debug + Send + Sync + 'static {
    fn is_connected(&self) -> bool;

    async fn await_disconnection(&self);
}

/// A connection from api client to a federation guardian (type erased)
pub type DynGuaridianConnection = Arc<dyn IGuardianConnection>;

/// A connection from api client to a federation guardian
#[async_trait]
pub trait IGuardianConnection: IConnection + Debug + Send + Sync + 'static {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> ServerResult<Value>;

    fn into_dyn(self) -> DynGuaridianConnection
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}

/// A connection from api client to a gateway (type erased)
pub type DynGatewayConnection = Arc<dyn IGatewayConnection>;

/// A connection from a client to a gateway
#[apply(async_trait_maybe_send!)]
pub trait IGatewayConnection: IConnection + Debug + Send + Sync + 'static {
    async fn request(
        &self,
        password: Option<String>,
        method: Method,
        route: &str,
        payload: Option<Value>,
    ) -> ServerResult<Value>;

    fn into_dyn(self) -> DynGatewayConnection
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}

#[derive(Debug)]
pub struct ConnectionPool<T: IConnection + ?Sized> {
    /// Available connectors which we can make connections
    connectors: ConnectorRegistry,

    active_connections: watch::Sender<BTreeSet<SafeUrl>>,

    /// Connection pool
    ///
    /// Every entry in this map will be created on demand and correspond to a
    /// single outgoing connection to a certain URL that is in the process
    /// of being established, or we already established.
    #[allow(clippy::type_complexity)]
    connections: Arc<tokio::sync::Mutex<HashMap<SafeUrl, Arc<ConnectionState<T>>>>>,
}

impl<T: IConnection + ?Sized> Clone for ConnectionPool<T> {
    fn clone(&self) -> Self {
        Self {
            connectors: self.connectors.clone(),
            connections: self.connections.clone(),
            active_connections: self.active_connections.clone(),
        }
    }
}

impl<T: IConnection + ?Sized> ConnectionPool<T> {
    pub fn new(connectors: ConnectorRegistry) -> Self {
        Self {
            connectors,
            connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            active_connections: watch::channel(BTreeSet::new()).0,
        }
    }

    async fn get_or_init_pool_entry(&self, url: &SafeUrl) -> Arc<ConnectionState<T>> {
        let mut pool_locked = self.connections.lock().await;
        pool_locked
            .entry(url.to_owned())
            .and_modify(|entry_arc| {
                // Check if existing connection is disconnected and reset the whole entry.
                //
                // This resets the state (like connectivity backoff), which is what we want.
                // Since the (`OnceCell`) was already initialized, it means connection was
                // successfully before, and disconnected afterwards.
                if let Some(existing_conn) = entry_arc.connection.get()
                    && !existing_conn.is_connected()
                {
                    trace!(
                        target: LOG_CLIENT_NET_API,
                        %url,
                        "Existing connection is disconnected, removing from pool"
                    );
                    self.active_connections.send_modify(|v| {
                        v.remove(url);
                    });
                    *entry_arc = Arc::new(ConnectionState::new_reconnecting());
                }
            })
            .or_insert_with(|| Arc::new(ConnectionState::new_initial()))
            .clone()
    }

    pub async fn get_or_create_connection<F, Fut>(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
        create_connection: F,
    ) -> ServerResult<Arc<T>>
    where
        F: Fn(SafeUrl, Option<String>, ConnectorRegistry) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = ServerResult<Arc<T>>> + Send + 'static,
    {
        let pool_entry_arc = self.get_or_init_pool_entry(url).await;

        let leader_tx = loop {
            let mut leader_rx = {
                let mut chan_locked = pool_entry_arc
                    .merge_connection_attempts_chan
                    .lock()
                    .expect("locking error");

                if chan_locked.is_closed() {
                    let (leader_tx, leader_rx) = broadcast::channel(1);
                    *chan_locked = leader_rx;
                    // whoever was trying to connect last time is gone
                    // we're out of this lame loop for followers
                    break leader_tx;
                }

                // lets piggyback on the existing leader
                chan_locked.resubscribe()
            };

            if let Ok(res) = leader_rx.recv().await {
                match res {
                    Ok(o) => return Ok(o),
                    Err(err) => {
                        return Err(ServerError::Connection(anyhow::format_err!("{}", err)));
                    }
                }
            }
        };

        let conn = pool_entry_arc
            .connection
            .get_or_try_init(|| async {
                let retry_delay = pool_entry_arc.pre_reconnect_delay();
                fedimint_core::runtime::sleep(retry_delay).await;

                trace!(target: LOG_CLIENT_NET_API, %url, "Attempting to create a new connection");
                let res = create_connection(
                    url.clone(),
                    api_secret.map(std::string::ToString::to_string),
                    self.connectors.clone(),
                )
                .await;

                // If any other task was also waiting to connect, send them the connection
                // result.
                //
                // Note: we want to send both Ok or Err, so `res?` is used only afterwards.
                let _ = leader_tx.send(
                    res.as_ref()
                        .map(|o| o.clone())
                        .map_err(|err| err.to_string()),
                );

                let conn = res?;

                self.active_connections.send_modify(|v| {
                    v.insert(url.clone());
                });

                fedimint_core::runtime::spawn("connection disconnect watch", {
                    let conn = conn.clone();
                    let s = self.clone();
                    let url = url.clone();
                    async move {
                        // wait for this connection to disconnect
                        conn.await_disconnection().await;
                        // And afterwards, update `active_connections`.
                        //
                        // This will update the `active_connections` just like calling
                        // `get_or_create_connection` normally do, but we will
                        // not attempt to do anything with the result (i.e. try to connect).
                        s.get_or_init_pool_entry(&url).await;
                    }
                });

                Ok(conn)
            })
            .await?;

        trace!(target: LOG_CLIENT_NET_API, %url, "Connection ready");
        Ok(conn.clone())
    }
    /// Get receiver for changes in the active connections
    pub fn get_active_connection_receiver(&self) -> watch::Receiver<BTreeSet<SafeUrl>> {
        self.active_connections.subscribe()
    }

    pub async fn wait_for_initialized_connections(&self) {
        self.connectors.wait_for_initialized_connections().await
    }
}

/// Inner part of [`ConnectionState`] preserving state between attempts to
/// initialize [`ConnectionState::connection`]
#[derive(Debug)]
struct ConnectionStateInner {
    fresh: bool,
    backoff: FibonacciBackoff,
}

#[derive(Debug)]
pub struct ConnectionState<T: ?Sized> {
    /// Connection we are trying to or already established
    pub connection: tokio::sync::OnceCell<Arc<T>>,

    /// When tasks attempt to connect at the same time,
    /// this is the receiving end of the channel where
    /// the "leader" sends a result.
    merge_connection_attempts_chan:
        std::sync::Mutex<broadcast::Receiver<std::result::Result<Arc<T>, String>>>,

    /// State that technically is protected every time by
    /// the serialization of `OnceCell::get_or_try_init`, but
    /// for Rust purposes needs to be locked.
    inner: std::sync::Mutex<ConnectionStateInner>,
}

impl<T: ?Sized> ConnectionState<T> {
    /// Create a new connection state for a first time connection
    pub fn new_initial() -> Self {
        Self {
            connection: OnceCell::new(),
            inner: std::sync::Mutex::new(ConnectionStateInner {
                fresh: true,
                backoff: custom_backoff(
                    // First time connections start quick
                    Duration::from_millis(5),
                    Duration::from_secs(30),
                    None,
                ),
            }),
            merge_connection_attempts_chan: std::sync::Mutex::new(broadcast::channel(1).1),
        }
    }

    /// Create a new connection state for a connection that already failed, and
    /// is being reset
    pub fn new_reconnecting() -> Self {
        Self {
            connection: OnceCell::new(),
            inner: std::sync::Mutex::new(ConnectionStateInner {
                // set the attempts to 1, indicating that
                fresh: false,
                backoff: custom_backoff(
                    // Connections after a disconnect start with some minimum delay
                    Duration::from_millis(500),
                    Duration::from_secs(30),
                    None,
                ),
            }),
            merge_connection_attempts_chan: std::sync::Mutex::new(broadcast::channel(1).1),
        }
    }

    /// Record the fact that an attempt to connect is being made, and return
    /// time the caller should wait.
    pub fn pre_reconnect_delay(&self) -> Duration {
        let mut backoff_locked = self.inner.lock().expect("Locking failed");
        let fresh = backoff_locked.fresh;

        backoff_locked.fresh = false;

        if fresh {
            Duration::default()
        } else {
            backoff_locked.backoff.next().expect("Keeps retrying")
        }
    }
}
