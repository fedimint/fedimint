use std::borrow::Cow;
use std::collections::BTreeMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::{ApiEndpoint, ApiError, ApiMethod, IrohApiRequest};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompact as _;
use fedimint_logging::LOG_NET_API;
use fedimint_metrics::prometheus::HistogramTimer;
use fedimint_server_core::DynServerModule;
use futures::FutureExt as _;
use iroh_next::Endpoint;
use iroh_next::endpoint::{Connection, Incoming, VarInt};
use serde_json::Value;
use tokio::sync::Semaphore;
use tracing::{error, warn};

use super::api::{ConsensusApi, server_endpoints};
use crate::connection_limits::ConnectionLimits;
use crate::metrics::{
    IROH_API_CONNECTION_DURATION_SECONDS, IROH_API_CONNECTION_IDLE_TIMEOUT_TOTAL,
    IROH_API_CONNECTIONS_ACTIVE, IROH_API_REQUEST_DURATION_SECONDS, IROH_API_REQUEST_RESPONSE_CODE,
};
use crate::net::api::{HasApiContext, with_api_endpoint_timeout};

/// How long an Iroh API connection may stay idle before the server closes it.
const IROH_API_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Application-level QUIC error code for expected idle Iroh API connection
/// reaping.
const IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_CODE: u32 = 0;

/// Application-level QUIC close reason for idle Iroh API connection reaping.
const IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_REASON: &[u8] = b"idle timeout";

/// Metric label used for every request that does not resolve to a registered
/// endpoint.
const UNKNOWN_METHOD: &str = "unknown";

/// The Iroh API listener a connection arrived on. Both listeners speak Iroh
/// 1.x and serve the same API; they differ only in identity.
#[derive(Clone, Copy)]
pub(super) enum IrohApiListener {
    /// The API identity from the federation config.
    Default,
    /// The identity earlier releases advertised in guardian metadata, kept
    /// for clients that stored it. Its metric label shows when it goes
    /// unused.
    Transitional,
}

impl IrohApiListener {
    fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Transitional => "next",
        }
    }
}

pub(super) async fn run_iroh_api(
    api: Arc<IrohApiState>,
    endpoint: Endpoint,
    listener: IrohApiListener,
    task_group: TaskGroup,
) {
    loop {
        match endpoint.accept().await {
            Some(incoming) => {
                let permit = acquire_iroh_api_permit(
                    &api.parallel_connections_limit,
                    api.limits.max_connections,
                    listener.label(),
                    "connection",
                )
                .await;
                task_group.spawn_cancellable_silent(
                    "handle-iroh-connection",
                    handle_incoming(
                        api.clone(),
                        task_group.clone(),
                        incoming,
                        permit,
                        api.limits.max_requests_per_connection,
                        listener,
                    )
                    .then(|result| async {
                        if let Err(err) = result {
                            warn!(target: LOG_NET_API, err = %err.fmt_compact(), "Failed to handle iroh connection");
                        }
                    }),
                );
            }
            None => return,
        }
    }
}

type CoreApi = BTreeMap<String, ApiEndpoint<ConsensusApi>>;
type ModuleApi = BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>;

pub(super) struct IrohApiState {
    consensus: ConsensusApi,
    core: CoreApi,
    modules: ModuleApi,
    limits: ConnectionLimits,
    parallel_connections_limit: Arc<Semaphore>,
}

impl IrohApiState {
    pub(super) fn new(consensus: ConsensusApi, limits: ConnectionLimits) -> Arc<Self> {
        let core_api = server_endpoints()
            .into_iter()
            .map(|endpoint| (endpoint.path.to_string(), endpoint))
            .collect();

        let module_api = consensus
            .modules
            .iter_modules()
            .map(|(id, _, module)| {
                let api_endpoints = module
                    .api_endpoints()
                    .into_iter()
                    .map(|endpoint| (endpoint.path.to_string(), endpoint))
                    .collect::<BTreeMap<String, ApiEndpoint<DynServerModule>>>();

                (id, api_endpoints)
            })
            .collect();

        Arc::new(Self {
            consensus,
            core: core_api,
            modules: module_api,
            parallel_connections_limit: Arc::new(Semaphore::new(limits.max_connections)),
            limits,
        })
    }
}

async fn acquire_iroh_api_permit(
    limit: &Arc<Semaphore>,
    max: usize,
    listener: &'static str,
    resource: &'static str,
) -> tokio::sync::OwnedSemaphorePermit {
    if limit.available_permits() == 0 {
        warn!(
            target: LOG_NET_API,
            limit = max,
            listener,
            resource,
            "Iroh API limit reached, blocking"
        );
    }
    limit
        .clone()
        .acquire_owned()
        .await
        .expect("semaphore should not be closed")
}

struct ActiveIrohApiConnection {
    _duration: HistogramTimer,
}

impl ActiveIrohApiConnection {
    fn new() -> Self {
        IROH_API_CONNECTIONS_ACTIVE.inc();
        Self {
            _duration: IROH_API_CONNECTION_DURATION_SECONDS.start_timer(),
        }
    }
}

impl Drop for ActiveIrohApiConnection {
    fn drop(&mut self) {
        IROH_API_CONNECTIONS_ACTIVE.dec();
    }
}

async fn handle_incoming(
    api: Arc<IrohApiState>,
    task_group: TaskGroup,
    incoming: Incoming,
    connection_permit: tokio::sync::OwnedSemaphorePermit,
    iroh_api_max_requests_per_connection: usize,
    listener: IrohApiListener,
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    handle_iroh_api_connection(
        api,
        task_group,
        connection,
        connection_permit,
        iroh_api_max_requests_per_connection,
        listener,
    )
    .await
}

async fn handle_iroh_api_connection(
    api: Arc<IrohApiState>,
    task_group: TaskGroup,
    connection: Connection,
    _connection_permit: tokio::sync::OwnedSemaphorePermit,
    max_requests: usize,
    listener: IrohApiListener,
) -> anyhow::Result<()> {
    let parallel_requests_limit = Arc::new(Semaphore::new(max_requests));
    let _metrics = ActiveIrohApiConnection::new();

    loop {
        let accept_result = fedimint_core::runtime::timeout(
            IROH_API_CONNECTION_IDLE_TIMEOUT,
            connection.accept_bi(),
        )
        .await;

        let (send_stream, recv_stream) = match accept_result {
            Ok(streams) => streams?,
            Err(_) if parallel_requests_limit.available_permits() < max_requests => continue,
            Err(_) => {
                IROH_API_CONNECTION_IDLE_TIMEOUT_TOTAL.inc();
                tracing::debug!(
                    target: LOG_NET_API,
                    listener = listener.label(),
                    idle_timeout_secs = IROH_API_CONNECTION_IDLE_TIMEOUT.as_secs(),
                    "Closing idle Iroh API connection"
                );
                connection.close(
                    VarInt::from_u32(IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_CODE),
                    IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_REASON,
                );
                return Ok(());
            }
        };

        let permit = acquire_iroh_api_permit(
            &parallel_requests_limit,
            max_requests,
            listener.label(),
            "request",
        )
        .await;
        task_group.spawn_cancellable_silent(
            "handle-iroh-request",
            handle_iroh_api_stream(
                api.clone(),
                send_stream,
                recv_stream,
                permit,
                listener.label(),
            )
            .then(|result| async {
                if let Err(err) = result {
                    warn!(target: LOG_NET_API, err = %err.fmt_compact(), "Failed to handle Iroh API request");
                }
            }),
        );
    }
}

async fn handle_iroh_api_stream(
    api: Arc<IrohApiState>,
    mut send_stream: iroh_next::endpoint::SendStream,
    mut recv_stream: iroh_next::endpoint::RecvStream,
    _request_permit: tokio::sync::OwnedSemaphorePermit,
    listener_label: &'static str,
) -> anyhow::Result<()> {
    let request = recv_stream.read_to_end(100_000).await?;
    let response = handle_iroh_api_request(&api, &request, listener_label).await?;
    send_stream.write_all(&response).await?;
    send_stream.finish()?;
    Ok(())
}

async fn handle_iroh_api_request(
    api: &IrohApiState,
    request: &[u8],
    listener_label: &'static str,
) -> anyhow::Result<Vec<u8>> {
    let request = serde_json::from_slice::<IrohApiRequest>(request)?;
    let request_method = request.method.clone();
    let response = record_request_metrics(
        &api.core,
        &api.modules,
        &request_method,
        listener_label,
        await_response(api, request),
    )
    .await;

    Ok(serde_json::to_vec(&response)?)
}

fn metric_method<'a, C, M>(
    core: &'a BTreeMap<String, C>,
    modules: &'a BTreeMap<ModuleInstanceId, BTreeMap<String, M>>,
    method: &ApiMethod,
) -> Cow<'a, str> {
    match method {
        ApiMethod::Core(method) => core
            .get_key_value(method)
            .map_or(Cow::Borrowed(UNKNOWN_METHOD), |(method, _)| {
                Cow::Borrowed(method)
            }),
        ApiMethod::Module(module_id, method) => modules
            .get_key_value(module_id)
            .and_then(|(module_id, endpoints)| {
                endpoints
                    .get_key_value(method)
                    .map(|(method, _)| Cow::Owned(format!("{module_id}-{method}")))
            })
            .unwrap_or(Cow::Borrowed(UNKNOWN_METHOD)),
    }
}

async fn record_request_metrics<T, C, M>(
    core: &BTreeMap<String, C>,
    modules: &BTreeMap<ModuleInstanceId, BTreeMap<String, M>>,
    request_method: &ApiMethod,
    listener_label: &'static str,
    response: impl Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
    let method = metric_method(core, modules, request_method);
    let timer = IROH_API_REQUEST_DURATION_SECONDS
        .with_label_values(&[method.as_ref()])
        .start_timer();
    let response = response.await;
    timer.observe_duration();

    let response_code = response
        .as_ref()
        .map_or_else(|err| err.code.to_string(), |_| "0".to_string());
    IROH_API_REQUEST_RESPONSE_CODE
        .with_label_values(&[method.as_ref(), response_code.as_str(), listener_label])
        .inc();

    response
}

async fn await_response(api: &IrohApiState, request: IrohApiRequest) -> Result<Value, ApiError> {
    match request.method {
        ApiMethod::Core(method) => {
            let endpoint = api
                .core
                .get(&method)
                .ok_or_else(|| ApiError::not_found(method.clone()))?;

            run_handler(None, &method, async {
                let (state, context) = api.consensus.context(&request.request, None).await;
                (endpoint.handler)(state, context, request.request).await
            })
            .await
        }
        ApiMethod::Module(module_id, method) => {
            let endpoint = api
                .modules
                .get(&module_id)
                .ok_or_else(|| ApiError::not_found(module_id.to_string()))?
                .get(&method)
                .ok_or_else(|| ApiError::not_found(method.clone()))?;

            run_handler(Some(module_id), &method, async {
                let (state, context) = api
                    .consensus
                    .context(&request.request, Some(module_id))
                    .await;
                (endpoint.handler)(state, context, request.request).await
            })
            .await
        }
    }
}

/// Runs an API endpoint with the same deadline as WebSocket requests, turning a
/// timeout or panic into an error response for the caller that triggered it.
///
/// Iroh API requests run on the root task group, so an escaping panic would
/// trip the task group's panic guard and shut the whole guardian down. The
/// jsonrpsee path contains handler panics the same way.
async fn run_handler(
    module_id: Option<ModuleInstanceId>,
    method: &str,
    handler: impl Future<Output = Result<Value, ApiError>>,
) -> Result<Value, ApiError> {
    // Using `AssertUnwindSafe` here is far from ideal. In theory this means we
    // could end up with an inconsistent state. In practice most API functions are
    // only reading and the few that do write anything are atomic. Lastly, this is
    // only the last line of defense.
    AssertUnwindSafe(with_api_endpoint_timeout(handler))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| {
            error!(
                target: LOG_NET_API,
                module_id = ?module_id,
                method,
                "API handler panicked, DO NOT IGNORE, FIX IT!!!"
            );

            Err(ApiError::server_error("API handler panicked".to_string()))
        })
}

#[cfg(test)]
mod tests;
