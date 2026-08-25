use std::borrow::Cow;
use std::collections::BTreeMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::{ApiEndpoint, ApiError, ApiMethod, IrohApiRequest};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_logging::LOG_NET_API;
use fedimint_metrics::prometheus::HistogramTimer;
use fedimint_server_core::DynServerModule;
use futures::FutureExt as _;
use iroh::Endpoint;
use iroh::endpoint::{Incoming, RecvStream, SendStream, VarInt};
use serde_json::Value;
use tokio::sync::Semaphore;
use tracing::{error, warn};

use super::api::{ConsensusApi, server_endpoints};
use crate::connection_limits::ConnectionLimits;
use crate::metrics::{
    IROH_API_CONNECTION_DURATION_SECONDS, IROH_API_CONNECTION_IDLE_TIMEOUT_TOTAL,
    IROH_API_CONNECTIONS_ACTIVE, IROH_API_REQUEST_DURATION_SECONDS, IROH_API_REQUEST_RESPONSE_CODE,
};
use crate::net::api::HasApiContext;

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

pub(super) async fn run_iroh_api(
    api: Arc<IrohApiState>,
    endpoint: Endpoint,
    task_group: TaskGroup,
) {
    loop {
        match endpoint.accept().await {
            Some(incoming) => {
                let permit = acquire_iroh_api_permit(
                    &api.parallel_connections_limit,
                    api.limits.max_connections,
                    "0.35",
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
                    )
                    .then(|result| async {
                        if let Err(err) = result {
                            warn!(target: LOG_NET_API, err = %err.fmt_compact_anyhow(), "Failed to handle iroh connection");
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
    version: &'static str,
    resource: &'static str,
) -> tokio::sync::OwnedSemaphorePermit {
    if limit.available_permits() == 0 {
        warn!(
            target: LOG_NET_API,
            limit = max,
            version,
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
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    handle_iroh_api_connection(
        api,
        task_group,
        VersionedIrohConnection::Legacy(connection),
        connection_permit,
        iroh_api_max_requests_per_connection,
        IrohApiVersion::Legacy,
    )
    .await
}

#[derive(Clone, Copy)]
enum IrohApiVersion {
    Legacy,
    Next,
}

impl IrohApiVersion {
    fn log_label(self) -> &'static str {
        match self {
            Self::Legacy => "0.35",
            Self::Next => "1.0",
        }
    }

    fn metric_label(self) -> &'static str {
        match self {
            Self::Legacy => "default",
            Self::Next => "next",
        }
    }

    fn request_task_name(self) -> &'static str {
        match self {
            Self::Legacy => "handle-iroh-request",
            Self::Next => "handle-iroh-next-request",
        }
    }
}

enum VersionedIrohConnection {
    Legacy(iroh::endpoint::Connection),
    Next(iroh_next::endpoint::Connection),
}

impl VersionedIrohConnection {
    async fn accept_bi(&self) -> anyhow::Result<(VersionedSendStream, VersionedRecvStream)> {
        Ok(match self {
            Self::Legacy(connection) => {
                let (send, recv) = connection.accept_bi().await?;
                (
                    VersionedSendStream::Legacy(send),
                    VersionedRecvStream::Legacy(recv),
                )
            }
            Self::Next(connection) => {
                let (send, recv) = connection.accept_bi().await?;
                (
                    VersionedSendStream::Next(send),
                    VersionedRecvStream::Next(recv),
                )
            }
        })
    }

    fn close_for_idle_timeout(&self) {
        match self {
            Self::Legacy(connection) => connection.close(
                VarInt::from_u32(IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_CODE),
                IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_REASON,
            ),
            Self::Next(connection) => connection.close(
                iroh_next::endpoint::VarInt::from_u32(IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_CODE),
                IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_REASON,
            ),
        }
    }
}

enum VersionedSendStream {
    Legacy(SendStream),
    Next(iroh_next::endpoint::SendStream),
}

impl VersionedSendStream {
    async fn write_response(mut self, response: &[u8]) -> anyhow::Result<()> {
        match &mut self {
            Self::Legacy(send) => {
                send.write_all(response).await?;
                send.finish()?;
            }
            Self::Next(send) => {
                send.write_all(response).await?;
                send.finish()?;
            }
        }
        Ok(())
    }
}

enum VersionedRecvStream {
    Legacy(RecvStream),
    Next(iroh_next::endpoint::RecvStream),
}

impl VersionedRecvStream {
    async fn read_request(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(match self {
            Self::Legacy(recv) => recv.read_to_end(100_000).await?,
            Self::Next(recv) => recv.read_to_end(100_000).await?,
        })
    }
}

async fn handle_iroh_api_connection(
    api: Arc<IrohApiState>,
    task_group: TaskGroup,
    connection: VersionedIrohConnection,
    _connection_permit: tokio::sync::OwnedSemaphorePermit,
    max_requests: usize,
    version: IrohApiVersion,
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
                    version = version.log_label(),
                    idle_timeout_secs = IROH_API_CONNECTION_IDLE_TIMEOUT.as_secs(),
                    "Closing idle Iroh API connection"
                );
                connection.close_for_idle_timeout();
                return Ok(());
            }
        };

        let permit = acquire_iroh_api_permit(
            &parallel_requests_limit,
            max_requests,
            version.log_label(),
            "request",
        )
        .await;
        task_group.spawn_cancellable_silent(
            version.request_task_name(),
            handle_iroh_api_stream(
                api.clone(),
                send_stream,
                recv_stream,
                permit,
                version.metric_label(),
            )
            .then(|result| async {
                if let Err(err) = result {
                    warn!(target: LOG_NET_API, err = %err.fmt_compact_anyhow(), "Failed to handle Iroh API request");
                }
            }),
        );
    }
}

async fn handle_iroh_api_stream(
    api: Arc<IrohApiState>,
    send_stream: VersionedSendStream,
    mut recv_stream: VersionedRecvStream,
    _request_permit: tokio::sync::OwnedSemaphorePermit,
    metric_label: &'static str,
) -> anyhow::Result<()> {
    let request = recv_stream.read_request().await?;
    let response = handle_iroh_api_request(&api, &request, metric_label).await?;
    send_stream.write_response(&response).await
}

async fn handle_iroh_api_request(
    api: &IrohApiState,
    request: &[u8],
    version_label: &'static str,
) -> anyhow::Result<Vec<u8>> {
    let request = serde_json::from_slice::<IrohApiRequest>(request)?;
    let request_method = request.method.clone();
    let response = record_request_metrics(
        &api.core,
        &api.modules,
        &request_method,
        version_label,
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
    version_label: &'static str,
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
        .with_label_values(&[method.as_ref(), response_code.as_str(), version_label])
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

            let (state, context) = api.consensus.context(&request.request, None).await;

            run_handler(
                None,
                &method,
                (endpoint.handler)(state, context, request.request),
            )
            .await
        }
        ApiMethod::Module(module_id, method) => {
            let endpoint = api
                .modules
                .get(&module_id)
                .ok_or_else(|| ApiError::not_found(module_id.to_string()))?
                .get(&method)
                .ok_or_else(|| ApiError::not_found(method.clone()))?;

            let (state, context) = api
                .consensus
                .context(&request.request, Some(module_id))
                .await;

            run_handler(
                Some(module_id),
                &method,
                (endpoint.handler)(state, context, request.request),
            )
            .await
        }
    }
}

/// Runs an API endpoint handler, turning a panic into an error response for the
/// caller that triggered it.
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
    AssertUnwindSafe(handler)
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

// --- iroh-next API endpoint functions ---

pub(super) async fn run_iroh_api_next(
    api: Arc<IrohApiState>,
    endpoint: iroh_next::Endpoint,
    task_group: TaskGroup,
) {
    loop {
        match endpoint.accept().await {
            Some(incoming) => {
                let permit = acquire_iroh_api_permit(
                    &api.parallel_connections_limit,
                    api.limits.max_connections,
                    "1.0",
                    "connection",
                )
                .await;
                task_group.spawn_cancellable_silent(
                    "handle-iroh-next-connection",
                    handle_incoming_next(
                        api.clone(),
                        task_group.clone(),
                        incoming,
                        permit,
                        api.limits.max_requests_per_connection,
                    )
                    .then(|result| async {
                        if let Err(err) = result {
                            warn!(target: LOG_NET_API, err = %err.fmt_compact_anyhow(), "Failed to handle iroh-next connection");
                        }
                    }),
                );
            }
            None => return,
        }
    }
}

async fn handle_incoming_next(
    api: Arc<IrohApiState>,
    task_group: TaskGroup,
    incoming: iroh_next::endpoint::Incoming,
    connection_permit: tokio::sync::OwnedSemaphorePermit,
    iroh_api_max_requests_per_connection: usize,
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    handle_iroh_api_connection(
        api,
        task_group,
        VersionedIrohConnection::Next(connection),
        connection_permit,
        iroh_api_max_requests_per_connection,
        IrohApiVersion::Next,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::SocketAddr;

    use anyhow::Context as _;
    use fedimint_metrics::prometheus::core::Collector;
    use fedimint_metrics::prometheus::proto::Metric;
    use futures::future::pending;
    use futures::{pin_mut, poll};
    use iroh_next::endpoint::presets::Minimal;
    use iroh_next::{EndpointAddr, RelayMode, SecretKey, TransportAddr};

    use super::*;

    const TEST_ALPN: &[u8] = b"fedimint-iroh-api-adapter-test";

    fn has_method_label(metric: &Metric, method: &str) -> bool {
        metric
            .get_label()
            .iter()
            .any(|label| label.name() == "method" && label.value() == method)
    }

    fn duration_count(method: &str) -> u64 {
        IROH_API_REQUEST_DURATION_SECONDS
            .collect()
            .into_iter()
            .flat_map(|family| family.metric)
            .filter(|metric| has_method_label(metric, method))
            .map(|metric| metric.histogram.sample_count())
            .sum()
    }

    fn response_count(method: &str) -> u64 {
        IROH_API_REQUEST_RESPONSE_CODE
            .collect()
            .into_iter()
            .flat_map(|family| family.metric)
            .filter(|metric| has_method_label(metric, method))
            .map(|metric| metric.counter.value() as u64)
            .sum()
    }

    fn method_series(metrics: Vec<Metric>, method: &str) -> BTreeSet<Vec<(String, String)>> {
        metrics
            .into_iter()
            .filter(|metric| has_method_label(metric, method))
            .map(|metric| {
                metric
                    .label
                    .into_iter()
                    .map(|label| (label.name().to_owned(), label.value().to_owned()))
                    .collect()
            })
            .collect()
    }

    fn duration_series(method: &str) -> BTreeSet<Vec<(String, String)>> {
        method_series(
            IROH_API_REQUEST_DURATION_SECONDS
                .collect()
                .into_iter()
                .flat_map(|family| family.metric)
                .collect(),
            method,
        )
    }

    fn response_series(method: &str) -> BTreeSet<Vec<(String, String)>> {
        method_series(
            IROH_API_REQUEST_RESPONSE_CODE
                .collect()
                .into_iter()
                .flat_map(|family| family.metric)
                .collect(),
            method,
        )
    }

    #[tokio::test]
    async fn bounds_method_labels_for_all_iroh_request_metrics() {
        const CORE_METHOD: &str = "metrics_test_core";
        const MODULE_ID: ModuleInstanceId = 42;
        const MODULE_METHOD: &str = "metrics_test_module";
        const MODULE_LABEL: &str = "42-metrics_test_module";

        let core = BTreeMap::from([(CORE_METHOD.to_owned(), true)]);
        let modules = BTreeMap::from([(
            MODULE_ID,
            BTreeMap::from([(MODULE_METHOD.to_owned(), true)]),
        )]);
        let hostile_methods = [
            ApiMethod::Core("metrics_test_unknown_core".to_owned()),
            ApiMethod::Core("metrics_test_unknown_core_!@#$%^&*()".to_owned()),
            ApiMethod::Module(MODULE_ID, "metrics_test_unknown_module_method".to_owned()),
            ApiMethod::Module(
                MODULE_ID,
                "metrics_test_unknown_module_method_with_a_long_suffix".to_owned(),
            ),
            ApiMethod::Module(43, "metrics_test_unknown_module".to_owned()),
            ApiMethod::Module(44, "metrics_test_unknown_module_!@#$%^&*()".to_owned()),
        ];

        assert_eq!(
            metric_method(&core, &modules, &ApiMethod::Core(CORE_METHOD.to_owned())),
            CORE_METHOD
        );
        assert_eq!(
            metric_method(
                &core,
                &modules,
                &ApiMethod::Module(MODULE_ID, MODULE_METHOD.to_owned())
            ),
            MODULE_LABEL
        );
        for method in &hostile_methods {
            assert_eq!(metric_method(&core, &modules, method), UNKNOWN_METHOD);
        }

        let duration_before = [
            duration_count(CORE_METHOD),
            duration_count(MODULE_LABEL),
            duration_count(UNKNOWN_METHOD),
        ];
        let response_before = [
            response_count(CORE_METHOD),
            response_count(MODULE_LABEL),
            response_count(UNKNOWN_METHOD),
        ];

        record_request_metrics(
            &core,
            &modules,
            &ApiMethod::Core(CORE_METHOD.to_owned()),
            "default",
            async { Ok::<_, ApiError>(()) },
        )
        .await
        .expect("registered core request succeeds");
        record_request_metrics(
            &core,
            &modules,
            &ApiMethod::Module(MODULE_ID, MODULE_METHOD.to_owned()),
            "next",
            async { Ok::<_, ApiError>(()) },
        )
        .await
        .expect("registered module request succeeds");
        for method in &hostile_methods {
            record_request_metrics(&core, &modules, method, "default", async {
                Err::<(), _>(ApiError::not_found("test rejection".to_owned()))
            })
            .await
            .expect_err("unregistered request is rejected");
        }

        {
            let cancelled_method =
                ApiMethod::Core("metrics_test_cancelled_attacker_input".to_owned());
            let cancelled = record_request_metrics(
                &core,
                &modules,
                &cancelled_method,
                "default",
                pending::<Result<(), ApiError>>(),
            );
            pin_mut!(cancelled);
            assert!(poll!(cancelled.as_mut()).is_pending());
        }

        assert_eq!(duration_count(CORE_METHOD) - duration_before[0], 1);
        assert_eq!(duration_count(MODULE_LABEL) - duration_before[1], 1);
        assert_eq!(
            duration_count(UNKNOWN_METHOD) - duration_before[2],
            hostile_methods.len() as u64 + 1
        );
        assert_eq!(response_count(CORE_METHOD) - response_before[0], 1);
        assert_eq!(response_count(MODULE_LABEL) - response_before[1], 1);
        assert_eq!(
            response_count(UNKNOWN_METHOD) - response_before[2],
            hostile_methods.len() as u64
        );
        assert_eq!(duration_series(UNKNOWN_METHOD).len(), 1);
        let unknown_response_series = response_series(UNKNOWN_METHOD);
        assert_eq!(unknown_response_series.len(), 1);
        assert!(unknown_response_series.iter().any(|labels| {
            labels
                .iter()
                .any(|(name, value)| name == "code" && value == "404")
                && labels
                    .iter()
                    .any(|(name, value)| name == "type" && value == "default")
        }));
        assert!(response_series(CORE_METHOD).iter().any(|labels| {
            labels
                .iter()
                .any(|(name, value)| name == "code" && value == "0")
                && labels
                    .iter()
                    .any(|(name, value)| name == "type" && value == "default")
        }));
        assert!(response_series(MODULE_LABEL).iter().any(|labels| {
            labels
                .iter()
                .any(|(name, value)| name == "code" && value == "0")
                && labels
                    .iter()
                    .any(|(name, value)| name == "type" && value == "next")
        }));

        for method in hostile_methods
            .iter()
            .map(ToString::to_string)
            .chain(["metrics_test_cancelled_attacker_input".to_owned()])
        {
            assert!(duration_series(&method).is_empty());
            assert!(response_series(&method).is_empty());
        }
    }

    #[tokio::test]
    async fn panicking_handler_returns_an_error_instead_of_unwinding() {
        let error = run_handler(None, "test_endpoint", async { panic!("handler panic") })
            .await
            .expect_err("a panicking handler is reported as a server error");

        assert_eq!(error.code, 500);

        let error = run_handler(Some(3), "test_endpoint", async {
            panic!("module handler panic")
        })
        .await
        .expect_err("a panicking module handler is reported as a server error");

        assert_eq!(error.code, 500);
    }

    #[tokio::test]
    async fn shared_connection_limit_applies_across_versions() {
        let limit = Arc::new(Semaphore::new(1));
        let legacy_permit = acquire_iroh_api_permit(&limit, 1, "0.35", "connection").await;

        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                acquire_iroh_api_permit(&limit, 1, "1.0", "connection"),
            )
            .await
            .is_err()
        );

        drop(legacy_permit);
        let _permit = tokio::time::timeout(
            Duration::from_secs(1),
            acquire_iroh_api_permit(&limit, 1, "1.0", "connection"),
        )
        .await
        .expect("v1 acquires the shared permit after the legacy connection releases it");
    }

    #[tokio::test]
    async fn iroh_v1_request_uses_shared_stream_adapter() -> anyhow::Result<()> {
        let server = iroh_next::Endpoint::builder(Minimal)
            .relay_mode(RelayMode::Disabled)
            .secret_key(SecretKey::from_bytes(&[11; 32]))
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
            .bind()
            .await?;
        let client = iroh_next::Endpoint::builder(Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server_addr = EndpointAddr::from_parts(
            server.id(),
            server.bound_sockets().into_iter().map(TransportAddr::Ip),
        );
        let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel();

        let server_request = async {
            let incoming = server.accept().await.context("server endpoint closed")?;
            let connection = incoming.accept()?.await?;
            let (send, mut recv) = VersionedIrohConnection::Next(connection)
                .accept_bi()
                .await?;
            assert_eq!(recv.read_request().await?, b"request");
            send.write_response(b"response").await?;
            client_done_rx.await?;
            anyhow::Ok(())
        };
        let client_request = async {
            let connection = client.connect(server_addr, TEST_ALPN).await?;
            let (mut send, mut recv) = connection.open_bi().await?;
            send.write_all(b"request").await?;
            send.finish()?;
            let response = recv.read_to_end(100_000).await?;
            anyhow::ensure!(response == b"response");
            client_done_tx.send(()).expect("server is still running");
            anyhow::Ok(())
        };

        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::try_join!(server_request, client_request)
        })
        .await
        .context("Iroh v1 adapter test timed out")??;
        client.close().await;
        server.close().await;
        Ok(())
    }
}
