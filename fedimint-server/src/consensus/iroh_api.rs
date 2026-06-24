use std::collections::BTreeMap;
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
use tracing::warn;

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
    let method = request.method.to_string();
    let timer = IROH_API_REQUEST_DURATION_SECONDS
        .with_label_values(&[&method])
        .start_timer();
    let response = await_response(api, request).await;
    timer.observe_duration();

    let response_code = response
        .as_ref()
        .map_or_else(|err| err.code.to_string(), |_| "0".to_string());
    IROH_API_REQUEST_RESPONSE_CODE
        .with_label_values(&[method.as_str(), response_code.as_str(), version_label])
        .inc();

    Ok(serde_json::to_vec(&response)?)
}

async fn await_response(api: &IrohApiState, request: IrohApiRequest) -> Result<Value, ApiError> {
    match request.method {
        ApiMethod::Core(method) => {
            let endpoint = api.core.get(&method).ok_or(ApiError::not_found(method))?;

            let (state, context) = api.consensus.context(&request.request, None).await;

            (endpoint.handler)(state, context, request.request).await
        }
        ApiMethod::Module(module_id, method) => {
            let endpoint = api
                .modules
                .get(&module_id)
                .ok_or(ApiError::not_found(module_id.to_string()))?
                .get(&method)
                .ok_or(ApiError::not_found(method))?;

            let (state, context) = api
                .consensus
                .context(&request.request, Some(module_id))
                .await;

            (endpoint.handler)(state, context, request.request).await
        }
    }
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
    use std::net::SocketAddr;

    use anyhow::Context as _;
    use iroh_next::endpoint::presets::Minimal;
    use iroh_next::{EndpointAddr, RelayMode, SecretKey, TransportAddr};

    use super::*;

    const TEST_ALPN: &[u8] = b"fedimint-iroh-api-adapter-test";

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
