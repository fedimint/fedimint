use std::borrow::Cow;
use std::collections::BTreeMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    let accepting = match incoming.accept() {
        Ok(accepting) => accepting,
        Err(err) => {
            return log_benign_connection_end_or_propagate(err.into(), IrohApiVersion::Legacy);
        }
    };
    let connection = match accepting.await {
        Ok(connection) => connection,
        Err(err) => {
            return log_benign_connection_end_or_propagate(err.into(), IrohApiVersion::Legacy);
        }
    };
    let parallel_requests_limit = Arc::new(Semaphore::new(iroh_api_max_requests_per_connection));
    handle_iroh_api_connection(
        task_group,
        VersionedIrohConnection::Legacy(connection),
        connection_permit,
        parallel_requests_limit,
        iroh_api_max_requests_per_connection,
        IrohApiVersion::Legacy,
        move |send_stream, recv_stream, permit| {
            let api = api.clone();
            handle_iroh_api_stream(
                send_stream,
                recv_stream,
                permit,
                IrohApiVersion::Legacy,
                move |request| async move {
                    handle_iroh_api_request(&api, &request, IrohApiVersion::Legacy.metric_label())
                        .await
                },
            )
        },
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

/// Whether an Iroh error is an ordinary end of a connection rather than a fault
/// an operator should be told about.
///
/// Clients close a connection whose request budget elapsed, which is routine
/// for a long-poll refresh, and abrupt client death surfaces as the idle
/// timeout or a reset. `LocallyClosed` is not a client hang-up at all - it is
/// this server closing the connection, via `close_for_idle_timeout` or endpoint
/// shutdown - but it is no more a fault than the rest, so it belongs here too.
/// `ConnectionClosed` is deliberately excluded: it means the peer's QUIC stack
/// aborted the connection, which is a transport fault rather than a client
/// hanging up.
///
/// Errors that merely wrap a `ConnectionError` are classified by what they
/// wrap, so a transport fault keeps its `warn!` however deep it is buried:
/// the stream-level `ConnectionLost` on both transports, and iroh-next's
/// handshake `ConnectingError` (iroh 0.35's `Connecting` yields a bare
/// `ConnectionError` instead, so it needs no unwrapping).
fn is_benign_connection_end(error: &anyhow::Error) -> bool {
    is_legacy_benign_connection_end(error) || is_next_benign_connection_end(error)
}

fn is_legacy_benign_connection_end(error: &anyhow::Error) -> bool {
    use iroh::endpoint::{ConnectionError, ReadError, ReadToEndError, WriteError};

    fn connection(error: &ConnectionError) -> bool {
        matches!(
            error,
            ConnectionError::ApplicationClosed(_)
                | ConnectionError::LocallyClosed
                | ConnectionError::TimedOut
                | ConnectionError::Reset
        )
    }
    fn write(error: &WriteError) -> bool {
        match error {
            WriteError::Stopped(_) => true,
            WriteError::ConnectionLost(error) => connection(error),
            _ => false,
        }
    }
    fn read(error: &ReadError) -> bool {
        match error {
            ReadError::Reset(_) => true,
            ReadError::ConnectionLost(error) => connection(error),
            _ => false,
        }
    }

    error
        .downcast_ref::<ConnectionError>()
        .is_some_and(connection)
        || error.downcast_ref::<WriteError>().is_some_and(write)
        || error.downcast_ref::<ReadError>().is_some_and(read)
        || error
            .downcast_ref::<ReadToEndError>()
            .is_some_and(|error| matches!(error, ReadToEndError::Read(error) if read(error)))
}

fn is_next_benign_connection_end(error: &anyhow::Error) -> bool {
    use iroh_next::endpoint::{
        ConnectingError, ConnectionError, ReadError, ReadToEndError, WriteError,
    };

    fn connection(error: &ConnectionError) -> bool {
        matches!(
            error,
            ConnectionError::ApplicationClosed(_)
                | ConnectionError::LocallyClosed
                | ConnectionError::TimedOut
                | ConnectionError::Reset
        )
    }
    fn write(error: &WriteError) -> bool {
        match error {
            WriteError::Stopped(_) => true,
            WriteError::ConnectionLost(error) => connection(error),
            _ => false,
        }
    }
    fn read(error: &ReadError) -> bool {
        match error {
            ReadError::Reset(_) => true,
            ReadError::ConnectionLost(error) => connection(error),
            _ => false,
        }
    }

    error
        .downcast_ref::<ConnectionError>()
        .is_some_and(connection)
        || error.downcast_ref::<WriteError>().is_some_and(write)
        || error.downcast_ref::<ReadError>().is_some_and(read)
        || error
            .downcast_ref::<ReadToEndError>()
            .is_some_and(|error| matches!(error, ReadToEndError::Read(error) if read(error)))
        || error.downcast_ref::<ConnectingError>().is_some_and(|error| {
            matches!(error, ConnectingError::ConnectionError { source, .. } if connection(source))
        })
}

/// Demotes a benign connection end to `debug` and hands every other error back
/// to the caller, which decides how loudly to report a genuine fault.
///
/// Shared by the three places an Iroh error surfaces: connection
/// establishment, `accept_bi`, and a per-request handler.
fn log_benign_connection_end_or_propagate(
    error: anyhow::Error,
    version: IrohApiVersion,
) -> anyhow::Result<()> {
    if !is_benign_connection_end(&error) {
        return Err(error);
    }

    tracing::debug!(
        target: LOG_NET_API,
        version = version.log_label(),
        err = %error.fmt_compact_anyhow(),
        "Iroh API connection ended without a fault"
    );
    Ok(())
}

#[derive(Clone)]
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

    /// Resolves once this connection is closed, for either iroh version.
    async fn closed(&self) {
        match self {
            Self::Legacy(connection) => {
                connection.closed().await;
            }
            Self::Next(connection) => {
                connection.closed().await;
            }
        }
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
    /// Resolves once the client stops waiting for this request: dropping its
    /// `RecvStream` makes quinn send `STOP_SENDING`, which surfaces here.
    ///
    /// This cannot fire spuriously before a response is written. It can also
    /// resolve when the connection is lost, which cancels the request just as
    /// legitimately. Local completion cannot happen before anything is written,
    /// and 0-RTT rejection is impossible because the server does not create
    /// 0-RTT streams. The outcome is therefore deliberately discarded: every
    /// way this resolves here means the response has nowhere left to go.
    async fn stopped(&mut self) {
        match self {
            Self::Legacy(send) => {
                let _ = send.stopped().await;
            }
            Self::Next(send) => {
                let _ = send.stopped().await;
            }
        }
    }

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

async fn cancel_on_connection_close(
    connection: &VersionedIrohConnection,
    handler: impl Future<Output = anyhow::Result<()>>,
) -> Option<anyhow::Result<()>> {
    tokio::select! {
        biased;
        () = connection.closed() => None,
        result = handler => Some(result),
    }
}

/// Serves requests off one Iroh API connection until it goes away.
///
/// `parallel_requests_limit` must be a semaphore built for this connection
/// alone, holding `max_requests` permits: the idle reap below reads any
/// outstanding permit as a request of this connection still in flight.
async fn handle_iroh_api_connection<Handler, HandlerFuture>(
    task_group: TaskGroup,
    connection: VersionedIrohConnection,
    _connection_permit: tokio::sync::OwnedSemaphorePermit,
    parallel_requests_limit: Arc<Semaphore>,
    max_requests: usize,
    version: IrohApiVersion,
    handle_stream: Handler,
) -> anyhow::Result<()>
where
    Handler: Fn(
            VersionedSendStream,
            VersionedRecvStream,
            tokio::sync::OwnedSemaphorePermit,
        ) -> HandlerFuture
        + Clone
        + Send
        + 'static,
    HandlerFuture: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let _metrics = ActiveIrohApiConnection::new();

    loop {
        let accept_result = fedimint_core::runtime::timeout(
            IROH_API_CONNECTION_IDLE_TIMEOUT,
            connection.accept_bi(),
        )
        .await;

        let (send_stream, recv_stream) = match accept_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(err)) => return log_benign_connection_end_or_propagate(err, version),
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
        let connection_for_request = connection.clone();
        let handle_stream = handle_stream.clone();
        task_group.spawn_cancellable_silent(version.request_task_name(), async move {
            // Cancelling an in-flight request once the client is gone is safe:
            // the response can no longer be delivered, and a dbtx that has not
            // committed is dropped atomically. A dirty uncommitted dbtx emits the
            // standard warning and captures a backtrace when cancellation drops
            // it (`submit_transaction` is exempt via `ignore_uncommitted()`).
            // Reaching that warning means landing between a handler's first
            // dbtx write and its `commit_tx*` call, so it takes a non-database
            // await inside that stretch to be reachable at all - the database
            // ones resolve within a single poll, since `fedimint-rocksdb` runs
            // them under `block_in_place`. Today's writing endpoints have no
            // such await: `consensus/api.rs`'s unauthenticated
            // `BACKUP_ENDPOINT`, the widest-open of them, runs `insert_entry`
            // straight through `commit_tx_result`, and the LN module's gateway
            // register and remove endpoints have the same shape.
            // Where a write HAS committed the client sees a failed request and
            // may retry, which is equivalent - not literally identical, since a
            // retried `sign_api_announcement` bumps its nonce and a retried meta
            // submit draws a fresh salt - and is already what happens when a
            // connection drops mid-response. The threshold-quorum `upload_backup`
            // and `register_gateway` writes land on at least `threshold()` peers
            // but may leave slower peers unchanged; those APIs tolerate that.
            //
            // This outer race ties the whole handler lifetime to the connection,
            // including any state not currently polling a stream-local signal.
            let result = cancel_on_connection_close(
                &connection_for_request,
                handle_stream(send_stream, recv_stream, permit),
            )
            .await;

            match result {
                Some(Ok(())) => {}
                Some(Err(err)) => {
                    if let Err(err) = log_benign_connection_end_or_propagate(err, version) {
                        warn!(
                            target: LOG_NET_API,
                            version = version.log_label(),
                            err = %err.fmt_compact_anyhow(),
                            "Failed to handle Iroh API request"
                        );
                    }
                }
                None => tracing::debug!(
                    target: LOG_NET_API,
                    version = version.log_label(),
                    "Cancelling in-flight Iroh API request, connection closed"
                ),
            }
        });
    }
}

/// Reads one request off a stream and writes back what `respond` makes of it,
/// racing each half against the client abandoning this request.
///
/// The `stopped()` future the read races against is dropped with that read; the
/// write below builds a fresh one, so the two halves never share a race.
async fn handle_iroh_api_stream<Respond, RespondFuture>(
    mut send_stream: VersionedSendStream,
    mut recv_stream: VersionedRecvStream,
    _request_permit: tokio::sync::OwnedSemaphorePermit,
    version: IrohApiVersion,
    respond: Respond,
) -> anyhow::Result<()>
where
    Respond: FnOnce(Vec<u8>) -> RespondFuture,
    RespondFuture: Future<Output = anyhow::Result<Vec<u8>>>,
{
    let Some(request) = read_iroh_api_request(&mut send_stream, &mut recv_stream, version).await?
    else {
        return Ok(());
    };
    write_iroh_api_response(send_stream, respond(request), version).await
}

async fn read_iroh_api_request(
    send_stream: &mut VersionedSendStream,
    recv_stream: &mut VersionedRecvStream,
    version: IrohApiVersion,
) -> anyhow::Result<Option<Vec<u8>>> {
    tokio::select! {
        biased;
        () = send_stream.stopped() => {
            tracing::debug!(
                target: LOG_NET_API,
                version = version.log_label(),
                "Cancelling in-flight Iroh API request while reading, client is no longer waiting for it"
            );
            Ok(None)
        },
        request = recv_stream.read_request() => Ok(Some(request?)),
    }
}

async fn write_iroh_api_response(
    mut send_stream: VersionedSendStream,
    response: impl Future<Output = anyhow::Result<Vec<u8>>>,
    version: IrohApiVersion,
) -> anyhow::Result<()> {
    // A client that gives up on this one request while keeping the connection
    // for its others drops its `RecvStream`, which arrives here as `stopped()`.
    let response = tokio::select! {
        biased;
        () = send_stream.stopped() => {
            tracing::debug!(
                target: LOG_NET_API,
                version = version.log_label(),
                "Cancelling in-flight Iroh API request, client is no longer waiting for it"
            );
            return Ok(());
        },
        response = response => response?,
    };

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
    // Timed by hand rather than with a `HistogramTimer`, which observes on drop:
    // a cancelled request would otherwise file the time it sat parked as if it
    // were a served request's latency, with no matching response code below.
    let started = Instant::now();
    let response = response.await;
    IROH_API_REQUEST_DURATION_SECONDS
        .with_label_values(&[method.as_ref()])
        .observe(started.elapsed().as_secs_f64());

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
    let accepting = match incoming.accept() {
        Ok(accepting) => accepting,
        Err(err) => {
            return log_benign_connection_end_or_propagate(err.into(), IrohApiVersion::Next);
        }
    };
    let connection = match accepting.await {
        Ok(connection) => connection,
        Err(err) => {
            return log_benign_connection_end_or_propagate(err.into(), IrohApiVersion::Next);
        }
    };
    let parallel_requests_limit = Arc::new(Semaphore::new(iroh_api_max_requests_per_connection));
    handle_iroh_api_connection(
        task_group,
        VersionedIrohConnection::Next(connection),
        connection_permit,
        parallel_requests_limit,
        iroh_api_max_requests_per_connection,
        IrohApiVersion::Next,
        move |send_stream, recv_stream, permit| {
            let api = api.clone();
            handle_iroh_api_stream(
                send_stream,
                recv_stream,
                permit,
                IrohApiVersion::Next,
                move |request| async move {
                    handle_iroh_api_request(&api, &request, IrohApiVersion::Next.metric_label())
                        .await
                },
            )
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use anyhow::Context as _;
    use bytes::Bytes;
    use fedimint_metrics::prometheus::core::Collector;
    use fedimint_metrics::prometheus::proto::Metric;
    use futures::future::pending;
    use futures::{pin_mut, poll};
    use iroh_next::endpoint::presets::Minimal;
    use iroh_next::{EndpointAddr, RelayMode, TransportAddr};

    use super::*;

    const TEST_ALPN: &[u8] = b"fedimint-iroh-api-adapter-test";
    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    struct ConnectedPair {
        _server_endpoint: iroh_next::Endpoint,
        _client_endpoint: iroh_next::Endpoint,
        server: iroh_next::endpoint::Connection,
        client: iroh_next::endpoint::Connection,
    }

    async fn connected_pair() -> anyhow::Result<ConnectedPair> {
        let server_endpoint = iroh_next::Endpoint::builder(Minimal)
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
            .bind()
            .await?;
        let client_endpoint = iroh_next::Endpoint::builder(Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server_addr = EndpointAddr::from_parts(
            server_endpoint.id(),
            server_endpoint
                .bound_sockets()
                .into_iter()
                .map(TransportAddr::Ip),
        );

        let (server, client) = tokio::time::timeout(
            TEST_TIMEOUT,
            futures::future::try_join(
                async {
                    let incoming = server_endpoint
                        .accept()
                        .await
                        .context("server endpoint closed")?;

                    anyhow::Ok(incoming.accept()?.await?)
                },
                async { anyhow::Ok(client_endpoint.connect(server_addr, TEST_ALPN).await?) },
            ),
        )
        .await
        .context("connecting the test endpoints timed out")??;

        Ok(ConnectedPair {
            _server_endpoint: server_endpoint,
            _client_endpoint: client_endpoint,
            server,
            client,
        })
    }

    struct ConnectedPairLegacy {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        server: iroh::endpoint::Connection,
        client: iroh::endpoint::Connection,
    }

    async fn connected_pair_legacy() -> anyhow::Result<ConnectedPairLegacy> {
        let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let server_endpoint = Endpoint::builder()
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind_addr_v4(loopback)
            .bind()
            .await?;
        let client_endpoint = Endpoint::builder()
            .relay_mode(iroh::RelayMode::Disabled)
            .bind_addr_v4(loopback)
            .bind()
            .await?;
        let server_addr = iroh::NodeAddr::from_parts(
            server_endpoint.node_id(),
            None,
            [server_endpoint.bound_sockets().0],
        );

        let (server, client) = tokio::time::timeout(
            TEST_TIMEOUT,
            futures::future::try_join(
                async {
                    let incoming = server_endpoint
                        .accept()
                        .await
                        .context("server endpoint closed")?;

                    anyhow::Ok(incoming.accept()?.await?)
                },
                async { anyhow::Ok(client_endpoint.connect(server_addr, TEST_ALPN).await?) },
            ),
        )
        .await
        .context("connecting the legacy test endpoints timed out")??;

        Ok(ConnectedPairLegacy {
            _server_endpoint: server_endpoint,
            _client_endpoint: client_endpoint,
            server,
            client,
        })
    }

    #[tokio::test]
    async fn connection_loop_cancels_request_and_releases_permit_when_connection_closes()
    -> anyhow::Result<()> {
        const MAX_REQUESTS: usize = 1;

        let pair = connected_pair().await?;
        let task_group = TaskGroup::new();
        let connection_permit = Arc::new(Semaphore::new(1))
            .acquire_owned()
            .await
            .expect("test semaphore is open");
        let request_limit = Arc::new(Semaphore::new(MAX_REQUESTS));
        let request_started = Arc::new(tokio::sync::Notify::new());
        let request_started_for_handler = request_started.clone();
        let server_connection = VersionedIrohConnection::Next(pair.server.clone());
        let request_limit_for_server = request_limit.clone();
        let task_group_for_server = task_group.clone();
        let server_task = fedimint_core::runtime::spawn(
            "test-iroh-production-connection-cancellation",
            async move {
                handle_iroh_api_connection(
                    task_group_for_server,
                    server_connection,
                    connection_permit,
                    request_limit_for_server,
                    MAX_REQUESTS,
                    IrohApiVersion::Next,
                    move |send_stream, mut recv_stream, permit| {
                        let request_started = request_started_for_handler.clone();
                        async move {
                            recv_stream.read_request().await?;
                            request_started.notify_one();
                            // Held so only the connection close can free them.
                            let _keep = (send_stream, permit);
                            std::future::pending::<()>().await;
                            Ok(())
                        }
                    },
                )
                .await
            },
        );

        let (mut client_send, _client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"request").await?;
        client_send.finish()?;
        tokio::time::timeout(TEST_TIMEOUT, request_started.notified())
            .await
            .context("request handler did not start")?;
        assert_eq!(request_limit.available_permits(), 0);

        pair.client
            .close(iroh_next::endpoint::VarInt::from_u32(0), b"done");
        let connection_result = tokio::time::timeout(TEST_TIMEOUT, server_task)
            .await
            .context("connection task did not stop after the client closed")??;
        assert!(
            connection_result.is_ok(),
            "connection task returned {connection_result:?}"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while request_limit.available_permits() != MAX_REQUESTS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("request permit remained held after the connection closed")?;

        Ok(())
    }

    #[tokio::test]
    async fn partial_request_is_dropped_when_its_response_is_abandoned() -> anyhow::Result<()> {
        const MAX_REQUESTS: usize = 1;

        let pair = connected_pair().await?;
        let (mut client_send, mut client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"partial request").await?;
        let (mut send_stream, mut recv_stream) = VersionedIrohConnection::Next(pair.server.clone())
            .accept_bi()
            .await?;
        let request_limit = Arc::new(Semaphore::new(MAX_REQUESTS));
        let permit = request_limit
            .clone()
            .acquire_owned()
            .await
            .expect("test semaphore is open");
        let handler_task =
            fedimint_core::runtime::spawn("test-iroh-partial-request-cancellation", async move {
                let result =
                    read_iroh_api_request(&mut send_stream, &mut recv_stream, IrohApiVersion::Next)
                        .await;
                drop(permit);
                result
            });

        client_recv.stop(iroh_next::endpoint::VarInt::from_u32(0))?;
        let handler_result = tokio::time::timeout(TEST_TIMEOUT, handler_task)
            .await
            .context("handler remained parked on the partial request after STOP_SENDING")??;
        assert!(handler_result?.is_none());
        assert_eq!(request_limit.available_permits(), MAX_REQUESTS);
        assert!(pair.server.close_reason().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn parked_handler_is_dropped_when_the_connection_closes() -> anyhow::Result<()> {
        let pair = connected_pair().await?;
        let (mut client_send, _client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"request").await?;
        client_send.finish()?;
        let (send_stream, _recv_stream) = VersionedIrohConnection::Next(pair.server.clone())
            .accept_bi()
            .await?;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handler = write_iroh_api_response(
            send_stream,
            async move {
                started_tx.send(()).expect("test is still waiting");
                std::future::pending::<anyhow::Result<Vec<u8>>>().await
            },
            IrohApiVersion::Next,
        );
        let server_connection = VersionedIrohConnection::Next(pair.server.clone());
        let server_task =
            fedimint_core::runtime::spawn("test-iroh-connection-cancellation", async move {
                cancel_on_connection_close(&server_connection, handler).await
            });
        tokio::time::timeout(TEST_TIMEOUT, started_rx).await??;

        pair.client
            .close(iroh_next::endpoint::VarInt::from_u32(0), b"done");
        let result = tokio::time::timeout(TEST_TIMEOUT, server_task).await??;
        assert!(result.is_none(), "handler won the connection-close race");
        Ok(())
    }

    #[tokio::test]
    async fn parked_handler_is_dropped_when_its_own_request_is_abandoned() -> anyhow::Result<()> {
        let pair = connected_pair().await?;
        let (mut client_send, mut client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"request").await?;
        client_send.finish()?;
        let (send_stream, _recv_stream) = VersionedIrohConnection::Next(pair.server.clone())
            .accept_bi()
            .await?;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handler_task = fedimint_core::runtime::spawn(
            "test-iroh-request-cancellation",
            write_iroh_api_response(
                send_stream,
                async move {
                    started_tx.send(()).expect("test is still waiting");
                    std::future::pending::<anyhow::Result<Vec<u8>>>().await
                },
                IrohApiVersion::Next,
            ),
        );
        tokio::time::timeout(TEST_TIMEOUT, started_rx).await??;

        client_recv.stop(iroh_next::endpoint::VarInt::from_u32(0))?;
        tokio::time::timeout(TEST_TIMEOUT, handler_task)
            .await
            .expect("handler remained parked after STOP_SENDING")??;
        assert!(pair.server.close_reason().is_none());
        Ok(())
    }

    /// A transport fault the peer's QUIC stack raised, which must keep its
    /// `warn!` however it reaches us.
    fn transport_fault() -> iroh::endpoint::ConnectionError {
        iroh::endpoint::ConnectionError::ConnectionClosed(iroh::endpoint::ConnectionClose {
            error_code: iroh::endpoint::TransportErrorCode::PROTOCOL_VIOLATION,
            frame_type: None,
            reason: Bytes::default(),
        })
    }

    /// `iroh-next`'s `ConnectionClose` has an unnameable `frame_type`, so build
    /// it from a `TransportError` instead of a struct literal.
    fn transport_fault_next() -> iroh_next::endpoint::ConnectionError {
        iroh_next::endpoint::ConnectionError::ConnectionClosed(
            iroh_next::endpoint::TransportError::new(
                iroh_next::endpoint::TransportErrorCode::PROTOCOL_VIOLATION,
                String::new(),
            )
            .into(),
        )
    }

    #[test]
    fn benign_connection_errors_end_the_accept_loop_without_hiding_transport_faults() {
        use iroh::endpoint::{ApplicationClose, ConnectionError};
        use iroh_next::endpoint::{
            ApplicationClose as ApplicationCloseNext, ConnectionError as ConnectionErrorNext,
            VarInt as VarIntNext,
        };

        for error in [
            ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: VarInt::from_u32(1),
                reason: Bytes::default(),
            }),
            ConnectionError::LocallyClosed,
            ConnectionError::TimedOut,
            ConnectionError::Reset,
        ] {
            assert!(
                log_benign_connection_end_or_propagate(error.into(), IrohApiVersion::Legacy)
                    .is_ok()
            );
        }
        assert!(
            log_benign_connection_end_or_propagate(
                transport_fault().into(),
                IrohApiVersion::Legacy
            )
            .is_err()
        );

        for error in [
            ConnectionErrorNext::ApplicationClosed(ApplicationCloseNext {
                error_code: VarIntNext::from_u32(1),
                reason: Bytes::default(),
            }),
            ConnectionErrorNext::LocallyClosed,
            ConnectionErrorNext::TimedOut,
            ConnectionErrorNext::Reset,
        ] {
            assert!(
                log_benign_connection_end_or_propagate(error.into(), IrohApiVersion::Next).is_ok()
            );
        }
        assert!(
            log_benign_connection_end_or_propagate(
                transport_fault_next().into(),
                IrohApiVersion::Next
            )
            .is_err()
        );
    }

    /// The stream and handshake errors carry a `ConnectionError` inside, so the
    /// classifier has to look at what they wrap rather than at the wrapper.
    #[test]
    fn wrapped_client_hang_ups_are_benign_but_wrapped_transport_faults_are_not() {
        use iroh::endpoint::{ConnectionError, ReadError, ReadToEndError, WriteError};
        use iroh_next::endpoint::{
            ConnectingError as ConnectingErrorNext, ConnectionError as ConnectionErrorNext,
            ReadError as ReadErrorNext, ReadToEndError as ReadToEndErrorNext, VarInt as VarIntNext,
            WriteError as WriteErrorNext,
        };

        for error in [
            anyhow::Error::from(WriteError::Stopped(VarInt::from_u32(1))),
            anyhow::Error::from(WriteError::ConnectionLost(ConnectionError::TimedOut)),
            anyhow::Error::from(ReadError::Reset(VarInt::from_u32(1))),
            anyhow::Error::from(ReadToEndError::Read(ReadError::ConnectionLost(
                ConnectionError::TimedOut,
            ))),
            anyhow::Error::from(WriteErrorNext::ConnectionLost(
                ConnectionErrorNext::TimedOut,
            )),
            anyhow::Error::from(ReadErrorNext::Reset(VarIntNext::from_u32(1))),
            anyhow::Error::from(ReadToEndErrorNext::Read(ReadErrorNext::ConnectionLost(
                ConnectionErrorNext::TimedOut,
            ))),
            // `Accepting` reports a mid-handshake client disappearance as a
            // `ConnectingError`, never as a bare `ConnectionError`.
            anyhow::Error::from(ConnectingErrorNext::from(ConnectionErrorNext::TimedOut)),
        ] {
            assert!(
                is_benign_connection_end(&error),
                "{error:?} was not demoted"
            );
        }

        for error in [
            anyhow::Error::from(WriteError::ConnectionLost(transport_fault())),
            anyhow::Error::from(ReadError::ConnectionLost(transport_fault())),
            anyhow::Error::from(ReadToEndError::Read(ReadError::ConnectionLost(
                transport_fault(),
            ))),
            anyhow::Error::from(WriteErrorNext::ConnectionLost(transport_fault_next())),
            anyhow::Error::from(ReadErrorNext::ConnectionLost(transport_fault_next())),
            anyhow::Error::from(ReadToEndErrorNext::Read(ReadErrorNext::ConnectionLost(
                transport_fault_next(),
            ))),
            anyhow::Error::from(ConnectingErrorNext::from(transport_fault_next())),
        ] {
            assert!(!is_benign_connection_end(&error), "{error:?} was demoted");
        }
    }

    #[tokio::test]
    async fn normal_request_completes_and_writes_its_response() -> anyhow::Result<()> {
        let pair = connected_pair().await?;
        let (mut client_send, mut client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"request").await?;
        client_send.finish()?;
        let (send_stream, mut recv_stream) = VersionedIrohConnection::Next(pair.server.clone())
            .accept_bi()
            .await?;
        assert_eq!(recv_stream.read_request().await?, b"request");

        write_iroh_api_response(
            send_stream,
            async move {
                // Give `stopped()` a deterministic chance to cancel the handler
                // if it were to resolve before the client actually abandoned it.
                tokio::task::yield_now().await;
                Ok(b"response".to_vec())
            },
            IrohApiVersion::Next,
        )
        .await?;

        let response = tokio::time::timeout(TEST_TIMEOUT, client_recv.read_to_end(100_000))
            .await
            .context("client never received the response")??;
        assert_eq!(response, b"response");
        Ok(())
    }

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

        let unknown_duration_before_cancel = duration_count(UNKNOWN_METHOD);
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
        // The cancelled request contributes nothing to the duration histogram.
        assert_eq!(
            duration_count(UNKNOWN_METHOD),
            unknown_duration_before_cancel
        );

        assert_eq!(duration_count(CORE_METHOD) - duration_before[0], 1);
        assert_eq!(duration_count(MODULE_LABEL) - duration_before[1], 1);
        // No `+ 1` for the cancelled request: it is dropped at its await point, so
        // the manual `Instant` timing never observes. A `HistogramTimer` observed on
        // drop instead, filing the time the request sat parked as served latency
        // with no matching response code.
        assert_eq!(
            duration_count(UNKNOWN_METHOD) - duration_before[2],
            hostile_methods.len() as u64
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

    /// The legacy twin of the test above. The success path needs pinning on
    /// `quinn` in its own right: were `stopped()` to resolve early there, every
    /// iroh-0.35 request would silently become a debug-logged no-op. Both
    /// halves race it, so this goes through `read_iroh_api_request` rather than
    /// reading the stream directly - the legacy tests below only pin that race
    /// in its cancelling direction.
    #[tokio::test]
    async fn legacy_transport_completes_a_normal_request_and_writes_its_response()
    -> anyhow::Result<()> {
        let pair = connected_pair_legacy().await?;
        let (mut client_send, mut client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"request").await?;
        client_send.finish()?;
        let (mut send_stream, mut recv_stream) =
            VersionedIrohConnection::Legacy(pair.server.clone())
                .accept_bi()
                .await?;
        let request =
            read_iroh_api_request(&mut send_stream, &mut recv_stream, IrohApiVersion::Legacy)
                .await?
                .context("the read race cancelled a request the client never abandoned")?;
        assert_eq!(request, b"request");

        write_iroh_api_response(
            send_stream,
            async move {
                // Give `stopped()` a deterministic chance to cancel the handler
                // if it were to resolve before the client actually abandoned it.
                tokio::task::yield_now().await;
                Ok(b"response".to_vec())
            },
            IrohApiVersion::Legacy,
        )
        .await?;

        let response = tokio::time::timeout(TEST_TIMEOUT, client_recv.read_to_end(100_000))
            .await
            .context("client never received the response")??;
        assert_eq!(response, b"response");
        Ok(())
    }

    /// The two tests above cover the read and the write in isolation.
    /// `handle_iroh_api_stream` is where they compose - the read's `stopped()`
    /// future is dropped and the write builds a fresh one - so drive that
    /// sequence once against a real client, with a real permit to release.
    #[tokio::test]
    async fn iroh_api_stream_answers_a_request_and_releases_its_permit() -> anyhow::Result<()> {
        const MAX_REQUESTS: usize = 1;

        let pair = connected_pair().await?;
        let (mut client_send, mut client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"request").await?;
        client_send.finish()?;
        let (send_stream, recv_stream) = VersionedIrohConnection::Next(pair.server.clone())
            .accept_bi()
            .await?;
        let request_limit = Arc::new(Semaphore::new(MAX_REQUESTS));
        let permit = request_limit
            .clone()
            .acquire_owned()
            .await
            .expect("test semaphore is open");

        handle_iroh_api_stream(
            send_stream,
            recv_stream,
            permit,
            IrohApiVersion::Next,
            |request| async move {
                assert_eq!(request, b"request");
                Ok(b"response".to_vec())
            },
        )
        .await?;

        let response = tokio::time::timeout(TEST_TIMEOUT, client_recv.read_to_end(100_000))
            .await
            .context("client never received the response")??;
        assert_eq!(response, b"response");
        assert_eq!(request_limit.available_permits(), MAX_REQUESTS);
        Ok(())
    }

    /// Both `stopped()` races run over `quinn` on the legacy transport instead
    /// of `noq`, so pin them there rather than only arguing the two stacks
    /// behave the same.
    #[tokio::test]
    async fn legacy_transport_cancels_requests_abandoned_while_reading_and_while_responding()
    -> anyhow::Result<()> {
        let pair = connected_pair_legacy().await?;

        // A request the client abandons before it finished uploading it.
        let (mut client_send, mut client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"partial request").await?;
        let (mut send_stream, mut recv_stream) =
            VersionedIrohConnection::Legacy(pair.server.clone())
                .accept_bi()
                .await?;
        let reading =
            fedimint_core::runtime::spawn("test-iroh-legacy-read-cancellation", async move {
                read_iroh_api_request(&mut send_stream, &mut recv_stream, IrohApiVersion::Legacy)
                    .await
            });
        client_recv.stop(VarInt::from_u32(0))?;
        let request = tokio::time::timeout(TEST_TIMEOUT, reading)
            .await
            .context("handler remained parked on the partial request after STOP_SENDING")???;
        assert!(request.is_none());

        // A request the client abandons while the server is still answering it.
        let (mut client_send, mut client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"request").await?;
        client_send.finish()?;
        let (send_stream, _recv_stream) = VersionedIrohConnection::Legacy(pair.server.clone())
            .accept_bi()
            .await?;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let responding = fedimint_core::runtime::spawn(
            "test-iroh-legacy-response-cancellation",
            write_iroh_api_response(
                send_stream,
                async move {
                    started_tx.send(()).expect("test is still waiting");
                    std::future::pending::<anyhow::Result<Vec<u8>>>().await
                },
                IrohApiVersion::Legacy,
            ),
        );
        tokio::time::timeout(TEST_TIMEOUT, started_rx).await??;

        client_recv.stop(VarInt::from_u32(0))?;
        tokio::time::timeout(TEST_TIMEOUT, responding)
            .await
            .context("handler remained parked after STOP_SENDING")???;
        assert!(pair.server.close_reason().is_none());
        Ok(())
    }

    /// The connection-close race runs over `quinn` too, and it is the arm that
    /// cancels a handler parked on something other than its own stream, so pin
    /// it on the legacy transport for the same reason as the races above.
    #[tokio::test]
    async fn legacy_transport_cancels_a_parked_handler_when_the_connection_closes()
    -> anyhow::Result<()> {
        let pair = connected_pair_legacy().await?;
        let (mut client_send, _client_recv) = pair.client.open_bi().await?;
        client_send.write_all(b"request").await?;
        client_send.finish()?;
        let (send_stream, _recv_stream) = VersionedIrohConnection::Legacy(pair.server.clone())
            .accept_bi()
            .await?;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handler = write_iroh_api_response(
            send_stream,
            async move {
                started_tx.send(()).expect("test is still waiting");
                std::future::pending::<anyhow::Result<Vec<u8>>>().await
            },
            IrohApiVersion::Legacy,
        );
        let server_connection = VersionedIrohConnection::Legacy(pair.server.clone());
        let server_task =
            fedimint_core::runtime::spawn("test-iroh-legacy-connection-cancellation", async move {
                cancel_on_connection_close(&server_connection, handler).await
            });
        tokio::time::timeout(TEST_TIMEOUT, started_rx).await??;

        pair.client.close(VarInt::from_u32(0), b"done");
        let result = tokio::time::timeout(TEST_TIMEOUT, server_task)
            .await
            .context("handler remained parked after the connection closed")??;
        assert!(result.is_none(), "handler won the connection-close race");
        Ok(())
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
}
