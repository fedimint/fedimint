use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fedimint_core::task::jit::JitTryAnyhow;
use fedimint_core::time::now;
use fedimint_core::util::{backoff_util, SafeUrl};
use fedimint_core::PeerId;
use fedimint_logging::LOG_CLIENT_NET_API;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use super::JsonRpcClient;

// TODO(tvolk131): Merge this with `FederationPeerClient`.
#[derive(Debug)]
pub struct FederationPeer<C> {
    pub url: SafeUrl,
    pub peer_id: PeerId,
    pub api_secret: Option<String>,
    pub client: RwLock<FederationPeerClient<C>>,
}

impl<C> FederationPeer<C>
where
    C: JsonRpcClient + 'static,
{
    pub fn new(url: SafeUrl, peer_id: PeerId, api_secret: Option<String>) -> Self {
        let client = RwLock::new(FederationPeerClient::new(
            peer_id,
            url.clone(),
            api_secret.clone(),
        ));

        Self {
            url,
            peer_id,
            api_secret,
            client,
        }
    }
}

/// The client in [`FederationPeer`], that takes care of reconnecting by
/// starting background Jit task
#[derive(Debug)]
pub struct FederationPeerClient<C> {
    pub client: JitTryAnyhow<C>,
    connection_state: Arc<tokio::sync::Mutex<FederationPeerClientConnectionState>>,
}

impl<C> FederationPeerClient<C>
where
    C: JsonRpcClient + 'static,
{
    fn new(peer_id: PeerId, url: SafeUrl, api_secret: Option<String>) -> Self {
        let connection_state = Arc::new(tokio::sync::Mutex::new(
            FederationPeerClientConnectionState::new(),
        ));

        Self {
            client: Self::new_jit_client(peer_id, url, api_secret, connection_state.clone()),
            connection_state,
        }
    }

    fn new_jit_client(
        peer_id: PeerId,
        url: SafeUrl,
        api_secret: Option<String>,
        connection_state: Arc<Mutex<FederationPeerClientConnectionState>>,
    ) -> JitTryAnyhow<C> {
        JitTryAnyhow::new_try(move || async move {
            Self::wait(&peer_id, &url, &connection_state).await;

            let res = C::connect(&url, api_secret).await;

            match &res {
                Ok(_) => {
                    connection_state.lock().await.reset();
                    debug!(
                            target: LOG_CLIENT_NET_API,
                            peer_id = %peer_id,
                            url = %url,
                            "Connected to peer");
                }
                Err(err) => {
                    debug!(
                            target: LOG_CLIENT_NET_API,
                            peer_id = %peer_id,
                            url = %url,
                            %err, "Unable to connect to peer");
                }
            }
            Ok(res?)
        })
    }

    pub fn reconnect(&mut self, peer_id: PeerId, url: SafeUrl, api_secret: Option<String>) {
        self.client = Self::new_jit_client(peer_id, url, api_secret, self.connection_state.clone());
    }

    async fn wait(
        peer_id: &PeerId,
        url: &SafeUrl,
        connection_state: &Arc<Mutex<FederationPeerClientConnectionState>>,
    ) {
        let mut connection_state_guard = connection_state.lock().await;

        if connection_state_guard.last_connection_attempt_or.is_none() {
            debug!(
                target: LOG_CLIENT_NET_API,
                peer_id = %peer_id,
                url = %url,
                "Connecting to peer...");
        } else {
            debug!(
                target: LOG_CLIENT_NET_API,
                peer_id = %peer_id,
                url = %url,
                "Retrying connecting to peer...");
        }

        connection_state_guard.wait().await;
    }
}

/// Connection state shared/preserved between [`FederationPeerClient`] and the
/// Jit tasks it spawns.
#[derive(Debug)]
struct FederationPeerClientConnectionState {
    /// Last time a connection attempt was made, or `None` if no attempt has
    /// been made yet.
    last_connection_attempt_or: Option<SystemTime>,
    connection_backoff: backoff_util::FibonacciBackoff,
}

impl FederationPeerClientConnectionState {
    const MIN_BACKOFF: Duration = Duration::from_millis(100);
    const MAX_BACKOFF: Duration = Duration::from_secs(15);

    fn new() -> Self {
        Self {
            last_connection_attempt_or: None,
            connection_backoff: backoff_util::custom_backoff(
                Self::MIN_BACKOFF,
                Self::MAX_BACKOFF,
                None,
            ),
        }
    }

    /// Wait (if needed) before reconnection attempt based on number of previous
    /// attempts and update reconnection stats.
    async fn wait(&mut self) {
        let now_ts = now();
        let desired_timeout = self.connection_backoff.next().unwrap_or(Self::MAX_BACKOFF);
        let since_last_connect = match self.last_connection_attempt_or {
            Some(last) => now_ts.duration_since(last).unwrap_or_default(),
            None => Duration::ZERO,
        };

        let sleep_duration = desired_timeout.saturating_sub(since_last_connect);
        if Duration::ZERO < sleep_duration {
            debug!(
                target: LOG_CLIENT_NET_API,
                duration_ms=sleep_duration.as_millis(),
                "Waiting before reconnecting");
            fedimint_core::runtime::sleep(sleep_duration).await;
        }

        self.last_connection_attempt_or = Some(now_ts);
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}
