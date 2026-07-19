use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::envs::{
    FM_GW_IROH_CONNECT_OVERRIDES_PLAIN_ENV, FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV,
    FM_IROH_N0_DISCOVERY_ENABLE_ENV, FM_IROH_PKARR_RESOLVER_ENABLE_ENV, is_env_var_set_opt,
    parse_kv_list_from_env,
};
use fedimint_core::module::{
    ApiError, ApiMethod, ApiRequestErased, FEDIMINT_API_ALPN, FEDIMINT_GATEWAY_ALPN,
    IrohApiRequest, IrohGatewayRequest, IrohGatewayResponse,
};
use fedimint_core::net::iroh::{IROH_IDLE_TIMEOUT, IROH_KEEP_ALIVE_INTERVAL};

/// The maximum number of bytes we are willing to buffer when reading an API
/// response from an iroh QUIC stream. This must be large enough to accommodate
/// the largest possible signed session outcome. A session can contain up to
/// `broadcast_rounds_per_session` (default 3600) rounds, each peer produces one
/// unit per round, and each unit can be up to `ALEPH_BFT_UNIT_BYTE_LIMIT`
/// bytes. The response is JSON-serialized which hex-encodes the consensus
/// bytes, roughly doubling the size. We use 2x the raw max as a conservative
/// upper bound. For a 4-peer federation this is ~1.44 GB.
const IROH_MAX_RESPONSE_BYTES: usize = ALEPH_BFT_UNIT_BYTE_LIMIT * 3600 * 4 * 2;

/// Wall-clock budget for a single iroh API request to make it through the QUIC
/// bi-stream (open + write + finish + read response). If exceeded we close the
/// underlying [`Connection`], which causes [`IConnection::is_connected`] to
/// return false on the next pool lookup so a fresh connection is established
/// for the retry. Used for endpoints that respond promptly (`block_count`,
/// `status`, etc).
const IROH_REQUEST_TIMEOUT_DEFAULT: Duration = Duration::from_secs(60);

/// Wall-clock budget for an iroh API request to a server-side long-poll
/// endpoint (`await_*` / `wait_*`). These wait on the server until an event
/// fires (block height reached, contract cancelled, etc.) before responding,
/// so they need a generous bound. Set well above realistic mainnet block
/// intervals; if a long-poll legitimately needs longer than this the upstream
/// `request_current_consensus_retry` loop will reconnect and retry.
const IROH_REQUEST_TIMEOUT_LONG_POLL: Duration = Duration::from_secs(60 * 60);

/// Shorter long-poll budget for the retry-safe lnv2 payment waits
/// (`await_incoming_contract`, `await_incoming_contracts` and
/// `decryption_key_share` on the receive path, `await_preimage` on the send
/// path).
///
/// These block server-side until their event fires: `await_incoming_contracts`
/// parks indefinitely on `wait_key_check`, `decryption_key_share` parks on
/// `wait_key_exists` until the funding output is accepted, and
/// `await_incoming_contract` and `await_preimage` poll until their contract
/// expires — a wall-clock expiry for an incoming contract, a consensus block
/// height for an outgoing one, and for an lnurl receive no real bound at all
/// (its `expiration_or_fee` is fee-encoded near `u64::MAX`).
///
/// Either way the client's budget is effectively the bound on how long a
/// *stalled* connection is kept before it is closed and the retry loop
/// reconnects — a degraded path cannot deliver the expiration response any
/// more than it can deliver a settlement. A degraded-but-not-dead
/// QUIC path (keep-alives still pass, so the 60s idle timeout never fires, but
/// request data no longer flows) otherwise pins the client for the full hour of
/// [`IROH_REQUEST_TIMEOUT_LONG_POLL`] before it can recover — long enough to
/// look like a stuck receive/send to a 24/7 client that mostly waits on these
/// endpoints.
///
/// A 5-minute budget caps that degraded-path outage at ~5 min (plus the
/// api-client retry backoff ceiling), while a *healthy* idle subscription only
/// reconnects ~12×/hour. This tier is deliberately NOT applied to the
/// consensus long-polls (`await_transaction`, `await_block_height`,
/// `await_signed_session_outcome`, …): those keep the 1-hour bound so their
/// healthy idle waits do not churn connections. Re-issuing these waits is
/// safe — they are pure server-side reads, `await_incoming_contracts` is driven
/// by the monotonic `IncomingContractStreamIndexKey` cursor (the client
/// persists `next_index` only after processing a batch, so a retry replays but
/// never skips), and a replayed incoming contract dedups on its stable
/// operation id.
const IROH_REQUEST_TIMEOUT_LNV2_WAIT: Duration = Duration::from_secs(5 * 60);

/// The retry-safe lnv2 payment-wait endpoints that take the shorter
/// [`IROH_REQUEST_TIMEOUT_LNV2_WAIT`] budget. Matched by exact name (not a
/// prefix) so the shorter budget can never silently widen to an unrelated
/// `await_*` method.
///
/// `decryption_key_share` is here despite not carrying an `await_`/`wait_`
/// prefix: it long-polls on `wait_key_exists` exactly like the others (its own
/// server-side comment says it "mirrors the AWAIT_INCOMING_CONTRACT and
/// AWAIT_PREIMAGE endpoints"), and the gateway deliberately issues it *before*
/// the funding output is accepted so the two overlap. It is therefore expected
/// to block past the 60s prompt default, which without this entry closes the
/// shared pooled connection once a minute for the whole wait.
const IROH_LNV2_WAIT_METHODS: &[&str] = &[
    "await_incoming_contract",
    "await_incoming_contracts",
    "await_preimage",
    "decryption_key_share",
];

/// Application-level QUIC error code we use when closing a [`Connection`]
/// after a request timeout. Recorded by the peer as the close reason; chosen
/// arbitrarily but stable across stable and `iroh_next` impls so the two
/// emit identical telemetry. The value 1 distinguishes us from a graceful
/// close (0).
const IROH_REQUEST_TIMEOUT_ERROR_CODE: u32 = 1;
const IROH_REQUEST_TIMEOUT_ERROR_REASON: &[u8] = b"request timeout";

/// Request timeout strategy: long-poll endpoints (`await_*` / `wait_*`)
/// get the long bound, everything else gets the default. The string match
/// is a heuristic; it covers all currently-defined fedimint long-poll
/// endpoints and stays correct if new ones follow the existing naming
/// convention. False positives (a non-long-poll endpoint that happens to
/// match the prefix) just give that one method a longer leash; the worse
/// case is a false negative — a long-poll method that doesn't match
/// either prefix would get the 60s default and fail fast on legitimate
/// waits, but the upstream retry loop would reconnect and try again.
fn request_timeout_for_method(method: &ApiMethod) -> Duration {
    let name = match method {
        ApiMethod::Core(name) => name.as_str(),
        ApiMethod::Module(_, name) => name.as_str(),
    };
    // Exact-name overrides come FIRST so the shorter budget is scoped to
    // exactly the intended endpoints, then the generic prefix heuristic.
    if IROH_LNV2_WAIT_METHODS.contains(&name) {
        IROH_REQUEST_TIMEOUT_LNV2_WAIT
    } else if name.starts_with("await_") || name.starts_with("wait_") {
        IROH_REQUEST_TIMEOUT_LONG_POLL
    } else {
        IROH_REQUEST_TIMEOUT_DEFAULT
    }
}

/// Width of the window over which routine lnv2 wait expiries are spread. See
/// [`request_timeout_for_method_spread`].
const IROH_LNV2_WAIT_SPREAD: Duration = Duration::from_secs(60);

/// Number of distinct millisecond slots in [`IROH_LNV2_WAIT_SPREAD`].
const IROH_LNV2_WAIT_SPREAD_SLOTS: u64 = IROH_LNV2_WAIT_SPREAD.as_secs() * 1_000;

/// Map a remote's node id to a stable spread offset in
/// `0..IROH_LNV2_WAIT_SPREAD`.
///
/// The offset has to satisfy two constraints that rule out the more obvious
/// sources:
///
/// - It must not depend on the ORDER waits are issued in. An issue-order
///   counter looks like it staggers them, but the order peers re-issue in is
///   itself the order they last expired in, so a per-rank offset step cancels
///   against the per-rank expiry stagger and the fleet re-synchronizes.
/// - It must not depend on the resolution of a platform facility. A sub-second
///   wall-clock reading is nanosecond-grained only on some targets:
///   [`fedimint_core::time::now`] is built from `js_sys::Date` on wasm
///   (millisecond-quantised, coarser under fingerprinting resistance) and from
///   `FILETIME` on Windows (100ns ticks, so `nanos % 60` cycles just three
///   values). A fan-out issued inside one tick then reads one value and every
///   peer draws the same offset — inert in exactly the case it exists for.
///
/// A node id has neither problem: it is a public key, so it is uniformly
/// distributed and stable; it is known before the request is sent; and it is
/// the same value on every platform. Each peer keeps a fixed slot in the
/// window, and because the slot is a pure function of that id there is no
/// feedback path from expiry order back into the offset — which is what made
/// the counter re-synchronize.
///
/// This bounds clustering rather than eliminating it. Distinct offsets give
/// distinct cycle periods (`300s - offset`), so peers that were re-issued
/// together immediately fan out; but two periods still share a finite common
/// multiple, so a pair does re-coincide eventually. With millisecond slots that
/// is usually far out — random distinct pairs are typically months to years
/// apart — while a specially aligned low-`lcm` pair (say 300.0s and 280.0s,
/// meeting every 70min) can meet much sooner. Either way it is a transient
/// one-cycle coincidence, not the sustained every-cycle lock the order-derived
/// offset produced.
///
/// Slots are millisecond- rather than second-grained only to make exact
/// collisions negligible: a 4-peer federation collides with p≈1e-4 over 60_000
/// slots versus p≈0.1 over 60. Two peers that did collide share a period and so
/// expire together indefinitely — i.e. exactly as they do with no spread at
/// all, never worse.
fn spread_offset_for_peer(node_id: &[u8; 32]) -> Duration {
    // Fold the whole id through the splitmix64 finalizer rather than taking
    // leading bytes directly. A public key should already be uniform, but that
    // is an assumption about the key format; mixing avalanches every input bit
    // so ids sharing a prefix still land far apart, and the spread stops
    // depending on which bytes of the key happen to be well distributed.
    fn mix(mut z: u64) -> u64 {
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    let slot = node_id
        .chunks_exact(8)
        .map(|word| u64::from_be_bytes(word.try_into().expect("chunks_exact(8) yields 8 bytes")))
        .fold(0u64, |acc, word| mix(acc ^ word));
    Duration::from_millis(slot % IROH_LNV2_WAIT_SPREAD_SLOTS)
}

/// [`request_timeout_for_method`], with the routine expiry of the short lnv2
/// tier spread over [`IROH_LNV2_WAIT_SPREAD`].
///
/// A client waiting on several peers issues one wait per peer at the same
/// moment, so without this their budgets expire together and every pooled
/// per-peer connection closes on the same tick. Those connections are shared
/// with unrelated one-shot calls, and not every caller retries (lnv2
/// `gateways()` uses `request_with_strategy`, not the retrying variant), so a
/// synchronized close can surface a transient failure on a perfectly healthy
/// network. Staggering the budgets keeps the closes from clustering.
///
/// Only the short tier is spread: the 1-hour tier expires rarely enough that
/// clustering is not a concern, and the prompt tier must keep its exact bound.
///
/// `node_id` is the remote this request is bound for. `None` (the peer identity
/// was not available) skips the spread and keeps the exact tier bound, which is
/// the pre-spread behaviour. That should be unreachable — a pooled connection
/// has completed a handshake that pins the dialed key — but it would disable
/// the spread fleet-wide, so it is logged rather than silent.
fn request_timeout_for_method_spread(method: &ApiMethod, node_id: Option<&[u8; 32]>) -> Duration {
    let timeout = request_timeout_for_method(method);
    if timeout != IROH_REQUEST_TIMEOUT_LNV2_WAIT {
        return timeout;
    }
    let Some(node_id) = node_id else {
        debug!(
            target: LOG_NET_IROH,
            "No peer identity for an lnv2 wait, using the unspread tier bound"
        );
        return timeout;
    };
    timeout.saturating_sub(spread_offset_for_peer(node_id))
}

/// Log a request-timeout-triggered connection close, shared by the stable and
/// `iroh_next` request paths. A long-poll (budget above the prompt default)
/// reaching its budget with no data is expected steady state, so it logs at
/// `debug`; a prompt request exceeding the 60s default is unusual and warns.
fn log_request_timeout(method_str: &str, timeout: Duration) {
    // Three tiers, three levels. The short lnv2 tier expires every cycle on a
    // perfectly healthy idle subscription, so it is pure noise at anything
    // above `debug`. The 1-hour tier is different: an hour of a consensus
    // long-poll producing nothing is the very degraded-path symptom this
    // budget exists to bound, so it stays visible at default log levels. A
    // prompt request exceeding the 60s default is genuinely unusual.
    if timeout <= IROH_REQUEST_TIMEOUT_DEFAULT {
        warn!(
            target: LOG_NET_IROH,
            method = %method_str,
            timeout_secs = timeout.as_secs(),
            "iroh request timed out, retiring connection",
        );
    } else if timeout <= IROH_REQUEST_TIMEOUT_LNV2_WAIT {
        debug!(
            target: LOG_NET_IROH,
            method = %method_str,
            timeout_secs = timeout.as_secs(),
            "iroh payment-wait reached its budget, retiring connection to reconnect",
        );
    } else {
        info!(
            target: LOG_NET_IROH,
            method = %method_str,
            timeout_secs = timeout.as_secs(),
            "iroh long-poll reached its budget with no data, retiring connection to reconnect",
        );
    }
}
use fedimint_core::task::spawn;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_NET_IROH;
use futures::Future;
use futures::stream::{FuturesUnordered, StreamExt};
use iroh::discovery::pkarr::PkarrResolver;
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId, PublicKey};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, trace, warn};

use super::{DynGuaridianConnection, IGuardianConnection, ServerError, ServerResult};
use crate::{Connectivity, DynGatewayConnection, IConnection, IGatewayConnection, IrohPeerInfo};

#[derive(Clone)]
pub(crate) struct IrohConnector {
    stable: iroh::endpoint::Endpoint,
    next: iroh_next::endpoint::Endpoint,

    /// List of overrides to use when attempting to connect to given
    /// `NodeId`
    ///
    /// This is useful for testing, or forcing non-default network
    /// connectivity.
    connection_overrides: BTreeMap<NodeId, NodeAddr>,

    /// Registry-owned signal bumped whenever any per-connection monitoring
    /// task observes a transport-level path change (e.g. iroh relay →
    /// direct). Consumers of [`crate::ConnectorRegistry`] subscribe via
    /// [`crate::ConnectorRegistry::connectivity_change_notifier`].
    path_change: Arc<watch::Sender<u64>>,
}

impl fmt::Debug for IrohConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohEndpoint")
            .field("stable-id", &self.stable.node_id())
            .field("next-id", &self.next.id())
            .finish_non_exhaustive()
    }
}

impl IrohConnector {
    pub async fn new(
        iroh_dns: Option<SafeUrl>,
        iroh_enable_dht: bool,
        path_change: Arc<watch::Sender<u64>>,
    ) -> anyhow::Result<Self> {
        let mut s = Self::new_no_overrides(iroh_dns, iroh_enable_dht, path_change).await?;

        // Overrides are `<node-id>=<socket-addr>` pairs: the node id is the key
        // and the value is a single direct address. iroh 1.0 no longer ships
        // the `NodeTicket` format, so we keep the override wire format version
        // agnostic and build the (legacy) `NodeAddr` from its parts. Pre-0.12
        // binaries read the `NodeTicket`-format `FM_IROH_CONNECT_OVERRIDES`
        // instead; devimint emits both side by side.
        for env_var in [
            FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV,
            FM_GW_IROH_CONNECT_OVERRIDES_PLAIN_ENV,
        ] {
            for (k, v) in parse_kv_list_from_env::<NodeId, SocketAddr>(env_var)? {
                s = s.with_connection_override(k, NodeAddr::new(k).with_direct_addresses([v]));
            }
        }

        Ok(s)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn new_no_overrides(
        iroh_dns: Option<SafeUrl>,
        iroh_enable_dht: bool,
        path_change: Arc<watch::Sender<u64>>,
    ) -> anyhow::Result<Self> {
        let endpoint_stable = Box::pin({
            let iroh_dns = iroh_dns.clone();
            async {
                let mut builder = Endpoint::builder();

                if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
                    builder = builder.add_discovery(|_| Some(PkarrResolver::new(iroh_dns)));
                }

                // As a client, we don't need to register on any relays
                let mut builder = builder.relay_mode(iroh::RelayMode::Disabled);

                #[cfg(not(target_family = "wasm"))]
                if iroh_enable_dht {
                    builder = builder.discovery_dht();
                }

                // Add only resolver services here; the stable n0 convenience also
                // installs a publisher.
                {
                    if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
                        builder = builder.add_discovery(move |_| Some(PkarrResolver::n0_dns()));
                    } else {
                        warn!(
                            target: LOG_NET_IROH,
                            "Iroh pkarr resolver is disabled"
                        );
                    }

                    if is_env_var_set_opt(FM_IROH_N0_DISCOVERY_ENABLE_ENV).unwrap_or(true) {
                        #[cfg(not(target_family = "wasm"))]
                        {
                            builder = builder.add_discovery(move |_| {
                                Some(iroh::discovery::dns::DnsDiscovery::n0_dns())
                            });
                        }
                    } else {
                        warn!(
                            target: LOG_NET_IROH,
                            "Iroh n0 discovery is disabled"
                        );
                    }
                }

                let endpoint = builder
                    .transport_config(quic_transport_config())
                    .bind()
                    .await?;
                debug!(
                    target: LOG_NET_IROH,
                    node_id = %endpoint.node_id(),
                    node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
                    "Iroh api client endpoint (stable)"
                );
                Ok::<_, anyhow::Error>(endpoint)
            }
        });
        let endpoint_next = Box::pin(async {
            let mut builder = iroh_next::Endpoint::builder(iroh_next::endpoint::presets::Minimal);

            if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
                builder = builder
                    .address_lookup(iroh_next::address_lookup::PkarrResolver::builder(iroh_dns));
            }

            // As a client, we don't need to register on any relays
            let mut builder = builder.relay_mode(iroh_next::RelayMode::Disabled);

            #[cfg(not(target_family = "wasm"))]
            if iroh_enable_dht {
                builder = builder
                    .address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
            }

            // Add only resolver services here; the iroh preset convenience also
            // installs a publisher.
            {
                // Resolve using HTTPS requests to our DNS server's /pkarr path.
                builder =
                    builder.address_lookup(iroh_next::address_lookup::PkarrResolver::n0_dns());
                // Resolve using DNS queries outside browsers.
                #[cfg(not(target_family = "wasm"))]
                {
                    builder = builder
                        .address_lookup(iroh_next::address_lookup::DnsAddressLookup::n0_dns());
                }
            }

            let endpoint = builder
                .transport_config(quic_transport_config_next())
                .bind()
                .await?;
            debug!(
                target: LOG_NET_IROH,
                node_id = %endpoint.id(),
                node_id_pkarr = %z32::encode(endpoint.id().as_bytes()),
                "Iroh api client endpoint (next)"
            );
            Ok(endpoint)
        });

        let (endpoint_stable, endpoint_next) = tokio::try_join!(endpoint_stable, endpoint_next)?;

        Ok(Self {
            stable: endpoint_stable,
            next: endpoint_next,
            connection_overrides: BTreeMap::new(),
            path_change,
        })
    }

    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
    }

    pub fn node_id_from_url(url: &SafeUrl) -> anyhow::Result<NodeId> {
        if url.scheme() != "iroh" {
            bail!(
                "Unsupported scheme: {}, passed to iroh endpoint handler",
                url.scheme()
            );
        }
        let host = url.host_str().context("Missing host string in Iroh URL")?;

        let node_id = PublicKey::from_str(host).context("Failed to parse node id")?;

        Ok(node_id)
    }
}

#[async_trait::async_trait]
impl crate::Connector for IrohConnector {
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> ServerResult<DynGuaridianConnection> {
        if api_secret.is_some() {
            // There seem to be no way to pass secret over current Iroh calling
            // convention
            ServerError::Connection(anyhow::format_err!(
                "Iroh api secrets currently not supported"
            ));
        }
        let node_id =
            Self::node_id_from_url(url).map_err(|source| ServerError::InvalidPeerUrl {
                source,
                url: url.to_owned(),
            })?;
        let mut futures = FuturesUnordered::<
            Pin<
                Box<
                    dyn Future<Output = (ServerResult<DynGuaridianConnection>, &'static str)>
                        + Send,
                >,
            >,
        >::new();
        let connection_override = self.connection_overrides.get(&node_id).cloned();

        let self_clone = self.clone();
        futures.push(Box::pin({
            let connection_override = connection_override.clone();
            async move {
                (
                    self_clone
                        .make_new_connection_stable(node_id, connection_override)
                        .await
                        .map(PooledGuardianConnection::new)
                        .map(super::IGuardianConnection::into_dyn),
                    "stable",
                )
            }
        }));

        let self_clone = self.clone();
        let endpoint_next = self.next.clone();
        futures.push(Box::pin(async move {
            (
                self_clone
                    .make_new_connection_next(&endpoint_next, node_id, connection_override)
                    .await
                    .map(PooledGuardianConnection::new)
                    .map(super::IGuardianConnection::into_dyn),
                "next",
            )
        }));

        // Remember last error, so we have something to return if
        // neither connection works.
        let mut prev_err = None;

        // Loop until first success, or running out of connections.
        while let Some((result, iroh_stack)) = futures.next().await {
            match result {
                Ok(connection) => return Ok(connection),
                Err(err) => {
                    warn!(
                        target: LOG_NET_IROH,
                        err = %err.fmt_compact(),
                        %iroh_stack,
                        "Join error in iroh connection task"
                    );
                    prev_err = Some(err);
                }
            }
        }

        Err(prev_err.unwrap_or_else(|| {
            ServerError::ServerError(anyhow::anyhow!("Both iroh connection attempts failed"))
        }))
    }

    async fn connect_gateway(&self, url: &SafeUrl) -> anyhow::Result<DynGatewayConnection> {
        let node_id = Self::node_id_from_url(url)?;
        if let Some(node_addr) = self.connection_overrides.get(&node_id).cloned() {
            let conn = self
                .stable
                .connect(node_addr.clone(), FEDIMINT_GATEWAY_ALPN)
                .await?;

            #[cfg(not(target_family = "wasm"))]
            Self::spawn_connection_monitoring_stable(
                &self.stable,
                node_id,
                self.path_change.clone(),
            );

            Ok(IGatewayConnection::into_dyn(conn))
        } else {
            let conn = self.stable.connect(node_id, FEDIMINT_GATEWAY_ALPN).await?;
            Ok(IGatewayConnection::into_dyn(conn))
        }
    }

    fn connectivity(&self, url: &SafeUrl) -> Connectivity {
        let Ok(node_id) = Self::node_id_from_url(url) else {
            return Connectivity::Unknown;
        };
        let Ok(watcher) = self.stable.conn_type(node_id) else {
            return Connectivity::Unknown;
        };
        match watcher.get() {
            Ok(iroh::endpoint::ConnectionType::Direct(_)) => Connectivity::Direct,
            Ok(iroh::endpoint::ConnectionType::Relay(_)) => Connectivity::Relay,
            Ok(iroh::endpoint::ConnectionType::Mixed(..)) => Connectivity::Mixed,
            Ok(iroh::endpoint::ConnectionType::None) | Err(_) => Connectivity::Unknown,
        }
    }

    async fn iroh_peer_info(
        &self,
        url: &SafeUrl,
        path_timeout: Duration,
    ) -> ServerResult<Option<IrohPeerInfo>> {
        let node_id =
            Self::node_id_from_url(url).map_err(|source| ServerError::InvalidPeerUrl {
                source,
                url: url.to_owned(),
            })?;
        let connection_override = self.connection_overrides.get(&node_id).cloned();
        let _connection = self
            .make_new_connection_stable(node_id, connection_override)
            .await?;

        let mut conn_type_watcher = self
            .stable
            .conn_type(node_id)
            .map_err(ServerError::Connection)?;
        let mut conn_type = conn_type_watcher
            .get()
            .unwrap_or(iroh::endpoint::ConnectionType::None);

        if path_timeout > Duration::ZERO {
            let timeout = fedimint_core::runtime::sleep(path_timeout);
            tokio::pin!(timeout);

            while !matches!(
                conn_type,
                iroh::endpoint::ConnectionType::Direct(_)
                    | iroh::endpoint::ConnectionType::Mixed(..)
            ) {
                tokio::select! {
                    () = &mut timeout => break,
                    updated = conn_type_watcher.updated() => {
                        match updated {
                            Ok(updated) => conn_type = updated,
                            Err(_) => break,
                        }
                    }
                }
            }
        }

        Ok(Some(self.iroh_peer_info_from_conn_type(node_id, conn_type)))
    }
}

impl IrohConnector {
    fn iroh_peer_info_from_conn_type(
        &self,
        node_id: NodeId,
        conn_type: iroh::endpoint::ConnectionType,
    ) -> IrohPeerInfo {
        let remote_info = self.stable.remote_info(node_id);

        let direct_addr = match &conn_type {
            iroh::endpoint::ConnectionType::Direct(addr)
            | iroh::endpoint::ConnectionType::Mixed(addr, _) => Some(*addr),
            iroh::endpoint::ConnectionType::Relay(_) | iroh::endpoint::ConnectionType::None => None,
        };

        let mut known_direct_addrs = remote_info
            .as_ref()
            .map(|info| {
                info.addrs
                    .iter()
                    .map(|addr_info| addr_info.addr)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        if let Some(direct_addr) = direct_addr {
            known_direct_addrs.insert(direct_addr);
        }

        let relay_url = match &conn_type {
            iroh::endpoint::ConnectionType::Relay(relay_url)
            | iroh::endpoint::ConnectionType::Mixed(_, relay_url) => Some(relay_url.to_string()),
            iroh::endpoint::ConnectionType::Direct(_) | iroh::endpoint::ConnectionType::None => {
                remote_info.and_then(|info| info.relay_url.map(|relay| relay.relay_url.to_string()))
            }
        };

        IrohPeerInfo {
            node_id: node_id.to_string(),
            connectivity: connectivity_from_iroh_conn_type(&conn_type),
            direct_addr,
            known_direct_addrs: known_direct_addrs.into_iter().collect(),
            relay_url,
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn spawn_connection_monitoring_stable(
        endpoint: &Endpoint,
        node_id: NodeId,
        path_change: Arc<watch::Sender<u64>>,
    ) {
        if let Ok(mut conn_type_watcher) = endpoint.conn_type(node_id) {
            #[allow(clippy::let_underscore_future)]
            let _ = spawn("iroh connection (stable)", async move {
                if let Ok(conn_type) = conn_type_watcher.get() {
                    debug!(target: LOG_NET_IROH, %node_id, type = %conn_type, "Connection type (initial)");
                }
                while let Ok(event) = conn_type_watcher.updated().await {
                    debug!(target: LOG_NET_IROH, %node_id, type = %event, "Connection type (changed)");
                    path_change.send_modify(|c| *c = c.wrapping_add(1));
                }
            });
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn spawn_connection_monitoring_next(
        conn: &iroh_next::endpoint::Connection,
        node_id: iroh_next::EndpointId,
        path_change: Arc<watch::Sender<u64>>,
    ) {
        let conn = conn.clone();
        #[allow(clippy::let_underscore_future)]
        let _ = spawn("iroh connection (next)", async move {
            let mut paths = conn.paths_stream();
            if let Some(paths) = paths.next().await {
                debug!(target: LOG_NET_IROH, %node_id, ?paths, "Connection paths (initial)");
            }
            while let Some(paths) = paths.next().await {
                debug!(target: LOG_NET_IROH, %node_id, ?paths, "Connection paths changed");
                path_change.send_modify(|c| *c = c.wrapping_add(1));
            }
        });
    }

    async fn make_new_connection_stable(
        &self,
        node_id: NodeId,
        node_addr: Option<NodeAddr>,
    ) -> ServerResult<Connection> {
        trace!(target: LOG_NET_IROH, %node_id, "Creating new stable connection");
        let conn = match node_addr.clone() {
            Some(node_addr) => {
                trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                let conn = self.stable
                    .connect(node_addr.clone(), FEDIMINT_API_ALPN)
                    .await;

                #[cfg(not(target_family = "wasm"))]
                if conn.is_ok() {
                    Self::spawn_connection_monitoring_stable(
                        &self.stable,
                        node_id,
                        self.path_change.clone(),
                    );
                }
                conn
            }
            None => self.stable.connect(node_id, FEDIMINT_API_ALPN).await,
        }.map_err(ServerError::Connection)?;

        Ok(conn)
    }

    async fn make_new_connection_next(
        &self,
        endpoint_next: &iroh_next::Endpoint,
        node_id: NodeId,
        node_addr: Option<NodeAddr>,
    ) -> ServerResult<iroh_next::endpoint::Connection> {
        let next_node_id =
            iroh_next::EndpointId::from_bytes(node_id.as_bytes()).expect("Can't fail");

        let endpoint_next = endpoint_next.clone();

        trace!(target: LOG_NET_IROH, %node_id, "Creating new next connection");
        let conn = match node_addr.clone() {
            Some(node_addr) => {
                trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                let node_addr = node_addr_stable_to_next(&node_addr);
                let conn = endpoint_next
                    .connect(node_addr.clone(), FEDIMINT_API_ALPN)
                    .await;

                #[cfg(not(target_family = "wasm"))]
                if let Ok(conn) = &conn {
                    Self::spawn_connection_monitoring_next(
                        conn,
                        node_addr.id,
                        self.path_change.clone(),
                    );
                }

                conn
            }
            None => endpoint_next.connect(
                next_node_id,
                FEDIMINT_API_ALPN
            ).await,
        }
        .map_err(Into::into)
        .map_err(ServerError::Connection)?;

        Ok(conn)
    }
}

/// QUIC transport config with explicit idle timeout and keep-alive
/// for the stable iroh endpoint.
fn quic_transport_config() -> iroh::endpoint::TransportConfig {
    let mut config = iroh::endpoint::TransportConfig::default();
    config.max_idle_timeout(Some(
        IROH_IDLE_TIMEOUT
            .try_into()
            .expect("idle timeout fits in IdleTimeout"),
    ));
    config.keep_alive_interval(Some(IROH_KEEP_ALIVE_INTERVAL));
    config
}

/// QUIC transport config with explicit idle timeout and keep-alive
/// for the next iroh endpoint.
fn quic_transport_config_next() -> iroh_next::endpoint::QuicTransportConfig {
    iroh_next::endpoint::QuicTransportConfig::builder()
        .max_idle_timeout(Some(
            IROH_IDLE_TIMEOUT
                .try_into()
                .expect("idle timeout fits in IdleTimeout"),
        ))
        .keep_alive_interval(IROH_KEEP_ALIVE_INTERVAL)
        .build()
}

fn connectivity_from_iroh_conn_type(conn_type: &iroh::endpoint::ConnectionType) -> Connectivity {
    match conn_type {
        iroh::endpoint::ConnectionType::Direct(_) => Connectivity::Direct,
        iroh::endpoint::ConnectionType::Relay(_) => Connectivity::Relay,
        iroh::endpoint::ConnectionType::Mixed(..) => Connectivity::Mixed,
        iroh::endpoint::ConnectionType::None => Connectivity::Unknown,
    }
}

fn node_addr_stable_to_next(stable: &iroh::NodeAddr) -> iroh_next::EndpointAddr {
    let next_node_id =
        iroh_next::EndpointId::from_bytes(stable.node_id.as_bytes()).expect("Can't fail");
    let relay_addrs = stable.relay_url.iter().map(|u| {
        iroh_next::TransportAddr::Relay(
            iroh_next::RelayUrl::from_str(&u.to_string()).expect("Can't fail"),
        )
    });
    let direct_addrs = stable
        .direct_addresses
        .iter()
        .copied()
        .map(iroh_next::TransportAddr::Ip);

    iroh_next::EndpointAddr::from_parts(next_node_id, relay_addrs.chain(direct_addrs))
}

/// The per-iroh-version pieces [`PooledGuardianConnection`] needs.
///
/// The stable and `iroh_next` connection types have the same shape but distinct
/// concrete stream and error types, so this captures only the operations that
/// differ and lets the pooled wrapper be written once for both.
#[async_trait]
trait IrohGuardianConn: fmt::Debug + Send + Sync + 'static {
    /// The remote's 32-byte public key, if the handshake exposed one.
    fn remote_id_bytes(&self) -> Option<[u8; 32]>;

    /// Whether the underlying QUIC connection is still open.
    fn is_open(&self) -> bool;

    /// Close the underlying QUIC connection, recording our timeout as the
    /// reason.
    fn close_timed_out(&self);

    /// Resolves once the underlying QUIC connection is closed.
    async fn wait_closed(&self);

    /// One request/response round trip on a fresh bi-stream.
    async fn round_trip(&self, json: &[u8]) -> ServerResult<Vec<u8>>;
}

/// A pooled guardian connection that can be *retired* without being closed.
///
/// The pool drops an entry once [`IConnection::is_connected`] returns false,
/// and on a bare iroh connection the only way to make that happen is to close
/// it — which also aborts every other request in flight on that connection.
/// Requests sharing a pooled connection are unrelated to one another, and not
/// all of their callers retry (lnv2 `gateways()` uses `request_with_strategy`,
/// not the retrying variant), so a routine long-poll refresh could fail a
/// healthy one-shot call that merely overlapped it. A multi-guardian client
/// absorbs that — losing one peer still leaves a threshold — but a
/// single-guardian federation has no second peer to absorb anything, so the
/// call just fails.
///
/// Retiring separates eviction from teardown: the entry stops being handed out
/// for NEW requests, while requests already in flight run to completion on it.
/// The connection is closed as soon as the last of them finishes, so it does
/// not linger and the server-side cancellation still fires promptly.
#[derive(Debug)]
struct PooledGuardianConnection<C> {
    conn: C,
    /// Set once this connection should stop serving new requests. A watch (not
    /// a plain flag) so [`IConnection::await_disconnection`] can wake on it.
    retired: watch::Sender<bool>,
    /// Requests currently in flight on `conn`.
    in_flight: AtomicUsize,
}

/// Decrements the in-flight count on drop, closing the connection when the last
/// request leaves a retired one.
struct InFlightGuard<'a, C: IrohGuardianConn>(&'a PooledGuardianConnection<C>);

impl<C: IrohGuardianConn> Drop for InFlightGuard<'_, C> {
    fn drop(&mut self) {
        // `fetch_sub` returns the PREVIOUS value, so exactly one dropping guard
        // observes 1 and is therefore the last one out.
        if self.0.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 && *self.0.retired.borrow() {
            self.0.conn.close_timed_out();
        }
    }
}

impl<C: IrohGuardianConn> PooledGuardianConnection<C> {
    fn new(conn: C) -> Self {
        Self {
            conn,
            retired: watch::Sender::new(false),
            in_flight: AtomicUsize::new(0),
        }
    }

    fn enter(&self) -> InFlightGuard<'_, C> {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        InFlightGuard(self)
    }

    /// Stop serving new requests.
    ///
    /// In practice the caller holds an [`InFlightGuard`], so the close happens
    /// when that guard (or a later one) drops. The `in_flight == 0` branch is
    /// defensive: without it a retire with nothing in flight would leave the
    /// connection open until the pool entry was dropped.
    ///
    /// At least one of the two paths always closes, and the reason is subtler
    /// than it looks. The interleaving to worry about is a last guard reading
    /// `retired == false` while this reads `in_flight == 1`, so neither closes
    /// and the connection leaks open. It cannot happen because
    /// [`watch::Sender`] is `RwLock`-backed: `borrow` takes the read lock and
    /// `send_replace` the write lock, so the two are ordered against each
    /// other. If the guard's `borrow` reads `false` it precedes this
    /// `send_replace`, so its `fetch_sub` also precedes the `load` below, which
    /// therefore reads 0 and closes here.
    ///
    /// That means the flag may NOT be weakened to a plain `AtomicBool` with
    /// these orderings — without the lock, the store-buffer interleaving is
    /// real and would need `SeqCst`. Closing twice (guard drops between the
    /// `send_replace` and the `load`) is possible and harmless; `close` is
    /// idempotent on both iroh stacks.
    fn retire(&self) {
        self.retired.send_replace(true);
        if self.in_flight.load(Ordering::Acquire) == 0 {
            self.conn.close_timed_out();
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl<C: IrohGuardianConn> IConnection for PooledGuardianConnection<C> {
    async fn await_disconnection(&self) {
        let closed = std::pin::pin!(self.conn.wait_closed());
        let retired = std::pin::pin!(async {
            let mut rx = self.retired.subscribe();
            let _ = rx.wait_for(|retired| *retired).await;
        });
        futures::future::select(closed, retired).await;
    }

    fn is_connected(&self) -> bool {
        !*self.retired.borrow() && self.conn.is_open()
    }
}

#[async_trait]
impl<C: IrohGuardianConn> IGuardianConnection for PooledGuardianConnection<C> {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> ServerResult<Value> {
        let timeout =
            request_timeout_for_method_spread(&method, self.conn.remote_id_bytes().as_ref());
        let method_str = method.to_string();
        let json = serde_json::to_vec(&IrohApiRequest { method, request })
            .expect("Serialization to vec can't fail");

        let response = {
            let _guard = self.enter();
            match fedimint_core::runtime::timeout(timeout, self.conn.round_trip(&json)).await {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    // The bi-stream stalled past our budget. Retire the entry so
                    // the pool stops handing it out and the upstream retry loop
                    // gets a fresh connection, WITHOUT tearing down requests that
                    // are still in flight on this one.
                    //
                    // A long-poll reaching its budget with no data is EXPECTED
                    // steady state (idle subscription) — log it at debug. A
                    // prompt request exceeding the 60s default is genuinely
                    // unusual — warn.
                    log_request_timeout(&method_str, timeout);
                    self.retire();
                    return Err(ServerError::Transport(anyhow::anyhow!(
                        "iroh request {method_str} timed out after {timeout:?}"
                    )));
                }
            }
        };

        // TODO: We should not be serializing Results on the wire
        let response = serde_json::from_slice::<Result<Value, ApiError>>(&response)
            .map_err(|e| ServerError::InvalidResponse(e.into()))?;

        response.map_err(|e| ServerError::InvalidResponse(anyhow::anyhow!("Api Error: {:?}", e)))
    }
}

#[apply(async_trait_maybe_send!)]
impl IConnection for Connection {
    async fn await_disconnection(&self) {
        self.closed().await;
    }

    fn is_connected(&self) -> bool {
        self.close_reason().is_none()
    }
}

#[async_trait]
impl IrohGuardianConn for Connection {
    fn remote_id_bytes(&self) -> Option<[u8; 32]> {
        self.remote_node_id().ok().map(|id| *id.as_bytes())
    }

    fn is_open(&self) -> bool {
        self.close_reason().is_none()
    }

    fn close_timed_out(&self) {
        self.close(
            iroh::endpoint::VarInt::from_u32(IROH_REQUEST_TIMEOUT_ERROR_CODE),
            IROH_REQUEST_TIMEOUT_ERROR_REASON,
        );
    }

    async fn wait_closed(&self) {
        self.closed().await;
    }

    async fn round_trip(&self, json: &[u8]) -> ServerResult<Vec<u8>> {
        let (mut sink, mut stream) = self
            .open_bi()
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        sink.write_all(json)
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        sink.finish()
            .map_err(|e| ServerError::Transport(e.into()))?;

        stream
            .read_to_end(IROH_MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| ServerError::Transport(e.into()))
    }
}

#[apply(async_trait_maybe_send!)]
impl IConnection for iroh_next::endpoint::Connection {
    async fn await_disconnection(&self) {
        self.closed().await;
    }

    fn is_connected(&self) -> bool {
        self.close_reason().is_none()
    }
}

#[async_trait]
impl IrohGuardianConn for iroh_next::endpoint::Connection {
    fn remote_id_bytes(&self) -> Option<[u8; 32]> {
        Some(*self.remote_id().as_bytes())
    }

    fn is_open(&self) -> bool {
        self.close_reason().is_none()
    }

    fn close_timed_out(&self) {
        self.close(
            iroh_next::endpoint::VarInt::from_u32(IROH_REQUEST_TIMEOUT_ERROR_CODE),
            IROH_REQUEST_TIMEOUT_ERROR_REASON,
        );
    }

    async fn wait_closed(&self) {
        self.closed().await;
    }

    async fn round_trip(&self, json: &[u8]) -> ServerResult<Vec<u8>> {
        let (mut sink, mut stream) = self
            .open_bi()
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        sink.write_all(json)
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        sink.finish()
            .map_err(|e| ServerError::Transport(e.into()))?;

        stream
            .read_to_end(IROH_MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| ServerError::Transport(e.into()))
    }
}

#[apply(async_trait_maybe_send!)]
impl IGatewayConnection for Connection {
    async fn request(
        &self,
        password: Option<String>,
        _method: Method,
        route: &str,
        payload: Option<Value>,
    ) -> ServerResult<Value> {
        let iroh_request = IrohGatewayRequest {
            route: route.to_string(),
            params: payload,
            password,
        };
        let json = serde_json::to_vec(&iroh_request).expect("serialization cant fail");

        let (mut sink, mut stream) = self
            .open_bi()
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        sink.write_all(&json)
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        sink.finish()
            .map_err(|e| ServerError::Transport(e.into()))?;

        let response = stream
            .read_to_end(IROH_MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        let response = serde_json::from_slice::<IrohGatewayResponse>(&response)
            .map_err(|e| ServerError::InvalidResponse(e.into()))?;
        match StatusCode::from_u16(response.status).map_err(|e| {
            ServerError::InvalidResponse(anyhow::anyhow!("Invalid status code: {}", e))
        })? {
            StatusCode::OK => Ok(response.body),
            status => Err(ServerError::ServerError(anyhow::anyhow!(
                "Server returned status code: {}",
                status
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use async_trait::async_trait;
    use fedimint_core::module::ApiMethod;

    use super::{
        IROH_REQUEST_TIMEOUT_DEFAULT, IROH_REQUEST_TIMEOUT_LNV2_WAIT,
        IROH_REQUEST_TIMEOUT_LONG_POLL, IrohGuardianConn, request_timeout_for_method,
    };
    use crate::{IConnection, ServerResult};

    /// `await_*` endpoints that take the generic 1-hour long-poll budget. If a
    /// new endpoint is added without the prefix it will silently fall through
    /// to the default 60s budget — this list documents the contract and will
    /// surface renames as test churn. The lnv2 receive-side waits are
    /// deliberately absent: they take the shorter tier (see
    /// [`LNV2_WAIT_ENDPOINTS`]).
    const AWAIT_ENDPOINTS: &[&str] = &[
        // fedimint-core
        "await_output_outcome",
        "await_outputs_outcomes",
        "await_session_outcome",
        "await_signed_session_outcome",
        "await_transaction",
        // fedimint-ln-common
        "await_account",
        "await_block_height",
        "await_offer",
        "await_outgoing_contract_cancelled",
        "await_preimage_decryption",
    ];

    /// The lnv2 payment waits (receive claim + send proof-of-payment) that take
    /// the shorter budget so a degraded connection recovers in minutes, not an
    /// hour. `decryption_key_share` carries no `await_`/`wait_` prefix, so it
    /// is the one entry here that the generic heuristic would otherwise
    /// drop to the 60s prompt tier despite being a genuine long-poll.
    const LNV2_WAIT_ENDPOINTS: &[&str] = &[
        "await_incoming_contract",
        "await_incoming_contracts",
        "await_preimage",
        "decryption_key_share",
    ];

    /// A representative sample of prompt endpoints — anything that is
    /// expected to respond without server-side blocking.
    const PROMPT_ENDPOINTS: &[&str] = &[
        "block_count",
        "session_count",
        "session_status",
        "status",
        "version",
        "client_config",
        "audit",
        "account",
        "offer",
        "list_gateways",
        "submit_transaction",
        "consensus_block_count",
    ];

    #[test]
    fn await_prefix_gets_long_poll_timeout() {
        for name in AWAIT_ENDPOINTS {
            assert_eq!(
                request_timeout_for_method(&ApiMethod::Core((*name).to_owned())),
                IROH_REQUEST_TIMEOUT_LONG_POLL,
                "core endpoint {name} should map to the long-poll timeout"
            );
            assert_eq!(
                request_timeout_for_method(&ApiMethod::Module(0, (*name).to_owned())),
                IROH_REQUEST_TIMEOUT_LONG_POLL,
                "module endpoint {name} should map to the long-poll timeout"
            );
        }
    }

    #[test]
    fn lnv2_payment_waits_get_the_shorter_long_poll_timeout() {
        // These must map to the shorter tier, NOT the generic 1-hour bound, so a
        // stalled receiving client recovers in minutes. Exact-name matched, and
        // checked on both Core and Module method shapes.
        for name in LNV2_WAIT_ENDPOINTS {
            assert_eq!(
                request_timeout_for_method(&ApiMethod::Core((*name).to_owned())),
                IROH_REQUEST_TIMEOUT_LNV2_WAIT,
                "core endpoint {name} should map to the lnv2 receive long-poll timeout"
            );
            assert_eq!(
                request_timeout_for_method(&ApiMethod::Module(0, (*name).to_owned())),
                IROH_REQUEST_TIMEOUT_LNV2_WAIT,
                "module endpoint {name} should map to the lnv2 receive long-poll timeout"
            );
        }
        // The shorter tier is a strictly tighter bound than the generic one.
        assert!(IROH_REQUEST_TIMEOUT_LNV2_WAIT < IROH_REQUEST_TIMEOUT_LONG_POLL);
    }

    #[test]
    fn lnv2_wait_budgets_are_spread_and_other_tiers_are_not() {
        use std::collections::BTreeSet;

        use super::{
            IROH_LNV2_WAIT_SPREAD, request_timeout_for_method_spread, spread_offset_for_peer,
        };

        // A peer id stands in for a guardian. Vary only the low byte of the
        // leading 8, so these are as adversarially close as distinct keys get.
        let peer = |n: u8| {
            let mut id = [0u8; 32];
            id[7] = n;
            id
        };
        let wait = || ApiMethod::Core("await_incoming_contracts".to_owned());

        // The offset is a pure function of the peer id, so a given peer's
        // budget is the same on every cycle and on every platform — it cannot
        // silently degrade with the resolution of a clock, which is what a
        // wall-clock source did on wasm and Windows.
        let id = peer(3);
        assert_eq!(
            request_timeout_for_method_spread(&wait(), Some(&id)),
            request_timeout_for_method_spread(&wait(), Some(&id)),
            "a peer's spread budget must be stable across calls"
        );

        // Distinct peers must get distinct budgets, all inside (base - spread,
        // base]. This is the property the spread exists for: one wait per peer
        // issued at the same instant must not expire on the same tick.
        let budgets: BTreeSet<_> = (0..16)
            .map(|n| request_timeout_for_method_spread(&wait(), Some(&peer(n))))
            .collect();
        assert_eq!(budgets.len(), 16, "distinct peers collided on one budget");
        for budget in &budgets {
            assert!(
                *budget <= IROH_REQUEST_TIMEOUT_LNV2_WAIT
                    && *budget > IROH_REQUEST_TIMEOUT_LNV2_WAIT - IROH_LNV2_WAIT_SPREAD,
                "spread budget {budget:?} outside its window"
            );
        }

        // The offset spans the window rather than hugging one end.
        let offsets: BTreeSet<_> = (0..=u8::MAX)
            .map(|n| spread_offset_for_peer(&peer(n)))
            .collect();
        let lo = *offsets.iter().next().expect("non-empty");
        let hi = *offsets.iter().next_back().expect("non-empty");
        assert!(
            lo < IROH_LNV2_WAIT_SPREAD / 4 && hi > IROH_LNV2_WAIT_SPREAD * 3 / 4,
            "offsets {lo:?}..{hi:?} did not span the window"
        );
        assert!(hi < IROH_LNV2_WAIT_SPREAD, "offset escaped the window");

        // A missing peer identity falls back to the exact tier bound.
        assert_eq!(
            request_timeout_for_method_spread(&wait(), None),
            IROH_REQUEST_TIMEOUT_LNV2_WAIT
        );

        // The other tiers keep their exact bounds, spread or not.
        let id = peer(9);
        assert_eq!(
            request_timeout_for_method_spread(
                &ApiMethod::Core("await_transaction".to_owned()),
                Some(&id)
            ),
            IROH_REQUEST_TIMEOUT_LONG_POLL
        );
        assert_eq!(
            request_timeout_for_method_spread(
                &ApiMethod::Core("block_count".to_owned()),
                Some(&id)
            ),
            IROH_REQUEST_TIMEOUT_DEFAULT
        );
    }

    #[test]
    fn wait_prefix_also_gets_long_poll_timeout() {
        // No fedimint endpoint currently uses this prefix, but the
        // selector accepts it so future additions following the
        // alternate naming convention don't silently get the default.
        assert_eq!(
            request_timeout_for_method(&ApiMethod::Core("wait_for_event".to_owned())),
            IROH_REQUEST_TIMEOUT_LONG_POLL,
        );
    }

    #[test]
    fn prompt_endpoints_get_default_timeout() {
        for name in PROMPT_ENDPOINTS {
            assert_eq!(
                request_timeout_for_method(&ApiMethod::Core((*name).to_owned())),
                IROH_REQUEST_TIMEOUT_DEFAULT,
                "endpoint {name} should map to the default timeout"
            );
        }
    }

    #[test]
    fn endpoints_that_merely_contain_await_are_not_misclassified() {
        // The selector is prefix-based, so an endpoint name with
        // "await" elsewhere in the string must not get the long
        // budget by accident.
        assert_eq!(
            request_timeout_for_method(&ApiMethod::Core("submit_await_thing".to_owned())),
            IROH_REQUEST_TIMEOUT_DEFAULT,
        );
    }

    /// A stand-in guardian connection that records whether it was closed, so
    /// the retire/drain semantics can be asserted without a live QUIC endpoint.
    #[derive(Debug, Default)]
    struct FakeConn {
        closed: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl IrohGuardianConn for FakeConn {
        fn remote_id_bytes(&self) -> Option<[u8; 32]> {
            Some([7u8; 32])
        }

        fn is_open(&self) -> bool {
            !self.closed.load(Ordering::Acquire)
        }

        fn close_timed_out(&self) {
            self.closed.store(true, Ordering::Release);
        }

        async fn wait_closed(&self) {
            // Park unless the connection really is closed, so a test can tell
            // "woke because retired" apart from "woke because closed".
            if !self.closed.load(Ordering::Acquire) {
                std::future::pending::<()>().await;
            }
        }

        async fn round_trip(&self, _json: &[u8]) -> ServerResult<Vec<u8>> {
            unreachable!("these tests exercise retirement, not the wire")
        }
    }

    fn pooled() -> super::PooledGuardianConnection<FakeConn> {
        super::PooledGuardianConnection::new(FakeConn::default())
    }

    #[test]
    fn retiring_with_a_request_in_flight_does_not_close_the_connection() {
        // The whole point: a timed-out long-poll must stop the pool handing this
        // entry out WITHOUT aborting the unrelated requests riding on it. On a
        // single-guardian federation there is no second peer to absorb that, so
        // closing here would fail those calls outright.
        let pooled = pooled();
        let guard = pooled.enter();

        pooled.retire();

        assert!(!pooled.is_connected(), "a retired entry must not be reused");
        assert!(
            pooled.conn.is_open(),
            "retiring must not tear down a connection with work still on it"
        );

        // ... and it closes as soon as that last request is done.
        drop(guard);
        assert!(
            !pooled.conn.is_open(),
            "the last request out of a retired connection must close it"
        );
    }

    #[test]
    fn a_retired_connection_closes_only_after_the_last_request_leaves() {
        let pooled = pooled();
        let first = pooled.enter();
        let second = pooled.enter();

        pooled.retire();
        drop(first);
        assert!(
            pooled.conn.is_open(),
            "a still-busy retired connection must stay open"
        );

        drop(second);
        assert!(!pooled.conn.is_open(), "the last one out closes it");
    }

    #[test]
    fn retiring_an_idle_connection_closes_it_immediately() {
        // Defensive path: nothing in flight, so there is no guard drop coming
        // that would otherwise close it.
        let pooled = pooled();
        pooled.retire();
        assert!(!pooled.is_connected());
        assert!(!pooled.conn.is_open());
    }

    #[test]
    fn await_disconnection_wakes_on_retire_not_just_on_close() {
        use std::future::Future as _;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        let pooled = pooled();
        // Hold a request open so `retire()` does NOT close the connection —
        // otherwise this could pass by waking on the close instead.
        let _guard = pooled.enter();

        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut disconnected = std::pin::pin!(pooled.await_disconnection());

        assert!(
            matches!(disconnected.as_mut().poll(&mut cx), Poll::Pending),
            "a healthy connection must not report a disconnection"
        );

        // Both reconnect loops (fedimint-connectors/src/lib.rs and
        // fedimint-client/src/client.rs) drive pool refresh off this, so it has
        // to fire on retire; waiting for the physical close would defer the
        // refresh until the connection finished draining.
        pooled.retire();
        assert!(
            pooled.conn.is_open(),
            "precondition: retiring with a request in flight must not close"
        );
        assert!(
            matches!(disconnected.as_mut().poll(&mut cx), Poll::Ready(())),
            "await_disconnection must wake on retire, not only on close"
        );
    }

    #[test]
    fn a_healthy_connection_is_usable_and_stays_open() {
        let pooled = pooled();
        assert!(pooled.is_connected());
        {
            let _guard = pooled.enter();
            assert!(pooled.is_connected());
        }
        assert!(
            pooled.conn.is_open(),
            "an ordinary request completing must not close the connection"
        );
        assert!(pooled.is_connected());
    }
}
