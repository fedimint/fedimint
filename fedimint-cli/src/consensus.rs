//! `fedimint-cli dev consensus follow`: print a federation's consensus history
//! one item per line, optionally following new sessions as they are signed.
//!
//! Everything network related lives here, decoding/filtering/formatting is in
//! the pure [`view`] module.

mod view;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::io::{self, IsTerminal as _, Write as _};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::bail;
use fedimint_api_client::api::{
    DynGlobalApi, FederationApiExt as _, VERSION_THAT_INTRODUCED_GET_SESSION_STATUS,
    VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
};
use fedimint_client::ClientHandleArc;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::endpoint_constants::SESSION_STATUS_V2_ENDPOINT;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiRequestErased, ApiVersion, SerdeModuleEncodingBase64};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::session_outcome::{
    AcceptedItem, SessionOutcome, SessionStatus, SessionStatusV2,
};
use fedimint_core::util::FmtCompact as _;
use fedimint_core::util::backoff_util::{self, FibonacciBackoff};
use fedimint_core::{PeerId, runtime};
use fedimint_logging::LOG_CLIENT;
use futures::StreamExt as _;
use tracing::{debug, info, warn};
pub(crate) use view::ItemTypeFilter;
use view::{ItemFilter, ItemView, SessionSummary, Style};

use crate::cli::ConsensusFollowArgs;

/// Number of already signed sessions printed if `--from` is not given
const DEFAULT_BACKLOG_SESSIONS: u64 = 3;
/// How often to poll for new sessions (and pending items) while following
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Number of signed sessions fetched concurrently when catching up
const PREFETCH_SESSIONS: usize = 8;

/// Runs `dev consensus follow` until the requested range is printed, stdout is
/// closed, or Ctrl-C is pressed.
pub async fn follow(client: &ClientHandleArc, args: ConsensusFollowArgs) -> anyhow::Result<()> {
    if let (Some(from), Some(to)) = (args.from, args.to)
        && to < from
    {
        bail!("--to ({to}) must not be smaller than --from ({from})");
    }

    let config = client.config().await;
    let ctx = FollowCtx {
        api: client.api_clone(),
        // Don't fail on items of modules this client has no decoder for
        decoders: client.decoders().clone().with_fallback(),
        core_api_version: client.core_api_version().await,
        broadcast_public_keys: config.global.broadcast_public_keys.clone(),
        kinds: config
            .modules
            .iter()
            .map(|(id, module)| (*id, module.kind.clone()))
            .collect(),
        peers: config.global.api_endpoints.keys().copied().collect(),
    };

    let use_color = !args.no_color
        && !args.json
        && io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none();
    let mut printer = Printer {
        json: args.json,
        style: Style { color: use_color },
        filter: ItemFilter {
            only: args.only,
            modules: args.modules.clone(),
            inputs: args.inputs.clone(),
            outputs: args.outputs.clone(),
            all: args.all,
        },
    };

    tokio::select! {
        res = ctx.run(&args, &mut printer) => match res {
            Err(err) if is_broken_pipe(&err) => Ok(()),
            res => res,
        },
        _ = tokio::signal::ctrl_c() => {
            debug!(target: LOG_CLIENT, "Received Ctrl-C, stopping");
            Ok(())
        }
    }
}

fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::BrokenPipe)
}

struct FollowCtx {
    api: DynGlobalApi,
    decoders: ModuleDecoderRegistry,
    core_api_version: ApiVersion,
    broadcast_public_keys: Option<BTreeMap<PeerId, PublicKey>>,
    kinds: BTreeMap<ModuleInstanceId, ModuleKind>,
    peers: Vec<PeerId>,
}

/// Progress within the session currently being printed
#[derive(Default)]
struct SessionProgress {
    /// Pending items already printed (`--pending`)
    printed: Vec<AcceptedItem>,
    /// Number of printed items that passed the filter
    shown: usize,
    /// Whether we had to wait for the session to be signed
    waited: bool,
}

impl FollowCtx {
    async fn run(&self, args: &ConsensusFollowArgs, printer: &mut Printer) -> anyhow::Result<()> {
        let mut known_count = self.session_count_with_retry().await;
        let from = args
            .from
            .unwrap_or_else(|| known_count.saturating_sub(DEFAULT_BACKLOG_SESSIONS));
        // Exclusive end of the range to print, `None` to follow forever
        let end = match (args.to, args.no_follow) {
            (Some(to), _) => Some(to.saturating_add(1)),
            (None, true) => Some(known_count),
            (None, false) => None,
        };
        let pending = args.pending && self.supports_pending();

        info!(
            target: LOG_CLIENT,
            from,
            end = %end.map_or_else(|| "following".to_owned(), |end| end.to_string()),
            session_count = known_count,
            pending,
            "Following consensus history"
        );

        let mut next = from;
        let mut progress = SessionProgress::default();
        let mut pending_peer_idx = 0;
        let mut poll_backoff: Option<FibonacciBackoff> = None;

        while end.is_none_or(|end| next < end) {
            if next < known_count {
                let batch_end = end.map_or(known_count, |end| end.min(known_count));
                let mut sessions = futures::stream::iter(next..batch_end)
                    .map(|session_idx| self.fetch_signed_session(session_idx))
                    .buffered(PREFETCH_SESSIONS);

                while let Some((session_idx, outcome)) = sessions.next().await {
                    self.print_signed_session(session_idx, &outcome, &progress, printer)?;
                    progress = SessionProgress::default();
                    next = session_idx + 1;
                }
                continue;
            }

            progress.waited = true;

            if pending && next == known_count {
                let peer = self.peers[pending_peer_idx % self.peers.len()];
                match self.fetch_pending_items(next, peer).await {
                    Ok(Some(items)) => {
                        for (item_idx, item) in
                            items.iter().enumerate().skip(progress.printed.len())
                        {
                            let view =
                                ItemView::from_accepted(next, item_idx, item, &self.kinds, false);
                            if printer.print_item(&view)? {
                                progress.shown += 1;
                            }
                        }
                        if progress.printed.len() < items.len() {
                            progress.printed = items;
                        }
                    }
                    // The peer is not in this session (lagging behind or already done),
                    // ask another one next time
                    Ok(None) => pending_peer_idx += 1,
                    Err(err) => {
                        warn!(
                            target: LOG_CLIENT,
                            err = %err.fmt_compact(),
                            %peer,
                            session_idx = next,
                            "Failed to fetch pending session items, trying another peer"
                        );
                        pending_peer_idx += 1;
                    }
                }
            }

            let delay = poll_backoff
                .as_mut()
                .and_then(Iterator::next)
                .unwrap_or(POLL_INTERVAL);
            runtime::sleep(delay).await;

            match self.api.session_count().await {
                Ok(count) => {
                    known_count = count;
                    poll_backoff = None;
                }
                Err(err) => {
                    warn!(
                        target: LOG_CLIENT,
                        err = %err.fmt_compact(),
                        "Failed to fetch session count, retrying"
                    );
                    poll_backoff.get_or_insert_with(error_backoff);
                }
            }
        }

        Ok(())
    }

    fn supports_pending(&self) -> bool {
        if self.core_api_version < VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2 {
            warn!(
                target: LOG_CLIENT,
                core_api_version = %self.core_api_version,
                "Federation does not support fetching pending session items, ignoring --pending"
            );
            return false;
        }
        !self.peers.is_empty()
    }

    fn print_signed_session(
        &self,
        session_idx: u64,
        outcome: &SessionOutcome,
        progress: &SessionProgress,
        printer: &mut Printer,
    ) -> anyhow::Result<()> {
        if !outcome.items.starts_with(&progress.printed) {
            warn!(
                target: LOG_CLIENT,
                session_idx,
                printed = progress.printed.len(),
                "Signed session differs from previously printed pending items"
            );
        }

        let views: Vec<ItemView> = outcome
            .items
            .iter()
            .enumerate()
            .map(|(item_idx, item)| {
                ItemView::from_accepted(session_idx, item_idx, item, &self.kinds, true)
            })
            .collect();

        let mut shown = progress.shown;
        for view in views.iter().skip(progress.printed.len()) {
            if printer.print_item(view)? {
                shown += 1;
            }
        }

        let mut summary = SessionSummary::new(session_idx, &views);
        summary.shown = shown;
        summary.signed_at = progress.waited.then(|| {
            fedimint_core::time::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since_epoch| since_epoch.as_secs())
        });
        printer.print_session(&summary)
    }

    async fn session_count_with_retry(&self) -> u64 {
        let mut backoff = error_backoff();
        loop {
            match self.api.session_count().await {
                Ok(count) => return count,
                Err(err) => {
                    warn!(
                        target: LOG_CLIENT,
                        err = %err.fmt_compact(),
                        "Failed to fetch session count, retrying"
                    );
                    runtime::sleep(backoff.next().unwrap_or(POLL_INTERVAL)).await;
                }
            }
        }
    }

    /// Fetches a session that is known to be signed, retrying until it
    /// succeeds
    async fn fetch_signed_session(&self, session_idx: u64) -> (u64, SessionOutcome) {
        let mut backoff = error_backoff();
        loop {
            match self.try_fetch_signed_session(session_idx).await {
                Ok(outcome) => return (session_idx, outcome),
                Err(err) => {
                    warn!(
                        target: LOG_CLIENT,
                        err = %err.fmt_compact(),
                        session_idx,
                        "Failed to fetch signed session, retrying"
                    );
                    runtime::sleep(backoff.next().unwrap_or(POLL_INTERVAL)).await;
                }
            }
        }
    }

    async fn try_fetch_signed_session(&self, session_idx: u64) -> anyhow::Result<SessionOutcome> {
        // Same API selection as client recovery
        if self.core_api_version < VERSION_THAT_INTRODUCED_GET_SESSION_STATUS {
            return Ok(self.api.await_block(session_idx, &self.decoders).await?);
        }

        match self
            .api
            .get_session_status(
                session_idx,
                &self.decoders,
                self.core_api_version,
                self.broadcast_public_keys.as_ref(),
            )
            .await?
        {
            SessionStatus::Complete(outcome) => Ok(outcome),
            SessionStatus::Initial | SessionStatus::Pending(_) => {
                bail!("Session {session_idx} is not signed yet")
            }
        }
    }

    /// Fetches the items a single peer accepted so far in the session that is
    /// currently in progress. Returns `None` if the session is not in progress
    /// according to that peer.
    async fn fetch_pending_items(
        &self,
        session_idx: u64,
        peer: PeerId,
    ) -> anyhow::Result<Option<Vec<AcceptedItem>>> {
        let status = self
            .api
            .request_single_peer_federation::<SerdeModuleEncodingBase64<SessionStatusV2>>(
                SESSION_STATUS_V2_ENDPOINT.to_owned(),
                ApiRequestErased::new(session_idx),
                peer,
            )
            .await?
            .try_into_inner(&self.decoders)?;

        Ok(match status {
            SessionStatusV2::Pending(items) => Some(items),
            SessionStatusV2::Initial | SessionStatusV2::Complete(_) => None,
        })
    }
}

fn error_backoff() -> FibonacciBackoff {
    backoff_util::custom_backoff(Duration::from_secs(1), Duration::from_secs(30), None)
}

/// Writes items and session lines to stdout
struct Printer {
    json: bool,
    style: Style,
    filter: ItemFilter,
}

impl Printer {
    /// Prints `item` if it passes the filter, returns whether it was printed
    fn print_item(&mut self, item: &ItemView) -> io::Result<bool> {
        if !self.filter.matches(item) {
            return Ok(false);
        }
        let line = if self.json {
            view::item_json(item).to_string()
        } else {
            view::format_item_line(item, self.style)
        };
        Self::write_line(&line)?;
        Ok(true)
    }

    fn print_session(&mut self, summary: &SessionSummary) -> anyhow::Result<()> {
        let line = if self.json {
            view::session_json(summary).to_string()
        } else {
            view::format_session_line(summary, self.style)
        };
        Ok(Self::write_line(&line)?)
    }

    fn write_line(line: &str) -> io::Result<()> {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{line}")?;
        stdout.flush()
    }
}
