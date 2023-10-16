use std::time::Duration;

use fedimint_core::api::WsFederationApi;
use fedimint_core::db::Database;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::task::spawn;
use tokio::sync::watch;

use super::keychain::Keychain;
use super::{session, Message};
use crate::atomic_broadcast::backup;
use crate::atomic_broadcast::data_provider::DataProvider;
use crate::atomic_broadcast::finalization_handler::FinalizationHandler;
use crate::atomic_broadcast::network::Network;
use crate::atomic_broadcast::spawner::Spawner;
use crate::consensus::FedimintConsensus;
use crate::net::peers::ReconnectPeerConnections;

pub struct AtomicBroadcast {
    keychain: Keychain,
    db: Database,
    connections: ReconnectPeerConnections<Message>,
    mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
}

impl AtomicBroadcast {
    /// This function starts the atomic broadcast instance. A running instance
    /// serves signed blocks to peers on request even if we do not run a
    /// session.
    pub fn new(
        keychain: Keychain,
        db: Database,
        connections: ReconnectPeerConnections<Message>,
        mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
    ) -> Self {
        Self {
            keychain,
            db,
            connections,
            mempool_item_receiver,
        }
    }

    /// The receiver returns a sequence of items which is a subsequence of
    /// all items ordered in this session and a supersequence of the accepted
    /// items. The end of a session is signaled by the return of Some(None)
    /// while the return of None directly signals that the session has been
    /// interrupted, either by a call to shutdown or by dropping a
    /// decision_sender without sending a decision.
    pub async fn run_session(
        &self,
        consensus: FedimintConsensus,
        federation_api: WsFederationApi,
    ) -> anyhow::Result<()> {
        // if all nodes are correct the session will take 45 to 60 seconds. The
        // more nodes go offline the longer the session will take to complete.
        const EXPECTED_ROUNDS_PER_SESSION: usize = 45 * 4;
        // this constant needs to be 3000 or less to guarantee that the session
        // can never reach MAX_ROUNDs.
        const EXPONENTIAL_SLOWDOWN_OFFSET: usize = 3 * EXPECTED_ROUNDS_PER_SESSION;
        const MAX_ROUND: u16 = 5000;
        const ROUND_DELAY: f64 = 250.0;
        const BASE: f64 = 1.01;

        // this is the minimum number of unit data that will be ordered before we reach
        // the EXPONENTIAL_SLOWDOWN_OFFSET even if f peers do not attach unit data
        let batches_per_session = EXPECTED_ROUNDS_PER_SESSION * self.keychain.peer_count();

        // In order to bound a sessions RAM consumption we need to bound its number of
        // units and therefore its number of rounds. Since we use a session to
        // create a threshold signature for the corresponding block we have to
        // guarantee that an attacker cannot exhaust our memory by preventing the
        // creation of a threshold signature, thereby keeping the session open
        // indefinitely. Hence we increase the delay between rounds exponentially
        // such that MAX_ROUND would only be reached after roughly 350 years.
        // In case of such an attack the broadcast stops ordering any items until the
        // attack subsides as not items are ordered while the signatures are collected.
        let mut delay_config = aleph_bft::default_delay_config();
        delay_config.unit_creation_delay = std::sync::Arc::new(|round_index| {
            let delay = if round_index == 0 {
                0.0
            } else {
                ROUND_DELAY
                    * BASE.powf(round_index.saturating_sub(EXPONENTIAL_SLOWDOWN_OFFSET) as f64)
            };

            Duration::from_millis(delay.round() as u64)
        });

        let config = aleph_bft::create_config(
            self.keychain.peer_count().into(),
            self.keychain.peer_id().to_usize().into(),
            consensus.session_index,
            MAX_ROUND,
            delay_config,
            Duration::from_secs(100 * 365 * 24 * 60 * 60),
        )
        .expect("Config is valid");

        // the number of units ordered in a single aleph session is bounded
        let (unit_data_sender, unit_data_receiver) = async_channel::unbounded();
        let (signature_sender, signature_receiver) = watch::channel(None);
        let (terminator_sender, terminator_receiver) = futures::channel::oneshot::channel();

        let (loader, saver) = backup::load_session(self.db.clone()).await;

        let aleph_handle = spawn(
            "aleph run session",
            aleph_bft::run_session(
                config,
                aleph_bft::LocalIO::new(
                    DataProvider::new(self.mempool_item_receiver.clone(), signature_receiver),
                    FinalizationHandler::new(unit_data_sender),
                    saver,
                    loader,
                ),
                Network::new(self.connections.clone()),
                self.keychain.clone(),
                Spawner::new(),
                aleph_bft_types::Terminator::create_root(terminator_receiver, "Terminator"),
            ),
        )
        .expect("some handle on non-wasm");

        let (consensus, signed_block) = session::run(
            consensus,
            batches_per_session,
            unit_data_receiver,
            signature_sender,
            self.keychain.clone(),
            federation_api,
        )
        .await?;

        terminator_sender.send(()).ok();
        aleph_handle.await.ok();

        // we can only call complete_session after aleph bft has shut down
        // to prevent write conflicts when removing the aleph units
        consensus.complete_session(signed_block).await;

        Ok(())
    }
}
