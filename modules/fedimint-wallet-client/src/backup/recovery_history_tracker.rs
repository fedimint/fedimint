use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_logging::LOG_CLIENT_MODULE_WALLET;
use tracing::debug;

use super::RECOVER_MAX_GAP;
use crate::client_db::TweakIdx;
use crate::WalletClientModuleData;

/// Tracks addresses `TweakIdx`s/addresses that are expected to have been used
/// against the stream of addresses that were actually used for peg-ins in the
/// Federation.
///
/// Since replaying Federation history is entirely private, the goal here
/// is to find the last peg-in address already used without compromising
/// privacy like when querying Bitcoin node.
///
/// While at it, collect some addresses that were actually used for peg-ins by
/// other clients, just to query for them as decoys and thus hopefully make the
/// malicious Bitcoin node operator have less confidence about which addresses
/// are actually linked with each other.
#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ConsensusPegInTweakIdxesUsedTracker {
    /// Any time we detect one of the scripts in `pending_pubkey_scripts` was
    /// used we insert the `tweak_idx`, so we can skip asking network about
    /// them (which would be bad for privacy)
    used_tweak_idxes: BTreeSet<TweakIdx>,
    /// All the pubkey scripts we are looking for in the federation history, to
    /// detect previous successful peg-ins.
    pending_pubkey_scripts: BTreeMap<bitcoin::ScriptBuf, TweakIdx>,
    /// Next tweak idx to add to `pending_pubkey_scripts`
    next_pending_tweak_idx: TweakIdx,

    /// Collection of recent scripts from federation history that do not belong
    /// to us
    decoys: VecDeque<bitcoin::ScriptBuf>,
    // To avoid updating `decoys` for the whole recovery, which might be a lot of extra updates
    // most of which will be thrown away, ignore script pubkeys from before this `session_idx`
    decoy_session_threshold: u64,
}

impl ConsensusPegInTweakIdxesUsedTracker {
    pub(crate) fn new(
        previous_next_unused_idx: TweakIdx,
        start_session_idx: u64,
        current_session_count: u64,
        data: &WalletClientModuleData,
    ) -> Self {
        debug_assert!(start_session_idx <= current_session_count);

        let mut s = Self {
            next_pending_tweak_idx: previous_next_unused_idx,
            pending_pubkey_scripts: BTreeMap::new(),
            decoys: VecDeque::new(),
            decoy_session_threshold: current_session_count
                .saturating_sub((current_session_count.saturating_sub(current_session_count)) / 20),
            used_tweak_idxes: BTreeSet::new(),
        };

        s.init(data);

        s
    }

    fn init(&mut self, data: &WalletClientModuleData) {
        for _ in 0..RECOVER_MAX_GAP {
            self.generate_next_pending_tweak_idx(data);
        }
        debug_assert_eq!(self.pending_pubkey_scripts.len(), RECOVER_MAX_GAP as usize);
    }

    pub fn used_tweak_idxes(&self) -> &BTreeSet<TweakIdx> {
        &self.used_tweak_idxes
    }

    fn generate_next_pending_tweak_idx(&mut self, data: &WalletClientModuleData) {
        let (script, _address, _tweak_key, _operation_id) =
            data.derive_peg_in_script(self.next_pending_tweak_idx);

        self.pending_pubkey_scripts
            .insert(script, self.next_pending_tweak_idx);
        self.next_pending_tweak_idx = self.next_pending_tweak_idx.next();
    }

    fn refill_pending_pool_up_to_tweak_idx(
        &mut self,
        data: &WalletClientModuleData,
        tweak_idx: TweakIdx,
    ) {
        while self.next_pending_tweak_idx < tweak_idx {
            self.generate_next_pending_tweak_idx(data);
        }
    }

    pub(crate) fn handle_script(
        &mut self,
        data: &WalletClientModuleData,
        script: &bitcoin::ScriptBuf,
        session_idx: u64,
    ) {
        if let Some(tweak_idx) = self.pending_pubkey_scripts.get(script).copied() {
            debug!(target: LOG_CLIENT_MODULE_WALLET, %session_idx, ?tweak_idx, "Found previously used tweak_idx in federation history");

            self.used_tweak_idxes.insert(tweak_idx);

            self.refill_pending_pool_up_to_tweak_idx(data, tweak_idx.advance(RECOVER_MAX_GAP));
        } else if self.decoy_session_threshold < session_idx {
            self.push_decoy(script);
        }
    }

    /// Write a someone-elses used deposit address to use a decoy
    fn push_decoy(&mut self, script: &bitcoin::ScriptBuf) {
        self.decoys.push_front(script.clone());
        if 50 < self.decoys.len() {
            self.decoys.pop_back();
        }
    }

    /// Pop a someone-elses used deposit address to use a decoy
    pub(crate) fn pop_decoy(&mut self) -> Option<bitcoin::ScriptBuf> {
        self.decoys.pop_front()
    }
}
