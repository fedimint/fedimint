use std::collections::BTreeMap;

use bitcoin::XOnlyPublicKey;
use fedimint_api::{
    db::DatabaseTransaction,
    encoding::{Decodable, Encodable},
    PeerId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    action::{Action, ActionStaged, ProviderBid, SeekerAction},
    config::EpochConfig,
    db,
    stability_core::{self, EpochFeerate},
    AccountBalance, BackOff, ConsensusItemOutcome, LockedBalance, OracleClient, PoolConsensusItem,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EpochEnd {
    /// The price is an option because we may not know what the price is due to inability to fetch.
    /// We still want to indicate that we think the epoch has ended.
    pub price: Option<u64>,
    pub epoch_id: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EpochOutcome {
    pub total_seeker_locked: u64,
    pub total_provider_locked: u64,

    /// Epoch settled price
    pub settled_price: Option<u64>,
    /// Start feerate
    pub feerate: EpochFeerate,
}

pub struct EpochState {
    pub latest_ended: Option<u64>, // both epoch ids
    pub latest_settled: Option<u64>,
}

impl EpochState {
    pub async fn from_db(dbtx: &mut DatabaseTransaction<'_>) -> Self {
        Self {
            latest_ended: db::get(dbtx, &db::LastEpochEndedKey).await,
            latest_settled: db::get(dbtx, &db::LastEpochSettledKey).await,
        }
    }

    /// Returns the only epoch_id that we can accept user actions with. Returns [`None`] if epoch
    /// state is NOT settled (we will not process user actions).
    pub fn staging_epoch_id(&self) -> u64 {
        self.current_epoch_id() + 1
    }

    /// Returns the current epoch_id.
    pub fn current_epoch_id(&self) -> u64 {
        self.latest_ended.map_or(0, |id| id + 1)
    }

    /// Returns whether we are in a settled state.
    pub fn is_settled(&self) -> bool {
        if self.latest_settled == self.latest_ended {
            true
        } else if self.latest_settled < self.latest_ended {
            false
        } else {
            panic!("unexpected epoch state")
        }
    }

    /// requirements for incoming epoch_end (expected_epoch_id, needs_price)
    /// * expected_epoch_id: the expected value of the epoch_id field
    /// * needs_price: whether the epoch_end.price field is expected to be some
    pub fn expected_epoch_end_id(&self) -> (u64, bool) {
        if self.is_settled() {
            (self.latest_ended.map(|id| id + 1).unwrap_or(0), false)
        } else {
            (
                self.latest_ended
                    .expect("unsettled state expects atleast one ended epoch"),
                true,
            )
        }
    }
}

pub async fn can_propose(
    dbtx: &mut DatabaseTransaction<'_>,
    backoff: &BackOff,
    config: &EpochConfig,
) -> bool {
    let now = OffsetDateTime::now_utc();
    if !backoff.can_retry(now) {
        return false;
    }

    // expected epoch based on current time
    let expected_epoch = config.epoch_id_for_time(now);

    // last epoch in which price is settled
    let last_epoch_settled = db::get(dbtx, &db::LastEpochSettledKey).await;

    // we only need `last_settled_epoch` as `last_ended_epoch` is always equal or greater
    last_epoch_settled < Some(expected_epoch)
}

pub async fn consensus_proposal(
    dbtx: &mut DatabaseTransaction<'_>,
    backoff: &BackOff,
    config: &EpochConfig,
    oracle: &dyn OracleClient,
) -> Vec<PoolConsensusItem> {
    let now = OffsetDateTime::now_utc();
    if !backoff.can_retry(now) {
        return vec![];
    }

    // epoch consensus state
    let expected_epoch = config.epoch_id_for_time(now);

    let epoch_state = EpochState::from_db(dbtx).await;
    let is_settled = epoch_state.is_settled();

    // if we are in a settled state, and time requres epoch to end
    // propose `epoch_end` with `epoch_id = last_ended_epoch + 1`
    if is_settled && epoch_state.latest_ended < Some(expected_epoch) {
        // if is_settled && epoch_state.requires_ending(expected_epoch) {
        let epoch_id = epoch_state.latest_ended.map_or(0, |id| id + 1);
        let price = oracle.price_at_epoch_start(config, epoch_id).await.ok();
        if price.is_none() {
            backoff.record_failure(now);
        } else {
            backoff.reset();
        }
        return vec![EpochEnd { price, epoch_id }.into()];
    }

    // if we are not in a settled state, and time requires a settlement
    // propose `epoch_end` with `epoch_id = last_settled_epoch + 1`
    // ensure that we have a price!
    if !is_settled && epoch_state.latest_settled < Some(expected_epoch) {
        // if !is_settled && epoch_state.requires_settlement(expected_epoch) {
        let epoch_id = epoch_state.latest_settled.map_or(0, |id| id + 1);
        match oracle.price_at_epoch_start(config, epoch_id).await {
            Ok(price) => {
                backoff.reset();
                let price = Some(price);
                return vec![EpochEnd { price, epoch_id }.into()];
            }
            Err(err) => {
                backoff.record_failure(now);
                tracing::warn!(
                    error = err.to_string(),
                    "failed to fetch price and settle epoch, will try again"
                );
            }
        };
    }

    vec![]
}

pub async fn process_consensus_item(
    dbtx: &mut DatabaseTransaction<'_>,
    config: &EpochConfig,
    peer_id: PeerId,
    epoch_end: EpochEnd,
) -> ConsensusItemOutcome {
    // check epoch_end item relative to previous epoch_end item
    if let Some(prev_epoch_end) = db::get(dbtx, &db::EpochEndKey(peer_id)).await {
        // you cannot backtrack on epoch_end
        if epoch_end.epoch_id < prev_epoch_end.epoch_id {
            return ConsensusItemOutcome::Banned(format!(
                "attempted to backtrack on epoch_end (previous_epoch_end: {}, this_epoch_end: {})",
                prev_epoch_end.epoch_id, epoch_end.epoch_id
            ));
        }
        // we don't mark backtracking of price proposals
        if epoch_end.epoch_id == prev_epoch_end.epoch_id
            && epoch_end.price.is_none()
            && prev_epoch_end.price.is_some()
        {
            return ConsensusItemOutcome::Ignored(format!(
                "epoch: ignore backtrack of price proposal"
            ));
        }
    }

    // epoch consensus state
    let epoch_state = EpochState::from_db(dbtx).await;

    // check requirements for epoch_end
    let (expected_epoch_end_id, needs_price) = epoch_state.expected_epoch_end_id();
    if epoch_end.epoch_id > expected_epoch_end_id {
        return ConsensusItemOutcome::Banned(format!(
            "skipped epoch {}, got {} instead",
            expected_epoch_end_id, epoch_end.epoch_id
        ));
    }
    if epoch_end.epoch_id < expected_epoch_end_id {
        return ConsensusItemOutcome::Ignored(format!(
            "epoch: end request's epoch id ({}) is not the epoch ({}) we are ending",
            epoch_end.epoch_id, expected_epoch_end_id,
        ));
    }
    if needs_price && epoch_end.price.is_none() {
        return ConsensusItemOutcome::Ignored(format!(
            "epoch: end request requires price which is not provided",
        ));
    }

    // update epoch_end
    db::set(dbtx, &db::EpochEndKey(peer_id), &epoch_end).await;

    let threshold = config.price_threshold as usize;

    // see if we can update `last_ended_epoch`
    if epoch_state.is_settled() {
        let count = db::prefix_values(dbtx, &db::EpochEndKeyPrefix)
            .await
            .filter(|peer_epoch_end| peer_epoch_end.epoch_id == expected_epoch_end_id)
            .count();
        if count < threshold {
            return ConsensusItemOutcome::Applied;
        }
        db::set(dbtx, &db::LastEpochEndedKey, &expected_epoch_end_id).await;
    }

    // see if we can update `last_settled_epoch` with price tally: Map<price, occurences>
    let price_tally = db::prefix_entries(dbtx, &db::EpochEndKeyPrefix)
        .await
        .filter_map(|(_, peer_epoch_end)| peer_epoch_end.price)
        .fold(BTreeMap::new(), |mut tally, price| {
            *tally.entry(price).or_insert(0_usize) += 1;
            tally
        });

    // if we get a price that reaches agreement threshold, we can settle balances and start next epoch
    if let Some((price, _)) = price_tally.iter().find(|(_, &count)| count >= threshold) {
        // the `expected_epoch_end_id` is now the actual `epoch_end_id`
        let epoch_end_id = expected_epoch_end_id;

        db::set(dbtx, &db::LastEpochSettledKey, &epoch_end_id).await;

        // save price in epoch outcome and return epoch outcome
        let epoch_outcome = {
            let mut epoch_outcome = db::get(dbtx, &db::EpochOutcomeKey(epoch_end_id))
                .await
                // return dummy outcome for the very first epoch
                .unwrap_or(EpochOutcome {
                    feerate: EpochFeerate::from_ppm_feerate(0),
                    total_seeker_locked: 0,
                    total_provider_locked: 0,
                    settled_price: None,
                });
            let _old_price = epoch_outcome.settled_price.replace(*price);
            assert_eq!(_old_price, None);
            db::set(dbtx, &db::EpochOutcomeKey(epoch_end_id), &epoch_outcome).await;
            epoch_outcome
        };

        let previous_seeker_payouts =
            settle_locked_balances(dbtx, epoch_end_id, epoch_outcome).await;

        let current_balances = db::prefix_entries(dbtx, &db::AccountBalanceKeyPrefix)
            .await
            .map(|(k, v)| (k.0, v.unlocked.msats))
            .collect();

        let mut seeker_actions = Vec::<Action<SeekerAction>>::new();
        let mut provider_actions = Vec::<Action<ProviderBid>>::new();
        db::prefix_values(dbtx, &db::ActionStagedKeyPrefix)
            .await
            .for_each(|action| match action {
                ActionStaged::Seeker(a) => seeker_actions.push(a),
                ActionStaged::Provider(a) => provider_actions.push(a),
            });

        // Seeker actions are applied once and removed, whereas provider actions are reused.
        for seeker_id in seeker_actions.iter().map(|a| a.account_id) {
            db::pop(dbtx, &db::ActionStagedKey(seeker_id)).await;
        }

        let (seeker_locks, provider_bids) = stability_core::compute_desired_positions(
            &current_balances,
            previous_seeker_payouts,
            seeker_actions,
            provider_actions,
        );

        let (feerate, seeker_locked_balances, provider_locked_balances) =
            stability_core::match_locks_and_bids(
                seeker_locks.collect(),
                provider_bids
                    .filter(|bid| bid.min_feerate <= config.max_feerate_ppm)
                    .collect(),
                config.collateral_ratio,
            );

        let mut total_seeker_locked = 0;
        let mut total_provider_locked = 0;

        let locked_amounts_on_sides = seeker_locked_balances
            .into_iter()
            .map(|(k, a)| (k, LockedBalance::Seeker(fedimint_api::msats(a))))
            .chain(
                provider_locked_balances
                    .into_iter()
                    .map(|(k, a)| (k, LockedBalance::Provider(fedimint_api::msats(a)))),
            );

        for (account_id, locked_amount) in locked_amounts_on_sides {
            let current_balance = *current_balances
                .get(&account_id)
                .expect("there can not be a position if they have no balance");
            assert!(locked_amount.amount().msats <= current_balance);

            db::set(
                dbtx,
                &db::AccountBalanceKey(account_id),
                &AccountBalance {
                    unlocked: fedimint_api::msats(current_balance - locked_amount.amount().msats),
                    locked: locked_amount,
                },
            )
            .await;

            match locked_amount {
                LockedBalance::Seeker(a) => total_seeker_locked += a.msats,
                LockedBalance::Provider(a) => total_provider_locked += a.msats,
                LockedBalance::None => unreachable!("this is not possible"),
            }
        }

        // START EPOCH
        db::set(
            dbtx,
            &db::EpochOutcomeKey(epoch_end_id + 1),
            &EpochOutcome {
                feerate,
                settled_price: None,
                total_seeker_locked,
                total_provider_locked,
            },
        )
        .await;
    }

    ConsensusItemOutcome::Applied
}

/// Calculate payouts from this epoch's positions and unlock these payouts into unlocked balance
/// We need to store the Seekers' unlocked balance for them to relock in the next epoch.
async fn settle_locked_balances(
    dbtx: &mut DatabaseTransaction<'_>,
    epoch_id: u64,
    epoch_outcome: EpochOutcome,
) -> BTreeMap<XOnlyPublicKey, u64> {
    let prev_epoch_id = match epoch_id.checked_sub(1) {
        Some(prev_epoch_id) => prev_epoch_id,
        // there is no previous epoch, so no start_price and nothing to settle
        None => return BTreeMap::new(),
    };

    // we need the price of previous epoch (start price)
    let prev_epoch_outcome = db::get(dbtx, &db::EpochOutcomeKey(prev_epoch_id))
        .await
        .expect("previous epoch outcome must exist");
    let start_price = prev_epoch_outcome
        .settled_price
        .expect("previous epoch outcome must have a settled price");

    // get end_price and and feerate from epoch outcome
    let feerate = epoch_outcome.feerate;
    let end_price = epoch_outcome
        .settled_price
        .expect("price must be settled to settle locked balances");

    // inputs for core algorithm (maps of locked balances by account id)
    let mut seeker_entries = BTreeMap::new();
    let mut provider_entries = BTreeMap::new();

    // we need to know the positions for seekers and providers using their locked balance
    db::prefix_entries(dbtx, &db::AccountBalanceKeyPrefix)
        .await
        .for_each(|(key, account)| {
            let account_id = key.0;
            if account.locked.amount().msats > 0 {
                match account.locked {
                    LockedBalance::Seeker(a) => seeker_entries.insert(account_id, a.msats),
                    LockedBalance::Provider(a) => provider_entries.insert(account_id, a.msats),
                    LockedBalance::None => unreachable!("amount must be greater than 0"),
                };
            }
        });

    // calculate payouts from account positions (entries) and price change
    let (seeker_payouts, provider_payouts) = stability_core::calculate_payouts(
        feerate,
        seeker_entries,
        provider_entries,
        start_price,
        end_price,
    );

    // withdraw payout from lockbox into unlocked balance
    for (account_id, payout_amount) in seeker_payouts.iter().chain(provider_payouts.iter()) {
        let db_key = db::AccountBalanceKey(*account_id);
        let old_balance = db::get(dbtx, &db_key).await.unwrap_or_default();
        let new_balance = AccountBalance {
            locked: LockedBalance::None,
            unlocked: old_balance.unlocked + fedimint_api::msats(*payout_amount),
        };
        db::set(dbtx, &db_key, &new_balance).await;
    }

    seeker_payouts
}
