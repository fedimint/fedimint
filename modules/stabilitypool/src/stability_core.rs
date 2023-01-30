use std::collections::BTreeMap;

use fedimint_api::encoding::{Decodable, Encodable};
use secp256k1_zkp::XOnlyPublicKey;

use crate::action::{self, Action, SeekerAction};

/// Provider feerates are in parts per million
type FeeratePPM = u64;
/// Internal feerate unit is kept very high resolution to avoid precision losses.
const FEERATE_UNIT_DENOMINATOR: u64 = 1_000_000_000_000_000_000;
const PPM_TO_INTERNAL: u64 = FEERATE_UNIT_DENOMINATOR / 1_000_000;

/// Feerate for the epoch. Internally it is much higher resolution than the feerate that providers
/// use.
#[derive(
    Clone,
    Debug,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    Encodable,
    Decodable,
    Ord,
    PartialOrd,
)]
pub struct EpochFeerate(u64);

impl EpochFeerate {
    pub fn zero() -> Self {
        Self(0)
    }

    /// Approximate feerate in parts per million
    pub fn approx_ppm_feerate(&self) -> u64 {
        self.0 / PPM_TO_INTERNAL
    }

    /// Convert a parts per million feerate to an epoch feerate
    pub fn from_ppm_feerate(rate: FeeratePPM) -> Self {
        Self(rate * PPM_TO_INTERNAL)
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq)]
pub struct SeekerLock {
    /// The seeker's account id
    pub account_id: XOnlyPublicKey,
    /// The value the seeker wants to lock in. This may be partially filled.
    pub value: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderBid {
    /// The minimum feerate that this provider will accept
    pub min_feerate: u64,
    /// The maximum that can be locked at this feerate from this provider
    pub max_value: u64,
    /// The account id of the provider
    pub account_id: XOnlyPublicKey,
}

/// Ratio of seeker position to provider collateral.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, Encodable)]
pub struct CollateralRatio {
    pub seeker: u8,
    pub provider: u8,
}

impl CollateralRatio {
    /// The collateral needed to satisfy `position`.
    pub fn collateral_for_provider_position(&self, position: u64) -> u64 {
        ceiling_div(
            position as u128 * self.provider as u128,
            self.seeker as u128,
        )
        .expect("collateral for position is ridiculously high")
    }
    /// The amount long position a provider gets with `collateral`.
    pub fn position_for_provider_collateral(&self, collateral: u64) -> u64 {
        (collateral as u128 * self.seeker as u128 / self.provider as u128) as u64
    }

    /// How low does end_price/start_price have to go before the provider collateral is no longer
    /// sufficient.
    ///
    /// ```
    /// use stabilitypool::stability_core::CollateralRatio;
    /// assert_eq!(CollateralRatio { seeker: 1, provider: 1 }.seeker_protection_threshold(), 0.50);
    /// assert_eq!(CollateralRatio { seeker: 1, provider: 3 }.seeker_protection_threshold(), 0.25);
    /// assert_eq!(CollateralRatio { seeker: 3, provider: 2 }.seeker_protection_threshold(), 0.60);
    /// ```
    pub fn seeker_protection_threshold(&self) -> f64 {
        self.seeker as f64 / (self.provider as f64 + self.seeker as f64)
    }

    /// Whether the drop in price is big enough to mean provider collateral is no longer sufficient
    pub fn does_price_change_break_protection_threshold(
        &self,
        start_price: u64,
        end_price: u64,
    ) -> bool {
        (end_price as f64 / start_price as f64) < self.seeker_protection_threshold()
    }

    pub fn provider_leverage(&self) -> f64 {
        self.provider as f64 / (self.seeker + self.provider) as f64
    }
}

impl Default for CollateralRatio {
    fn default() -> Self {
        Self {
            seeker: 1,
            provider: 1,
        }
    }
}

fn ceiling_div(numerator: u128, denominator: u128) -> Option<u64> {
    u64::try_from((numerator + denominator - 1).checked_div(denominator)?).ok()
}

/// Compute desired positions using available balance (all unlocked), actions, prev. seeker payouts
///
/// # Returns
///
/// A tuple containing valid [`SeekerLock`]s and [`ProviderBid`]s that are not yet matched
pub fn compute_desired_positions(
    available_balances: &BTreeMap<XOnlyPublicKey, u64>,
    previous_seeker_payouts: BTreeMap<XOnlyPublicKey, u64>,
    seeker_actions: Vec<Action<action::SeekerAction>>,
    provider_actions: Vec<Action<action::ProviderBid>>,
) -> (
    impl Iterator<Item = SeekerLock> + '_,
    impl Iterator<Item = ProviderBid> + '_,
) {
    let mut seeker_locks: BTreeMap<_, _> = previous_seeker_payouts
        .into_iter()
        .map(|(account_id, payout)| {
            (
                account_id,
                SeekerLock {
                    account_id,
                    value: payout,
                },
            )
        })
        .collect();

    // lock or unlock seeker balances using any new actions
    for action in seeker_actions.iter() {
        match action.body {
            SeekerAction::Lock { amount } => {
                seeker_locks
                    .entry(action.account_id)
                    .and_modify(|seeker_lock| seeker_lock.value += amount.msats)
                    .or_insert(SeekerLock {
                        account_id: action.account_id,
                        value: amount.msats,
                    });
            }
            SeekerAction::Unlock { amount } => {
                seeker_locks
                    .entry(action.account_id)
                    .and_modify(|seeker_lock| {
                        seeker_lock.value = seeker_lock.value.saturating_sub(amount.msats)
                    });
            }
        }
    }

    for (account_id, seeker_lock) in &mut seeker_locks {
        seeker_lock.value = seeker_lock
            .value
            .min(*available_balances.get(account_id).unwrap_or(&0));
    }
    seeker_locks.retain(|_, seeker_lock| seeker_lock.value > 0);

    let provider_bids = provider_actions.into_iter().filter_map(|action| {
        let current_balance = *available_balances.get(&action.account_id)?;
        let bid_amount = action.body.max_amount.msats.min(current_balance);

        if bid_amount == 0 {
            None
        } else {
            Some(ProviderBid {
                min_feerate: action.body.min_feerate,
                max_value: bid_amount,
                account_id: action.account_id,
            })
        }
    });

    (seeker_locks.into_values(), provider_bids)
}

const TOTAL_MSAT: u64 = 21_000_000 * 100_000_000 * 1_000;
pub const MAX_TOTAL_SEEKER_VALUE: u64 = TOTAL_MSAT / 10;

/// Determines the feerate and who is included in the pool.
///
/// Arguments:
/// - `seeker_locks`: The seeker's desired short positions
/// - `provider_bids`: The provider's desired long position collateral with feerate required to include them.
/// - `pool_ratio`: The ratio between seeker position and provider collateral.
///
/// # Returns
///
/// The final feerate as well as BTreeMaps for filled postitions of seekers and providers.
/// Note we return `BTreeMap`s rather than `HashMap`s rather than
///
/// # Algorithm overview
///
/// The algorithm attempts to find that lowest feerate that will include enough providers collateral
/// to cover all the seeker's desired short positions. It starts with the lowest feerate provider
/// and incrementally increases the feerate until it has a large enough pool of collateral to
/// satisfy the stability seekers. It may partially use some of the collateral of the marginal
/// provider.
///
/// In the case where the algorithm cannot match all the desired seeker short positions with
/// provider long positions it will exclude some seekers by not including them in the epoch or only
/// partially including them.
pub fn match_locks_and_bids(
    mut seeker_locks: Vec<SeekerLock>,
    mut provider_bids: Vec<ProviderBid>,
    pool_ratio: CollateralRatio,
) -> (
    EpochFeerate,
    BTreeMap<XOnlyPublicKey, u64>,
    BTreeMap<XOnlyPublicKey, u64>,
) {
    provider_bids.retain(|bid| bid.max_value > 0);
    provider_bids.sort();
    let mut total_seeker_demand = 0u64;
    seeker_locks.retain(|lock| {
        if lock.value == 0 ||
            // We need to ignore seeker locks after we've already got a ridiculously large amount
            // seeker value to avoid overlflows later on.
            total_seeker_demand.saturating_add(lock.value) > MAX_TOTAL_SEEKER_VALUE
        {
            return false;
        }
        total_seeker_demand += lock.value;
        true
    });
    let mut provider_bids = provider_bids.into_iter();

    // we use BTreeMaps to avoid randomness of HashMaps
    let mut provider_entries = BTreeMap::<_, _>::default();
    let mut seeker_entries = BTreeMap::<_, _>::default();

    let mut selected_provider_collateral: u64 = 0;
    let mut current_feerate = EpochFeerate(0);
    let mut marginal_provider: Option<ProviderBid> = None;
    let feerate = loop {
        // in this loop we're trying our best to match all the seeker position so we calculate it in
        // each iteration with the feerate that is increasing with each iteration.
        let total_seeker_position = seeker_position(current_feerate, total_seeker_demand);
        let collateral_needed = pool_ratio.collateral_for_provider_position(total_seeker_position);
        let collateral_excess = selected_provider_collateral as i128 - collateral_needed as i128;

        if collateral_excess >= 0 {
            // We've selected enough providers to cover all seekers -- but perhaps too much!
            if let Some(provider) = &marginal_provider {
                // We need to adjust down the marginal provider's position so we have the right
                // amount on both sides of the pool.
                let prev = provider_entries.insert(
                    provider.account_id,
                    provider.max_value - collateral_excess as u64,
                );
                debug_assert_eq!(prev, Some(provider.max_value));
            } else {
                // We can only get here if there are no seekers because otherwise we'd have selected
                // a provider to cover the seeker's value.
                debug_assert_eq!(seeker_locks.len(), 0);
            };
            break current_feerate;
        }

        // We still do not have enough provider supply, let's figure out if it is worth including a
        // new one. What feerate is required to meet our target with current provider collateral? We
        // call this the "draining feerate" and we'll compare this to the next provider's fee rate.
        let draining_feerate = {
            let provider_position =
                pool_ratio.position_for_provider_collateral(selected_provider_collateral);
            let missing_without_fee = total_seeker_demand - provider_position;

            ceiling_div(
                missing_without_fee as u128 * FEERATE_UNIT_DENOMINATOR as u128,
                provider_position as u128,
            )
            .map(EpochFeerate)
        };

        match provider_bids.next() {
            Some(provider) => {
                debug_assert!(
                    match marginal_provider {
                        Some(marginal_provider) =>
                            provider.min_feerate >= marginal_provider.min_feerate,
                        None => true,
                    },
                    "providers are sorted in ascending min_feerate"
                );
                let provider_feerate = EpochFeerate::from_ppm_feerate(provider.min_feerate);

                let should_use_next_provider = match draining_feerate {
                    Some(_) => provider_feerate < draining_feerate.unwrap(),
                    None => true,
                };
                if should_use_next_provider {
                    // This provider has a lower feerate than the draining feerate so it's better to
                    // use them. First we assume we take all the value from this provider, removing
                    // any excess we don't need in the next iteration (provider_excess).
                    selected_provider_collateral += provider.max_value;
                    provider_entries.insert(provider.account_id, provider.max_value);
                    current_feerate = EpochFeerate::from_ppm_feerate(provider.min_feerate);
                    marginal_provider = Some(provider);
                } else {
                    // The draining feerate is better than using the next provider.
                    break draining_feerate.expect("draining_feerate can't be None here");
                }
            }
            // If there are no more providers we just use the feerate that gives us all the provider funds
            None => {
                break current_feerate;
            }
        }
    };

    // We've selected our providers and feerate. It's time to figure out which seekers are going to
    // make it in.
    //
    // First we need to know the total fee the provider's we've selected will charge.
    let total_fee = provider_fee(feerate, selected_provider_collateral, pool_ratio);
    // The total value we will lock from the seekers is the provider position + total fee.
    let mut seeker_locked_remaining =
        pool_ratio.position_for_provider_collateral(selected_provider_collateral) + total_fee;

    for seeker in seeker_locks.iter() {
        let locked_value = seeker_locked_remaining.min(seeker.value);
        if locked_value != 0 {
            seeker_locked_remaining -= locked_value;
            seeker_entries.insert(seeker.account_id, locked_value);
        } else {
            break;
        }
    }

    (feerate, seeker_entries, provider_entries)
}

/// Calculate the payouts from the entries into the lockbox using the start and end prices of the
/// epoch. Payouts are not *profits* they are simply what is returned to that account from the pool.
/// This is called with the output of [`epoch_start`] and the `start_price` and `end_price` of the
/// epoch.
///
/// The key thing this function is trying to ensure is that the values returned for seekers have the
/// same value in the stability asset at `end_price` as the their entry in `seeker_entries` had at
/// `start_price`. The providers will simply take the rest of the msats in the pool after this is
/// done along with their fee.
///
/// If `end_price / start_price` is so low it breaks seeker's protection threshold then the seekers
/// will get the entire pool value however the providers will still get their fee.
///
/// Note carefully that you do not need to pass in a [`CollateralRatio`] here since it is implied by
/// the relative total values of `seeker_entries` and `provider_entries`.
///
/// # Returns
///
/// A tuple of BTreeMaps containing seeker and provider payouts respectively
///
/// # Precision
///
/// The payouts are not directly calculated according to the [`provider_payout`] and
/// [`seeker_payout`] functions and there may be some tiny discrepancy between them (see the proptests tests
/// for how we ensure the discrepancy is strictly bounded).
pub fn calculate_payouts(
    feerate: EpochFeerate,
    seeker_entries: BTreeMap<XOnlyPublicKey, u64>,
    provider_entries: BTreeMap<XOnlyPublicKey, u64>,
    start_price: u64,
    end_price: u64,
) -> (BTreeMap<XOnlyPublicKey, u64>, BTreeMap<XOnlyPublicKey, u64>) {
    let mut seeker_payouts = BTreeMap::<_, _>::default();
    let mut provider_payouts = BTreeMap::<_, _>::default();
    let total_provider_locked: u64 = provider_entries.values().sum();
    let total_seeker_locked: u64 = seeker_entries.values().sum();
    let total_pooled_amount = total_provider_locked + total_seeker_locked;
    let total_fee = seeker_fee(feerate, total_seeker_locked);
    let total_seeker_position = total_seeker_locked - total_fee;
    let pnl = pnl_for_price(-(total_seeker_position as i64), start_price, end_price);
    // We pay the seekers back their locked msats + pnl (which may be negative) from the price change.
    let total_seeker_payout = (total_seeker_position as i64).saturating_add(pnl) as u64;
    // We can't pay the seekers more than what's in the pool
    let total_seeker_payout = total_seeker_payout.min(total_pooled_amount - total_fee);
    // We give providers whatever is left after the seekers have gotten paid so we always pay out
    // everything that went in.
    let total_provider_payout = total_pooled_amount - total_seeker_payout;

    // Now that we've got total payouts for seekers and providers we just distribute the coins to
    // each account according to their share of the pool.
    for (locked_amounts, payouts, total_locked, total_payout) in [
        (
            provider_entries,
            &mut provider_payouts,
            total_provider_locked,
            total_provider_payout,
        ),
        (
            seeker_entries,
            &mut seeker_payouts,
            total_seeker_locked,
            total_seeker_payout,
        ),
    ] {
        let mut remaining = total_payout;
        for (id, locked_amount) in locked_amounts.into_iter() {
            // pay them in proportion to locked_amount / total_locked
            let payout =
                (total_payout as u128 * locked_amount as u128 / total_locked as u128) as u64;

            remaining = remaining
                .checked_sub(payout)
                .expect("we're paying out more than we can");
            payouts.insert(id, payout);
        }

        // The total payouts may not add up to all that is owed to them due to rounding errors. The
        // rounding error is at most 1 msat per provider/seeker. We distribute 1msat to the users
        // until we run out. Note this slightly unfairly advantages those we are first in the list
        // (since they gain an extra msat!).
        assert!(remaining <= payouts.len() as u64);
        for value in payouts.values_mut() {
            if remaining == 0 {
                break;
            }
            *value += 1;
            remaining -= 1;
        }
    }

    // XXX: Assert that incoming value is precisely equal to outgoing value so we guarantee no inflation!
    {
        let final_seeker_payout = seeker_payouts.values().sum::<u64>();
        let final_provider_payout = provider_payouts.values().sum::<u64>();

        assert_eq!(
            total_provider_locked + total_seeker_locked,
            final_seeker_payout + final_provider_payout
        )
    }

    (seeker_payouts, provider_payouts)
}

/// The fee the seeker is going to pay to lock `locked_value`
pub fn seeker_fee(feerate: EpochFeerate, locked_value: u64) -> u64 {
    let feerate = feerate.0;
    // NOTE: the formula here is derived from
    // 1. fee = feerate * position
    // 2. position = locked_value - fee
    ((locked_value as u128 * feerate as u128)
        / (FEERATE_UNIT_DENOMINATOR as u128 + feerate as u128)) as u64
}

/// The short position in msats for the seeker after locking in `locked_value` (and paying the fee
/// on it).
pub fn seeker_position(feerate: EpochFeerate, locked_value: u64) -> u64 {
    locked_value - seeker_fee(feerate, locked_value)
}

/// The fee the provider will receive for locking in `locked_value`. The fee is paid per point of
/// position so we need to know the collateral `ratio`.
pub fn provider_fee(feerate: EpochFeerate, locked_value: u64, ratio: CollateralRatio) -> u64 {
    let feerate = feerate.0;
    let position = ratio.position_for_provider_collateral(locked_value);
    ((position as u128 * feerate as u128) / FEERATE_UNIT_DENOMINATOR as u128) as u64
}

/// The payout in msats (not including fee) for a provider who locked in `locked_value` into an
/// epoch with a certain price change.
pub fn provider_price_payout(
    locked_value: u64,
    start_price: u64,
    end_price: u64,
    ratio: CollateralRatio,
) -> u64 {
    let position = ratio.position_for_provider_collateral(locked_value);
    let pnl = pnl_for_price(position as i64, start_price, end_price);
    let payout = locked_value as i64 + pnl;
    if payout < 0 {
        0
    } else {
        payout as u64
    }
}

/// The payout in msats for a provider who locked in `locked_value` into an
/// epoch with a certain price change.
pub fn provider_payout(
    locked_value: u64,
    feerate: EpochFeerate,
    start_price: u64,
    end_price: u64,
    ratio: CollateralRatio,
) -> u64 {
    let fee = provider_fee(feerate, locked_value, ratio);
    let price_payout = provider_price_payout(locked_value, start_price, end_price, ratio);
    fee + price_payout
}

/// The payout in msats for a seeker who locked in `locked_value` into an
/// epoch with a certain price change.
pub fn seeker_payout(
    locked_value: u64,
    feerate: EpochFeerate,
    start_price: u64,
    end_price: u64,
    ratio: CollateralRatio,
) -> u64 {
    let position = seeker_position(feerate, locked_value);
    let pnl = pnl_for_price(-(position as i64), start_price, end_price);
    let max_payout = position + ratio.collateral_for_provider_position(position);
    ((position as i64).saturating_add(pnl) as u64).min(max_payout)
}

/// The profit/loss in msats. Note that providers have a positive `position` while seekers always
/// have a negative `position`.
pub fn pnl_for_price(position: i64, start_price: u64, end_price: u64) -> i64 {
    if end_price == 0 {
        return if position < 0 { i64::MAX } else { i64::MIN };
    }

    let pnl = position as i128 * (end_price as i128 - start_price as i128) / end_price as i128;

    if pnl > i64::MAX as i128 {
        i64::MAX
    } else if pnl < i64::MIN as i128 {
        i64::MIN
    } else {
        pnl as i64
    }
}

#[cfg(test)]
mod tests {
    use proptest::{
        prelude::*,
        test_runner::{RngAlgorithm, TestRng},
    };
    const HUNDRED_PERCENT_FEE: u64 = 1_000_000;

    use super::*;

    fn random_pubkey(rng: &mut impl RngCore) -> XOnlyPublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(rng);
        public_key.x_only_public_key().0
    }

    macro_rules! assert_almost_eq {
        ($lhs:expr, $rhs:expr, $fudge:expr) => {{
            let lhs = $lhs;
            let rhs = $rhs;
            let diff = rhs as i64 - lhs as i64;
            if !(lhs <= rhs && diff <= $fudge as i64) {
                panic!(
                    "{} ({}) should be equal or {} less than {} ({}) but the difference is {}",
                    stringify!($lhs),
                    lhs,
                    $fudge,
                    stringify!($rhs),
                    rhs,
                    rhs as i64 - lhs as i64
                );
            }
        }};
    }

    #[test]
    fn begin_exact_pair_match() {
        let seeker = SeekerLock {
            value: 10_000_000,
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let provider = ProviderBid {
            max_value: 11_000_000,
            min_feerate: HUNDRED_PERCENT_FEE / 10, // Should be a fee rate of 10%
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let (feerate, seeker_entries, provider_entries) = match_locks_and_bids(
            vec![seeker.clone()],
            vec![provider.clone()],
            CollateralRatio::default(),
        );
        assert_eq!(
            feerate,
            EpochFeerate::from_ppm_feerate(provider.min_feerate)
        );
        assert_eq!(seeker_entries.get(&seeker.account_id), Some(&10_000_000));
        let seeker_position = seeker_position(feerate, 10_000_000);
        let provider_position = *provider_entries.get(&provider.account_id).unwrap();
        assert_almost_eq!(seeker_position, provider_position, 1);
    }

    #[test]
    fn begin_no_seekers() {
        let provider = ProviderBid {
            max_value: 15_000_000,
            min_feerate: HUNDRED_PERCENT_FEE / 10, // A fee rate of 10%
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let (feerate, seeker_entries, provider_entries) =
            match_locks_and_bids(vec![], vec![provider.clone()], CollateralRatio::default());
        assert_eq!(feerate.0, 0);
        assert_eq!(provider_entries.len(), 0);
        assert_eq!(seeker_entries.len(), 0);
    }

    #[test]
    fn provider_with_zero_value_is_ignored() {
        let seeker = SeekerLock {
            value: 10_000_000,
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let provider = ProviderBid {
            max_value: 0,
            min_feerate: HUNDRED_PERCENT_FEE / 10, // A fee rate of 10%
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let (feerate, seeker_entries, provider_entries) =
            match_locks_and_bids(vec![seeker], vec![provider], CollateralRatio::default());
        assert_eq!(seeker_entries.len(), 0);
        assert_eq!(provider_entries.len(), 0);
        assert_eq!(feerate.0, 0);
    }

    #[test]
    fn begin_bigger_fee_than_min() {
        let seeker = SeekerLock {
            value: 11_000_000,
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let provider = ProviderBid {
            max_value: 10_000_000,
            min_feerate: HUNDRED_PERCENT_FEE / 100, // A fee rate of 1%
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let (feerate, _seeker_entries, _provider_entries) =
            match_locks_and_bids(vec![seeker], vec![provider], CollateralRatio::default());

        assert_eq!(feerate.approx_ppm_feerate(), HUNDRED_PERCENT_FEE / 100);
    }

    #[test]
    fn begin_two_providers_one_seeker() {
        let seeker = SeekerLock {
            value: 10_000_000,
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let providers = vec![
            ProviderBid {
                max_value: 5_000_000,
                min_feerate: HUNDRED_PERCENT_FEE / 10, // A fee rate of 10%
                account_id: random_pubkey(&mut rand::thread_rng()),
            },
            ProviderBid {
                max_value: 5_000_000,
                min_feerate: HUNDRED_PERCENT_FEE / 5, // A fee rate of 20%
                account_id: random_pubkey(&mut rand::thread_rng()),
            },
        ];

        let (feerate, seeker_entries, provider_entries) =
            match_locks_and_bids(vec![seeker], providers, CollateralRatio::default());

        assert_eq!(provider_entries.len(), 2);
        assert_eq!(seeker_entries.len(), 1);
        assert_eq!(feerate.approx_ppm_feerate(), HUNDRED_PERCENT_FEE / 5);
    }

    #[test]
    fn partial_fill_one_seeker() {
        let seekers = vec![
            SeekerLock {
                value: 10_000_000,
                account_id: random_pubkey(&mut rand::thread_rng()),
            },
            SeekerLock {
                value: 30_000_000,
                account_id: random_pubkey(&mut rand::thread_rng()),
            },
        ];

        let providers = vec![ProviderBid {
            max_value: 20_000_000,
            min_feerate: HUNDRED_PERCENT_FEE / 10, // A fee rate of 10%
            account_id: random_pubkey(&mut rand::thread_rng()),
        }];

        let (feerate, seeker_entries, provider_entries) =
            match_locks_and_bids(seekers.clone(), providers, CollateralRatio::default());

        assert_eq!(seeker_entries.len(), 2);
        assert_eq!(
            seeker_entries.get(&seekers[0].account_id),
            Some(&10_000_000)
        );
        assert_eq!(
            seeker_entries.get(&seekers[1].account_id),
            Some(&(12_000_000)),
            "fee is 10% and provider gives 20 million so total should be 22 million"
        );
        assert_eq!(provider_entries.len(), 1);
        assert_eq!(feerate.approx_ppm_feerate(), HUNDRED_PERCENT_FEE / 10);
    }

    #[test]
    fn end_just_fee() {
        let seeker = SeekerLock {
            value: 1_000,
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let provider = ProviderBid {
            max_value: 1_000,
            min_feerate: HUNDRED_PERCENT_FEE / 10, // Should be a fee rate of 10%
            account_id: random_pubkey(&mut rand::thread_rng()),
        };

        let (feerate, seeker_entries, provider_entries) = match_locks_and_bids(
            vec![seeker.clone()],
            vec![provider.clone()],
            CollateralRatio::default(),
        );
        let actual_seeker_lock = *seeker_entries.get(&seeker.account_id).unwrap();
        assert_eq!(actual_seeker_lock, 1_000);
        let actual_provider_lock = *provider_entries.get(&provider.account_id).unwrap();
        assert!(
            actual_seeker_lock.abs_diff(
                actual_provider_lock
                    + provider_fee(feerate, actual_provider_lock, CollateralRatio::default())
            ) <= 1
        );

        let start_price = 1_000_000;
        let end_price = 1_000_000;
        let (seeker_payouts, provider_payouts) = calculate_payouts(
            feerate,
            seeker_entries.clone().into_iter().collect(),
            provider_entries.clone().into_iter().collect(),
            start_price,
            end_price,
        );
        let seeker_payout = *seeker_payouts.get(&seeker.account_id).unwrap();
        let provider_payout = *provider_payouts.get(&provider.account_id).unwrap();
        assert_almost_eq!(seeker_payout, 910, 1);
        assert_eq!(
            actual_provider_lock + actual_seeker_lock - seeker_payout - provider_payout,
            0
        );
    }

    #[test]
    fn end_providers_liqd() {
        let seeker_entries = vec![(random_pubkey(&mut rand::thread_rng()), 1_000_000)];
        let provider_entries = vec![(random_pubkey(&mut rand::thread_rng()), 1_000_000)];
        let feerate = EpochFeerate::from_ppm_feerate(0);
        let start_price = 2_000_000;
        let end_price = 1_000_000;
        let (seeker_payouts, provider_payouts) = calculate_payouts(
            feerate,
            seeker_entries.clone().into_iter().collect(),
            provider_entries.clone().into_iter().collect(),
            start_price,
            end_price,
        );

        let seeker_payouts = seeker_payouts.get(&seeker_entries[0].0).unwrap();
        let provider_payouts = provider_payouts.get(&provider_entries[0].0).unwrap();

        assert_eq!(*seeker_payouts, seeker_entries[0].1 + provider_entries[0].1);
        assert_eq!(*provider_payouts, 0);
    }

    // This enforces that the payouts are
    fn test_guarantees(
        seekers: Vec<SeekerLock>,
        providers: Vec<ProviderBid>,
        start_price: u64,
        end_price: u64,
        pool_ratio: CollateralRatio,
        fudge_msat: u64,
    ) {
        let start_price_msat = start_price * 100_000_000_000;
        let end_price_msat = end_price * 100_000_000_000;
        let total_seeker_desired = seekers.iter().map(|seeker| seeker.value).sum::<u64>();
        let total_provider_desired = providers
            .iter()
            .map(|provider| provider.max_value)
            .sum::<u64>();

        let before_epoch_start = std::time::Instant::now();
        let (feerate, seeker_entries, provider_entries) =
            match_locks_and_bids(seekers, providers, pool_ratio);
        println!("epoch_start elapsed: {:?}", before_epoch_start.elapsed());

        let total_seeker_entered = seeker_entries.iter().map(|pos| pos.1).sum::<u64>();
        let total_provider_entered = provider_entries.iter().map(|pos| pos.1).sum::<u64>();
        if pool_ratio.position_for_provider_collateral(total_provider_desired)
            >= total_seeker_desired
            && total_seeker_desired < MAX_TOTAL_SEEKER_VALUE
        {
            // we should always cover all the seekers if we've got enough provider funds
            assert_eq!(
                total_seeker_entered, total_seeker_desired,
                "we should always cover all the seekers if we've got enough provider funds"
            );
        }

        let total_provider_position =
            pool_ratio.position_for_provider_collateral(total_provider_entered);
        let total_seeker_by_provider_fee =
            total_provider_position + provider_fee(feerate, total_provider_entered, pool_ratio);
        assert!(
            (total_seeker_entered).abs_diff(total_seeker_by_provider_fee) <= fudge_msat,
            "provider_fee calculation was {} off but we only allow {} deviation",
            total_seeker_entered as i64 - total_seeker_by_provider_fee as i64,
            fudge_msat
        );
        let total_seeker_by_seeker_fee =
            total_provider_position + seeker_fee(feerate, total_seeker_entered);
        assert!(
            total_seeker_entered.abs_diff(total_seeker_by_seeker_fee) <= fudge_msat,
            "seeker_fee calculation was {} off but we only allow {} deviation",
            total_seeker_entered as i64 - total_seeker_by_seeker_fee as i64,
            fudge_msat
        );

        let before_epoch_end = std::time::Instant::now();
        let (seeker_payouts, provider_payouts) = calculate_payouts(
            feerate,
            seeker_entries.clone(),
            provider_entries.clone(),
            start_price_msat,
            end_price_msat,
        );
        println!("epoch_end elapsed: {:?}", before_epoch_end.elapsed());

        let total_seeker_payedout: u64 = seeker_payouts.iter().map(|payout| payout.1).sum();
        let total_provider_payedout: u64 = provider_payouts.iter().map(|payout| payout.1).sum();
        assert_eq!(
            total_provider_payedout + total_seeker_payedout,
            total_seeker_entered + total_provider_entered,
            "The amounts paid out equal the amounts put in"
        );

        assert_eq!(seeker_entries.len(), seeker_payouts.len());
        assert_eq!(provider_entries.len(), provider_payouts.len());
        for (i, (seeker, payout)) in seeker_payouts.into_iter().enumerate() {
            let locked = *seeker_entries.get(&seeker).unwrap();
            let pos = seeker_position(feerate, locked);
            if !pool_ratio.does_price_change_break_protection_threshold(start_price, end_price) {
                let start_usd_hundredth = (pos as u128 * start_price as u128) / 10_000_000u128;
                let end_usd_hundredth = (payout as u128 * end_price as u128) / 10_000_000u128;
                let hundredth_cents_diff = start_usd_hundredth.abs_diff(end_usd_hundredth);
                assert!(
                    hundredth_cents_diff <= 1,
                    "our tolerance is one hundredth of a cent"
                );
            }
            let expected_payout =
                seeker_payout(locked, feerate, start_price, end_price, pool_ratio);
            let diff_to_expected = payout.abs_diff(expected_payout);
            assert!(
                diff_to_expected <= fudge_msat,
                "our error tolerance is {} msats but error was {} for seeker {}",
                fudge_msat,
                payout as i64 - expected_payout as i64,
                i
            );
        }

        for (i, (provider, payout)) in provider_payouts.into_iter().enumerate() {
            let locked = *provider_entries.get(&provider).unwrap();
            let expected_payout =
                provider_payout(locked, feerate, start_price, end_price, pool_ratio);
            let diff_to_expected = payout.abs_diff(expected_payout);
            assert!(
                diff_to_expected <= fudge_msat,
                "our error tolerance is {} msats but error was {} for the provider {}",
                fudge_msat,
                payout as i64 - expected_payout as i64,
                i
            );
        }
    }

    const TEST_PARTICIPANTS: usize = 100_000;

    lazy_static::lazy_static! {
        static ref CACHED_TEST_DATA: (Vec<SeekerLock>, Vec<ProviderBid>) = {
            let mut remaining_msat = TOTAL_MSAT;
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
            (0..TEST_PARTICIPANTS).map(|_| {
                (
                    {
                        let value = rng.gen_range(0..(remaining_msat / 1000 + 1));
                        remaining_msat -= value;
                        SeekerLock {
                            account_id:random_pubkey(&mut rng),
                            value
                        }

                    },
                    {
                        let value = rng.gen_range(0..(remaining_msat/1000 + 1) );
                        remaining_msat -= value;
                        ProviderBid {
                            account_id:random_pubkey(&mut rng),
                            max_value: value,
                            min_feerate: rng.gen_range(0..HUNDRED_PERCENT_FEE)
                        }
                    }
                )
            }).unzip()
        };
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        #[test]
        fn one_to_one_proptest(
            n_seekers in 0usize..TEST_PARTICIPANTS,
            n_providers in 0usize..TEST_PARTICIPANTS,
            start_price in 1_000_u64..1_000_000,
            // price change as a percentage of start price
            price_change in -100i64..300,
        ) {
            let pool_ratio = CollateralRatio {
                seeker: 1,
                provider: 1
            };
            let end_price = (start_price as i64 + (start_price as i64 * price_change / 100)) as u64;
            let seekers = CACHED_TEST_DATA.0.iter().cloned().take(n_seekers).collect();
            let providers = CACHED_TEST_DATA.1.iter().cloned().take(n_providers).collect();

            test_guarantees(seekers, providers, start_price, end_price, pool_ratio, 2);
        }

        #[test]
        fn varying_ratio_proptest(
            n_seekers in 0usize..TEST_PARTICIPANTS,
            n_providers in 0usize..TEST_PARTICIPANTS,
            start_price in 1_000_u64..1_000_000,
            // price change as a percentage of start price
            price_change in -100i64..300,
            pool_ratio in ((1u8..10), (1u8..10))
        ) {
            let pool_ratio = CollateralRatio {
                seeker: pool_ratio.0,
                provider: pool_ratio.1,
            };
            let end_price = (start_price as i64 + (start_price as i64 * price_change / 100)) as u64;

            let seekers = CACHED_TEST_DATA.0.iter().cloned().take(n_seekers).collect();
            let providers = CACHED_TEST_DATA.1.iter().cloned().take(n_providers).collect();
            // NOTE: Errors are larger with more drastic leverage ratios -- this is an empirically discovered bound
            let fudge = pool_ratio.seeker.max(pool_ratio.provider) as u64 * 2;
            test_guarantees(seekers, providers, start_price, end_price, pool_ratio, fudge);
        }
    }
}
