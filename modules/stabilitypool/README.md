# Fedimint Stability Pool

This module adds "stability pool" functionality to Fedimint. The stability pool allows users to "lock" in the US dollar value of their ecash for a fee. This feature is targeted towards users who are not willing to tolerate bitcoin's price volatility, but still wish to utilize Fedimint and the wider Bitcoin financial system. Examples could include a shop owner who has fixed costs purchasing stock that is denominated in USD, or an unbanked individual living within a developing nation who desires stability and not Bitcoin exposure.

Users who want a constant dollar value are referred to as stability `Seekers`, who will be matched with stability `Providers`.

Under normal working conditions, seekers can expect to maintain the US dollar value of their ecash minus some fee which is paid periodically to providers as a charge for this service.

## Overview

Stability seekers place requests for `Stability Locks` with some amount of ecash they want to lock. Stability providers place `Provider Bids` to take the other side of these locks, containing a maximum amount and some minimum fee rate (parts per million) they are willing to provide at.

The stability works through hedging, where stability seekers are going 1x short bitcoin and the stability providers are going long to take the other side. In both cases, bitcoin is the collateral they offer to take on these positions. The collateral seekers put up is always equal to their position but the collateral providers put up is a configurable parameter.

By hedging their bitcoin position, stability seekers will maintain the US dollar value of their locked amount.

These positions expire at the end of each period, called an `Epoch`. At the end of each epoch, stability seekers have their positions rolled over into the next epoch so their balance continues to maintain US dollar value (unless they request to `Unlock` their locked balance). Similarly, providers' bids are also re-entered for the next stability epoch's matchmaking unless they are withdrawn.

### Example scenario:

```
Imagine the bitcoin price is 20k, and a seeker locks 1.01 BTC against a provider's 1 BTC at 1% fee rate. The seeker will have a 1 BTC position locked that is worth 20k USD, and with a 1:1 collateralization (see below) this position is matched by a 1 BTC on provider bid. The provider receives their 0.01BTC fee.

Then imagine the price moves from 20k to 40K during this stability epoch. At the end of the epoch, the seeker's locked balance balance will be 0.5BTC, which is still worth the same as the 20k USD position they locked initially.

The provider on the other hand, will receive 1 + 0.5 BTC which is worth 1 * 40k + 0.5 * 40k = 60k. I.e. their collateral value increased from 20k to 40k, and their USD PnL from the position is 0.5x40k = 20k (since they were 1x long and price doubled -> +100% profit on the position)
```

### Usage

We have created new Fedimint command line interfaces, called with:

```
fedimint-cli pool <SUBCOMMAND>
```

A user can deposit their ecash into their pool account:

```
fedimint-cli pool deposit <AMOUNT>
```

Then request to lock this balance as a seeker:

```
fedimint-cli pool action seeker-lock <AMOUNT>
```

We can place a bid as a provider (using a second fedimint user session), with a feerate in parts per million. e.g. `1000` is `0.1%`.
The `<AMOUNT>` value is the maximum collateral they are willing to enter into the stability pool.

```
fedimint-cli pool action provider-bid <FEERATE> <AMOUNT>
```

Depending on the set collateralization ratio, this provider bid amount will be greater than the maximum position and is not the maximum position itself (in a user friendly API this would probably be changed to the position they want to take, from which the collateral can be derived).

Then once the epoch has started and positions have been matched, you can check your locked balance:

```
fedimint-cli pool balance
```

### Provider Role

Stability providers are willing to increase their BTC/USD exposure for a fee. It is recommended that the provider role be taken on by more sophisticated users, ideally making use of automated trading systems that hedge their long position in order to remain market neutral and just collect fees.

Stability providers submit a minimum feerate at which they are willing to provide this service for, and seekers' orders are matched with the lowest fee providers first, providers should not be able to see the bidded feerates of others in order to maintain a silent auction.

## Risk & "Liquidation"

### Large BTCUSD price drop

It is possible for the bitcoin price to drop so drastically during an epoch such that the collateral posted by the providers is insufficient to entirely cover the stability seekers' expected payout. The payout from the epoch will be worth less than the expected locked USD value.

The failure point depends on the collateralization ratio of the stability providers, which in our design is a configurable constant for the pool. For example, if the providers provide an equal amount of collateral to seekers, then they are covered for up to a 50% price drop during a single epoch. It is crucial that seekers be made aware of the extent to which they are covered, though in actuality it may often be nice to become net-long BTC after such a drastic drop in price. With short enough epochs (e.g. 10 minute), 1:1 collateralization is likely sufficient. Though users may feel more comfortable when presented with statements like "balance is locked with coverage up to a 90% drawdown", rather than just 50%.

### Insufficient Stability Providers

If the mint cannot collect enough long positions from the providers to cover the short positions of the seekers, the mint will not fulfill new seeker lock requests and possibly also evict (by not rolling over) existing stability seekers in order to balance both sides of the pool.

In these scenarios it is also possible for providers to charge exorbinantly high fees to the seekers, hence there is a configurable `global max pool feerate` which should be chosen carefully.

## Price Oracle

At the end of an epoch, each federation guardian will fetch the current price of BTCUSD using the BXBT price on Bitmex. The guardians will come to consensus on this price after a threshold of agreement. If the API is down or consensus can not be reached in time, not only will the settlement of this epoch be delayed, but also bids and locks for future epochs will be rejected in order to prevent gaming of the system.

## Other Currencies and Derivatives

Note that the price endpoint can be changed to your liking, the most obvious use case being the ability to denominate stability in other BTC currency pairs. For example by changing to BTCXXX, instead of locking in USD value, the stability pool could lock in Argentine Peso value or South African Rand. We believe this module is extremely promising internationally, and in fighting the mission of banking the unbanked.

Furthermore, you can begin to make bitcoin collateralized derivatives on any exotic product you like, so long as you can find or create an appropriate price oracle. With this module you could make it possible for Fedimint users to trade anything, even SOYBEAN/BTC. This is an idea we are rather excited about.

## `stability_core`

A key contribution of this effort is a rust module `stability_core` which contains the implementation of core algorithms for running the stability pool as pure functions.
We use [`proptest`] testing framework to provide empirical guarantees on the correctness of the implementation.
This was a crucial investment since it is impossible to pay out precisely the correct value to each account as we cannot pay out a fraction of a millisatoshi. Every msat is accounted for.

We define payout error for an individual account by comparing the actual payout against the ideal payout function. We include the ideal functions in `stability_core` as well and use them on the client to give an indication of the current value of the position in the pool.

Currently we guarantee a less than 2 millisatoshis difference between the actual and ideal for a 1:1 pool. This guarantee is looser in pools with other leverage ratios where the guarantee is `2*max(seeker_ratio, provider_ratio)*` e.g for a 3:8 pool we guarantee the difference between ideal and expected payouts is less than `2 * 8 = 16` millisatoshis.

We provide these strong guarantees in the face of any or all of the following conditions:

1. Large price swings within a single epoch of -%100 (Bitcoin price going to 0) to +%300
2. Hundreds of thousands of seekers and providers
3. collateral ratios from (1:10, to 10:1)
4. Millions of BTC in the pool

## Notes for developers and pool operators

### Seeker priority

The ordering of seekers when passed to `stability_core::match_locks_and_bids` is important because it determines who will be included and who will be excluded if there is not enough provider collateral to cover them. Currently the ordering is incidental but this should probably be changed so they are ordered by oldest (highest priority) to most recent (lowest priority). This would mean that the longer you've been a seeker in the pool the less likely you are to be removed from the pool due to insufficient provider funds.

### Account pool history is not stored on server

In order to understand their current state clients are limited to viewing:

- Their position in the current epoch (locked and unlocked balance).
- Their staged action for the next epoch
- The price history for all completed epochs

In order to provide an account history feature so the user can better understand how they got to their current balance they will have to check their position during every epoch.

It is possible that this information may be stored by the mint for them so they can retrieve it even when they are offline for a whole epoch, however storing this forever could be a privacy issue.

### No denial of service protection

Currently, there is no real limit on the actions that seekers and providers can take. It is possible to create an account with only 1 msat and make a bid or lock with 1 msat. In practice this needs to be limited in one or all of the following ways before running this code in production:

1. Actions in the pool should require paying a small fee to the mint
2. There should be limits on the smallest possible seeker lock or provider bid e.g. 100_000 msast

### Pool fees always go to the providers

In market conditions where leveraged long positions are highly desired the provider fee falls to 0.
It may be advantageous to allow this to go negative so that providers pay seekers.
Note it is not necessary that the seekers receive the funds from the negative feerate directly.
They could instead go into a bailout fund to buffer against large falls or be used to smooth out the feerate when the feerate goes higher again.

[`proptest`]: https://altsysrq.github.io/proptest-book/intro.html
