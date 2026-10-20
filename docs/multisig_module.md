# Multisig module: plan

A proposal for a Fedimint module that holds balances owned by k-of-n keys, and for the SDK API on top of it.

The product requirement is group-owned bitcoin inside a federation: a broker escrow where two of three people must agree before funds move. Fedi ships this today on top of the stability pool, which is the wrong substrate. This plan moves the primitive into Fedimint and leaves the SDK with the ceremony and the API.

## Naming

Fedi calls this feature "multispend". That word does not appear in Fedimint and should not: it is a product name, not a protocol concept.

Proposed module kind: `multisig`. Crates `fedimint-multisig-{common,server,client}`, plus `fedimint-multisig-tests`.

The one objection is that Fedimint's on-chain wallet is itself a federation multisig, so prose has to distinguish "the federation's multisig" from "a multisig account". No identifier collides, there is no `multisig` module kind today, and the alternative is coining a word nobody recognizes. `vault` is the fallback if the overload proves confusing in review. `escrow` is too narrow, since the module has no arbiter role.

## What exists today, and why it is the wrong substrate

Fedi's BTC multispend runs on stability pool v2, using it as a plain account ledger with BTC balances held out of cycle matching. It shipped in 26.10 behind the `btc_multispend` flag (fedibtc/fedi#12390).

Everything in that code that is hard is the fiat plumbing showing through. Transfers are fiat amounts converted at cycle-start prices, so encoding has to round-trip exactly. Submission needs a price-drift guard. Exact-msat withdrawal needed a consensus upgrade. All-sign groups need a MuSig2 aggregate key so they can withdraw exact sats while threshold groups settle on the fiat grid.

A sats-native module has none of those problems, because none of them are about group ownership. The stability pool exists to manufacture a fiat peg: price oracle feeding consensus, cycles, seeker and provider hedging. Drop fiat and the oracle, the cycles and the background consensus items all go, and with them the two objections raised against upstreaming the stability pool, that upstream has no fiat story and that a synthetic dollar carries legal exposure.

Approvals today ride Matrix, which makes a chat transport load-bearing for correctness. A module can verify k-of-n signatures directly, so Matrix drops back to what it is good at: notifications and presence.

## Target federations

The module targets federations running the second generation of the core modules, `mintv2`, `walletv2` and `lnv2`. It is not built to sit alongside a first-generation mint, wallet or lightning module.

Fedimint has no generation field. The split lives in the SDK, as a table of module kinds, and the newer federations are already second-generation with no older wallet or mint to accommodate.

## Units

No fiat, no peg, no oracle. That is what keeps the module small, and it is the whole argument for building it.

Not bitcoin-only in its types. Core already carries multi-unit amounts, the dummy module's input and output already name an `AmountUnit`, and the client already routes by unit. What makes that more than decoration is `mintv2`, whose config carries a unit, so a federation can hold something other than bitcoin and the module has a counterparty for a non-bitcoin balance. A first-generation mint is bitcoin-only, and against one the genericity would be dead code.

So the types stay unit-generic and no code path assumes bitcoin. The first release ships, tests and documents bitcoin.

## Design

### Accounts

An account is a balance with an ownership policy: a threshold `k` and `n` owner public keys, where `k = n = 1` is an ordinary single-owner account.

An account id is a hash of its policy plus a salt. Nothing creates an account. Funding one credits an id, and the policy is revealed to consensus the first time the account spends, when the module checks the hash and stores it.

That removes a creation operation and an entire class of "account not found" states, and it means a federation learns nothing about a group's membership until the group moves money.

### Three operations

**Fund.** A module output credits an account. Value comes from anywhere in the transaction, usually ecash notes. Anyone can fund any account.

**Transfer.** A module input moves value from one account to another inside the module. It carries the amount, the destination account, a sequence number, the owner signatures, a submitter key, and, on first spend, the policy. The module debits and credits in `process_input`, so the input reports zero value and the transaction needs no matching output.

The submitter key is there because core demands one. Every input reports exactly one public key and the transaction carries one signature for it, so the input names whoever is submitting and that person signs the transaction hash as usual. It carries no authority. The owner signatures are what authorize the spend, and they are checked against the policy, so it does not matter whether the submitter is an owner or a stranger.

**Withdraw.** A module input releases value from a single-owner account into the transaction, where it becomes ecash, a Lightning contract or a peg-out like any other input. Authorised by the ordinary transaction signature, with the account key as the input's public key.

A k-of-n account can only spend to another account in the module. A single-owner account can release value into a transaction. That split is forced, not chosen, and the next section is why.

### Why k-of-n cannot ride the transaction signature

Core authorizes one key per input. `InputMeta` returns a single `pub_key`, and `NaiveMultisig` verifies exactly one signature per input, in order. There is no slot for a second signer.

The obvious fix is to put the k signatures inside the input and have them sign the transaction id, which commits to every output. That does not work: the transaction id is computed over the encoded inputs, so signatures stored in an input would have to commit to themselves.

`verify_input_submission` is the other place a module could look at extra signatures. It is `#[doc(hidden)]`, documented as something most modules should not implement, and flagged for possible removal. It is also submission-only, not consensus, so it cannot be where money is authorized.

What is left is for the signatures to cover an explicit authorization message carried in the input, verified in `process_input`. That works, and it constrains the design: `process_input` sees the input and its input point, never the transaction's outputs. So the authorization can only bind to something the module itself controls. A destination account is such a thing. "Some outputs elsewhere in this transaction" is not.

Hence the split. If a k-of-n account could release value into a transaction, the submitter would choose the outputs alone, and one member could take the whole amount against a signature the others gave for something else. Transfer to a member's own account, then let that member withdraw, and every step is checked by the module.

A later version could let the authorization name a submitter, collapsing the two steps into one for a group that is happy to delegate. Not needed for the first release.

### Authorisation message

Signatures are plain Schnorr over a tagged hash of the account id, the sequence number, the amount, the unit and the destination. No MuSig2, no FROST, no ceremony, no DKG. Aggregate keys are only forced when a group has to look like one key, which is the moduleless ecash-notes design, not this one.

The tag matters. A bare transaction-id signature is exactly the message an ordinary input signature carries, so without domain separation an owner key reused as an account key could be replayed across the two.

Replay protection is a per-account sequence number, checked and incremented in `process_input`. The cost is that two proposals signed against the same sequence number conflict, and the loser has to be re-signed. For a shared account that is closer to the desired behavior than concurrent spends: the group authorizes one movement at a time and cannot over-commit its balance.

### What the module does not need

No DKG and no threshold secret. Guardians agree on state, they do not sign anything. Config generation is as empty as the dummy module's.

No consensus items and no background work. The module proposes nothing and wakes up for nothing. A guardian running it pays for storage and for verifying signatures on spends, and that is all.

No price feed, no cycles, no time dependence.

### Fees

Funding and withdrawal report fees from module config the ordinary way, defaulting to zero and settable by guardians. `mintv2`'s shape is the one to copy, a fixed base per input and output plus a relative rate in parts per million with a cap. Both also pay the mint's own note fees, because notes are reissued.

Transfers cannot work that way. A transfer input carries no value, and a transaction balances only when its inputs cover its outputs plus fees, so a fee declared the ordinary way would have to be paid by a second input, which means the submitter attaches ecash to move someone else's money. The first release should instead deduct the transfer fee from the source account inside `process_input`, which keeps a transfer a single input with no notes attached. Where a deducted fee goes is then the module's decision and needs settling in review.

Application-level fees stay an application concern.

### Recovery

Single-owner accounts are derivable from the seed, so a restored client can recompute its ids and ask the federation for balances.

Group accounts are not: the policy contains other people's keys. A restored client gets them back from its own client backup, which is where the client module should write its account policies, or from another member, since the policy is not secret within the group. An account that has never spent is invisible to the federation, so there is no third source. That gap is worth stating plainly in review rather than discovering later.

### Privacy

Guardians see account balances and every transfer, and they see group membership from the first spend onwards. Ecash does not work that way, and this module should not pretend otherwise.

This is not a regression against the stability pool, which has the same property, but it is a regression against holding the same funds as notes, and it belongs in the module's own documentation. Read `SECURITY.md` before settling the API endpoints, since "which accounts does this key own" is the kind of lookup that is convenient for recovery and bad for privacy.

## Open decisions

**Where approvals are collected.** The first release keeps signature collection off the federation: the client produces a proposal blob and a signature blob, and the application moves them over whatever transport it has. That is the smallest thing that can be upstreamed, and it has no pending state, no expiry, no garbage collection and no denial-of-service surface.

The alternative is worth a second consensus version, and is not a reason to hold the first: let members submit proposals and signatures to a module endpoint, have guardians carry them into consensus, and execute at threshold. That removes the transport problem entirely, which is the single biggest thing standing between this module and an SDK that is pleasant to use. It also adds client-submitted state to consensus, which is exactly the part upstream will push back on, so it should arrive with limits already designed: members only, a cap on open proposals per account, and expiry.

Decide the first release without it. Design the SDK API so it can be swapped in underneath without changing the surface.

**Mutable membership.** Adding or removing an owner changes the policy, which changes the account id. The first release should say so and require a transfer to a new account. Anything else needs a policy-update operation with its own threshold rules.

**Account id scheme.** Hash of policy and salt, as above, or explicit creation with a federation-assigned id. The hash version is better on privacy and smaller. Confirm it does not break the client's ability to enumerate its own accounts after restore.

## What lives where

The authorization hash is consensus-critical and lives in the common crate with the rest of the wire types.

The proposal and approval blobs are not consensus types, but they are interop types: a Fedi bridge client and an SDK client in the same group have to parse each other's. So they belong in `fedimint-multisig-client`, and the SDK re-exports them rather than defining its own.

That is the split. Consensus types, signature verification and the interop blob format go to Fedimint. Facade, operations, error mapping, bindings and examples go to the SDK.

## SDK layer

The SDK gets a facade, following the shape the others already have.

```rust
federation.multisig() -> Option<Multisig>

// Local. Derives the account id from the policy and touches no network.
multisig.account(policy: &Policy) -> Account

// What consensus holds: balance, sequence number, whether the policy is revealed.
multisig.state(&account) -> Result<AccountState>

multisig.deposit(&account, amount) -> Result<Operation<MultisigDepositState>>
multisig.propose(&account, amount, to: &AccountId) -> Result<SpendProposal>
multisig.sign(&proposal) -> Result<Approval>
multisig.execute(proposal, approvals) -> Result<Operation<MultisigSpendState>>
multisig.withdraw(&account, amount) -> Result<Operation<MultisigWithdrawState>>
```

`SpendProposal` and `Approval` serialize to bytes and parse back. The application carries them over Matrix, nostr, a QR code or a REST endpoint, and the SDK never learns which. If federation-collected approvals land later, `propose` and `sign` submit to the federation instead and `execute` becomes unnecessary, with no change to the types an application holds.

The rest is the usual wiring: a `Capabilities` flag so `multisig()` returns `None` on federations without the module, an entry in the module init registry, operation kinds and states, and uniffi exports so Kotlin, Swift and JavaScript get it for free.

`multisig` joins the SDK's generation table at generation two. The facade is then absent on a first-generation federation, and a configuration mixing the two stays refused the way it already is.

## Sequencing

The SDK requires every Fedimint crate at one exact version from crates.io, and CI checks that version against the release tag the flake builds devimint from. Development against an unreleased module moves both to a git revision instead, which preserves the property the check exists for: the client and the federation it is tested against come from one tree. Fedimint's crates require each other exactly, so that means all of them, and `pins-agree` asserts the `= "=<version>"` form, so it needs a revision branch or a skip while this work is in flight.

What a release gates is publishing, not development. crates.io takes no git dependencies, so the SDK crate and the packages generated from it ship only once a Fedimint release carries the module.

**1. Agree the shape upstream.** Open a design issue on fedimint/fedimint covering the account model, the authorization message, the two-tier spend rule and the units question. dpc has already said a multisig-like module handling any unit is reasonable, so this starts from agreement rather than from a cold pitch. Settle naming here too.

**2. Build the module.** Three crates on the dummy module's skeleton, plus a tests crate. Server: accounts, policy reveal, signature verification, sequence numbers, fees, db migrations. Client: account derivation, proposal and approval types, state machines for deposit, transfer and withdraw, backup of policies. Wire into `fedimintd`, the CLI and devimint. Integration tests for the group lifecycle, and for the attacks: wrong policy preimage, replayed sequence number, k-1 signatures, duplicate signer, k-of-n attempting to release into a transaction.

**3. Release.** Lands in a Fedimint release, which is what unblocks publishing the SDK. Guardians must opt in, since a module only exists on federations that deploy it, and a module that is not compiled into `fedimintd` needs a fork to run at all. Worth confirming early whether Fedi's own federations can take a release carrying it.

**4. SDK.** Starts as soon as phase 2 has a branch to build against, pinned to a revision rather than a tag. Facade, capabilities, operations, bindings, examples and the generated SDK surface. Moving the pin to the release version is the last step, not the first.

**5. Fedi migration.** Out of scope here. The app's SPv2-based implementation keeps working, and moving groups onto the module is its own project with its own migration story.

## Risks

Upstream may not want another module in tree. If so, the work still stands, but it runs in a fork of `fedimintd` and only on federations that deploy that fork, which is a materially worse distribution story and should be understood before phase 2 rather than after.

The transport gap is the thing most likely to make the SDK API feel thin. An application still has to move proposals and signatures between members, and the SDK cannot do that for it at first.

Guardian-visible balances and membership may be unacceptable for some deployments. There is no cheap fix inside this design.

The module only helps federations that run it, and now only second-generation ones, so the no-module path has to stay good. The facade returns `None`, and an application that needs group accounts everywhere still needs its own fallback.
