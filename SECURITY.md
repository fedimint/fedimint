# Security Policy

## Reporting a Vulnerability

Do **not** open a public GitHub issue for security bugs.

Send a report to **security@fedimint.org** (this address forwards to the
maintainers listed below) or message **`@elsirion.21`** on Signal.

Please include:

- What the bug is and where it is in the code.
- How to reproduce it, if possible.
- What an attacker can do with it (steal funds, break consensus, leak user
  data, stop the federation, etc.).
- Your name or handle, if you want credit in the fix announcement.

## Encrypted Reports

If the report is sensitive, encrypt it with PGP. Mail sent to
security@fedimint.org goes to both maintainers, so encrypt to **both keys**.

| Maintainer | Email | Key fingerprint |
| --- | --- | --- |
| dpc | `dpc@dpc.pw` | `23B8 147B 42EB 74CB 801F F76F 930E AF17 AB8F F29C` |
| elsirion | `elsirion@protonmail.com` | `B3CD FF6F 6D4B 2BE9 EA8B 0020 B300 5E57 1AA3 14DA` |

Both keys are hosted on the Proton Mail key server. To fetch them:

```sh
gpg --fetch-keys 'https://api.protonmail.ch/pks/lookup?op=get&search=dpc@dpc.pw'
gpg --fetch-keys 'https://api.protonmail.ch/pks/lookup?op=get&search=elsirion@protonmail.com'
```

Check the fingerprints against the table above before you use the keys.

Please keep the bug private until a fix is released and federation operators
had time to upgrade.

## Supported Versions

We only fix security bugs in the latest stable release line. Older releases do
not get patches. Run a current release if you run a federation in production.

## Scope

In scope:

- All code in this repository: `fedimintd`, `fedimint-cli`, the client
  libraries, the modules (mint, wallet, lightning, meta) and the gateway.
- Consensus safety, fund safety, user privacy, and denial of service against a
  federation.

Out of scope:

- Bugs in third-party software we depend on (report them upstream, but tell us
  too if Fedimint is affected).
- Attacks that need a majority of guardians to be malicious. The threat model
  assumes fewer than one third of guardians are faulty.
- Test and development setups, such as `devimint`.


## Guardian Bitcoin Backends

Configured Bitcoin RPC endpoints, including Esplora, are trusted inputs to a
guardian. Esplora is a trusted chain oracle: Fedimint does not independently
verify its chain selection, work, consensus rules, or freshness. Block payload
integrity checks and chain-identity comparisons are defense in depth against
inconsistent responses and misconfiguration, not the basis of this trust model.
Use operator-controlled or explicitly trusted services, with encrypted transport
across untrusted networks. A shared public provider can correlate guardian
activity and influence multiple guardians at once; independent operators should
consider this correlated trust dependency.

In hybrid mode (`FM_BITCOIND_URL` and `FM_ESPLORA_URL` together), available
endpoints must agree on the height-1 block hash at startup. If only one responds,
its trusted identity is remembered for the process lifetime; this allows startup
on Esplora while bitcoind is offline without an extra chain-pin option. An
endpoint's successfully checked identity is remembered and invalidated after an
observed RPC failure, so recovery checks it again before use. These are not
per-request identity proofs: trusted endpoints are expected to keep serving
their configured chain, and operators must restart the guardian when
deliberately changing chains.

Reads prefer bitcoind if it is not in initial block download and its reported
tip is at least Esplora's. Otherwise they use eligible Esplora. Health snapshots
last five seconds; probes run concurrently with a five-second deadline and
failed endpoints wait thirty seconds before another health probe. This bounds
the latency added by an unavailable secondary without spawning overlapping
blocking Core probes. Normal data requests retain their transport timeouts.
Any read error, including semantic errors, may be retried on another eligible
backend; a known-stale or IBD primary is not used as a read fallback. Neither
endpoint proves freshness when the other is unavailable.

Broadcast is deliberately bitcoind-first: Esplora receives the transaction only
if the primary attempt fails. A reachable, network-isolated bitcoind can accept
a transaction without propagating it. Fedimint relies on multiple guardians
rebroadcasting the same peg-out, assuming at least one broadcaster has working
Bitcoin connectivity; successful local submission is not proof of propagation.
We do not broadcast to both endpoints unconditionally. The federation's normal
rebroadcast and confirmation handling remain necessary.
Read-health failures do not suppress broadcast attempts; backend identity
checks still apply.

Esplora sees synchronization queries and, when used for broadcast fallback,
complete peg-out transactions and guardian-origin timing. Any primary broadcast
error, including policy rejection, may trigger this disclosure. Only configure a
fallback if these trust and privacy consequences are acceptable.

## Public Gateway Federation Status

Configured gateways expose unauthenticated HTTP and Iroh `POST
/federation_status` queries for one exact federation ID. The response contains
only finite, detail-free connectivity, Lightning module capability, and
registration-health classes for that ID. It must not reveal the gateway's
federation inventory, guardian identities, balances, route hints, credentials,
or raw errors; `/info` remains authenticated. A gateway that has not completed
mnemonic setup exposes only its setup endpoints.

Registration observations are process-local and cleared when the gateway leaves
the federation. Concurrent results follow attempt begin order so stale work
cannot overwrite a newer logical attempt, and advertised TTL uses monotonic
elapsed time. Status assembly holds the federation-manager read lock only while
capturing one coherent snapshot; do not clone the client solely for this public
query because that would interfere with concurrent leave.
