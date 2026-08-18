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

Each Lightning module exposes a versioned gateway registry snapshot endpoint.
An LNv1 snapshot distinguishes a registry with no records from one where every
record has expired, and returns the same current announcements as the existing
list endpoint. An LNv2 snapshot returns the same registered URLs as its existing
registry endpoint; LNv2 has no registration TTL, so its snapshot has no expiry
field. The client accepts a snapshot only when every configured guardian
responds, uses the current format, returns valid fields, and agrees on an empty
LNv1 registry's state.

The public gateway health result contains no gateway URL, announcement,
guardian identity, peer topology, or raw transport error. The client checks
each distinct current registration once. One healthy gateway makes the result
`Healthy`. The client reports that all gateways are unreachable or missing the
status endpoint only when every check returns the same result;
mixed or incomplete results become `Unknown`. A gateway transport failure
remains distinct from a reached gateway whose federation connection pool is
disconnected.
