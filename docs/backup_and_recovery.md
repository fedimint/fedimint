# Client E-cash backup&recovery

## Introduction

The client uses [the deterministic e-cash derivation scheme](./recoverable_e-cash.md). This allows e-cash recovery from the root key (exported and backed up securely during wallet creation) in case of data corruption or losing access to the wallet.

Using the root key it's possible to deterministically derive all the secret material, and by matching it against publicly available Fedimint federation history, recreate all the lost data.

However, recreating user funds by scanning the entire federation history might be very time and resource-consuming. To help with this problem Fedimint's backup&recovery supports backup snapshots, allowing practical and fast, yet privacy-preserving recovery.

This document is only a high-level description and might be out of date. For details, please refer to the source code itself, which contains a lot of nitty-gritty information.

## Creating backup snapshot

Periodically, on a fixed schedule (for privacy), the client should create and upload a backup snapshot of their e-cash data.

The following is the persistent data relevant to the e-cash derivation:

* spendable signed notes
* unconfirmed notes
* note derivation index counter for each amount tier

An atomic snapshot of all the above data is taken, along with the current Fedimint consensus `epoch`. The embedded `epoch` is what allows skipping a large part of Federation history during the restoration procedure.

All this data is serialized, padded (to avoid leaking any information), and encrypted with the deterministically derived (from the root seed key) backup encryption key.

### Federation provided backup snapshot storage

In principle, the encrypted backup snapshot could be stored anywhere, privately or publicly, but for the user's convenience, the Federation provides the ability to store and retrieve them.

The client creates a backup request containing:

* `ID` (backup signing public key),
* `timestamp` (current time, to prevent any reply attacks)
* `payload` (encrypted snapshot)

then the request is signed with the deterministically derived backup signing secret key.

The backup request is then sent to the Federation members. The `ID` is used as an anonymous identifier of the user and their most recent backup snapshot.

Each member verifies the signature is valid and matches the backup `ID`, then compares the `timestamp` against any already stored snapshot for this `ID`, to ensure only the most copy is stored.

The Federation also provides an ability for the client to download the most recent backup snapshot of a given ID.

## Restoring from the snapshot

Backup recovery works by starting from the recent snapshot, then sequentially querying the Federation for consensus epoch history since the backup snapshot was taken until the present time, and for each epoch,  scanning all the relevant consensus data and matching it against the existing (e.g. known spendable notes) and predicted client state (e.g. next in sequence deterministic blind nonces).

In essence, the recovery code is (in limited scope) replaying the Federation consensus history to fast-forward the snapshot to the final and up-to-date state.

