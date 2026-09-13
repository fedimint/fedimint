# Dual P2P feasibility spike

**Draft research/prototype to judge feasibility, not a production rollout
recommendation.** This experiment automatically uses one sender-owned session per
application direction when both guardians negotiate `FEDIMINT_P2P_DUAL_V1`.
There is no activation flag, capability registry, configuration migration, or
change to DKG admission.

## Before and after

Existing guardians use one bidirectional session, with the lower peer ID
responsible for reconnecting it. That remains the mixed-version mode. Two spike
guardians use two independent TLS TCP connections or Iroh QUIC connections:

```text
lower guardian:
    discovery dial -> authenticated ALPN result
        legacy -> existing bidirectional lifecycle
        dual   -> outgoing slot (send queue + independent EOF monitor)

higher guardian:
    authenticated dual accept -> incoming slot (receive loop)
        grants reverse dialing permission
    dual-only reverse dial -> outgoing slot

each dual guardian:
    outgoing failure -> reconnect own outgoing; retain incoming
    incoming failure -> clear incoming; retain outgoing; await sender reconnect
    duplicate incoming while occupied -> reject candidate, retain current slot
```

There is exactly one application outgoing queue consumer. Each slot owns its IO
future, so dropping an obsolete slot also removes its completion future; there
are no detached task events that can clear a newer slot. Incoming and outgoing
futures run independently, including when an outgoing write is parked. Polling
the unused outgoing receive direction detects idle closure; an application frame
there is a protocol violation.

## Compatibility and downgrade

Negotiation happens in the authenticated transport handshake, never in an
application preamble that an old decoder would see.

* TLS offers the dual ALPN. A selected dual ALPN enables dual mode; no selection
  retains the original framing and bidirectional lifecycle. Old empty-ALPN
  clients and servers interoperate with these offers.
* Iroh discovery offers dual plus the existing `FEDIMINT_P2P_ALPN`; the actual
  negotiated result chooses the lifecycle. Reverse dialing offers dual only.
* The lower peer bootstraps discovery. An unproven higher peer does not
  speculatively dial an old peer, which would otherwise replace its working
  bidirectional session.
* A higher peer can have stale knowledge after a lower peer downgrades. Old TLS
  can complete that reverse handshake without selecting ALPN. The higher peer
  drops the result, revokes reverse dialing permission, and waits for fresh
  discovery. This can transiently disturb the old lower manager, but must not
  create a repeated reverse-probe loop. A fresh legacy connection from the lower
  peer releases obsolete dual slots and restores legacy operation.
* A timeout or authentication failure is not evidence of legacy support. No
  permanent capability cache is stored. A healthy mixed pair need not actively
  re-probe until normal reconnect/restart.

## Deliberately retained limitations

**There is no bounded recovery guarantee for a half-open TLS incoming slot.**
If a sender reconnects while the receiver still sees its old session as open,
the receiver rejects the new session. Transport handshake success therefore
does not prove application admission. The test byte proxy reproduces this with
real TLS: it keeps the old socket open without forwarding EOF; reconnects are
rejected while the opposite application direction continues working. Releasing
the retained socket lets ordinary retries converge. This is an observation,
not a fix or a production liveness guarantee.

Queues remain bounded and lossy, without ACK, replay, delivery confirmation,
cross-direction ordering, or lossless reconnect. DKG still relies on a stable
initial connection for one-shot messages and may need to restart after loss.
Switching away from obsolete dual sessions can cancel their in-flight traffic.
There is no bounded drain protocol in this change.

Age rotation is sender-owned only in dual mode and is checked between sends.
A parked send still postpones age retirement, just as in legacy mode. Incoming
sessions never retire on the receiver's local age timer. Heartbeats, explicit
admission responses, sender generations, and stale-slot deadlines are possible
follow-up experiments, not hidden parts of this spike.

Connected status requires both local dual slots; legacy still needs one
bidirectional session. Existing RTT/type dashboard fields describe the outgoing
session when both slots exist. They are local observations, not delivery
acknowledgements. Existing connect/disconnect counters still cover the legacy
lifecycle and initial discovery, not every dual slot event; directional dual
logs and readiness status are the useful diagnostics in this prototype.

## Reproducible focused checks

```sh
cargo test -p fedimint-server --lib net::
just format
just final-lint
FM_SELFCI_CHECK_SKIP_BUILD=false FM_SELFCI_CHECK_SKIP_TESTS=false \
  FM_SELFCI_CHECK_SKIP_CLIPPY=false selfci check -c <change-id>
```

The focused tests execute real TLS and Iroh handshakes, with old/old, new/old,
old/new, and new/new peers. Test-only old fixtures preserve the lower-only
reconnect/replacement lifecycle and old empty-TLS/legacy-Iroh ALPN settings from
`46b195b5210908d43dd9276de236dbf1edc516e7`. They do not route old peers through
the new manager's legacy branch. They are nevertheless in-process fixtures,
not unchanged-binary deployment evidence.

Executed focused cases include simultaneous 2 MB messages, idle closure and
reconnection of each sender, retention of the opposite session, duplicate
incoming rejection, shutdown, the stale TLS reverse/downgrade path, readiness,
parked-send EOF monitoring, sender-owned age, and the retained TLS byte-proxy
case above.

The draft's verification report must separately identify actual unchanged-binary
federation runs and full CI outcomes. Do not infer from these focused tests that
the entire upgrade/restart matrix, Iroh half-open recovery, relay paths,
Iroh 0.35 compatibility, or arbitrary partitions have been tested.
