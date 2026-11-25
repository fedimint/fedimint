# Fedimint networking

Default ports:

* fedimintd p2p: 8173
* fedimint API: 8174
* ln-gateway API: 8175

To be expanded.

For the guardian P2P delivery and reconnection contract, see
[SPEC-guardian-p2p-delivery](../specs/SPEC-guardian-p2p-delivery.md).

## Guardian relay-only Iroh connections

Set `FM_IROH_P2P_ENABLE=false` (or `0`) before starting `fedimintd` to disable
direct IP transports for guardian P2P, the Iroh 1.x API listeners, and
guardian-origin Iroh 1.x API connections. Leave the variable unset or set it
to `true` or `1` to keep
the default direct-and-relay behavior. This local runtime option does not change
federation configuration, identities, or protocols and does not require another DKG.

In relay-only mode, the 1.x endpoints do not bind UDP sockets, advertise direct
IP addresses, or connect directly to peers. They ignore their configured IP bind
addresses. Direct-only connection overrides such as
`FM_IROH_CONNECT_OVERRIDES_PLAIN` cannot supply a usable path in this mode;
remove those overrides to use normal relay discovery.

Keep relays enabled (`FM_IROH_RELAYS_ENABLE` defaults to enabled), reachable,
and compatible with Iroh 1.x. Guardian P2P honors `FM_IROH_P2P_RELAY` and the
API listeners honor `FM_IROH_RELAY`. Disabling both IP transports and
relays prevents guardian startup because the endpoints cannot bind. Relay outages
or poor relay connectivity can interrupt P2P, stall consensus or setup/DKG, and prevent API
access; relay-only operation also adds relay bandwidth and latency costs.

This is not a guardian-wide or process-wide IP privacy guarantee. It does not
change TLS/WebSocket listeners or other network traffic. Relays and discovery
services still receive network traffic from the guardian. This option does not affect library clients or gateways.

## Guardian Iroh P2P upgrades

In Iroh-enabled federations, guardian-to-guardian P2P and the client-facing
guardian API both use Iroh 1.x. Iroh 0.35 and 1.x P2P transports cannot connect
to each other. Upgrades
across this boundary must therefore be coordinated. Consensus can continue while
a quorum (the required threshold of guardians) runs mutually compatible
software, so guardians may be upgraded in a staggered sequence. However, the old
transport loses quorum before the new transport gains it. Upgrade the guardians
in close succession to minimize this interval, during which neither group has
quorum and consensus cannot make progress. Rolling back across the incompatible
transport boundary is unsupported.

`FM_IROH_RELAY` configures the Iroh 1.x relays of the client API listeners and
`FM_IROH_P2P_RELAY` those of guardian P2P. When either is unset, that endpoint
uses the Fedimint-operated Iroh 1.x relays; an explicit list overrides that
default. `FM_IROH_RELAYS_ENABLE=0` disables relays regardless of the list. Both
must serve the Iroh 1.x relay protocol: a relay set up for the earlier Iroh 0.35
API listener cannot serve Iroh 1.x clients, so upgrade it before upgrading the
guardian.

Guardian P2P publishes only its relay address through Pkarr when one is
available. Without a relay address, it publishes its direct IP addresses instead
so other guardians can discover it by endpoint ID. This fallback is required for
relay-disabled deployments, but discloses the guardian's direct P2P addresses to
the configured Pkarr service.

## Iroh 1.x client API

The client-facing API serves Iroh 1.x under the API identity from the
federation config, on the API bind address. Clients from 0.12.0 on try Iroh
0.35 and Iroh 1.x against that identity concurrently and keep whichever
connects, so they need no change. Older clients ship a pre-release Iroh 1.x
with an incompatible wire protocol and can no longer connect over Iroh. The
listener registers on the relays from `FM_IROH_RELAY`, see above.

The Iroh 1.x default relay set selects Fedimint-operated home relays rather than
n0's public relays. It is not an egress allowlist: clients and guardians can still
dial peers through other relay URLs advertised in those peers' address records.
The set also lists `eu01.iroh.fedimint.org` and `us01.iroh.fedimint.org`, which
do not resolve yet and are reserved for a later move to Fedimint-owned domains.
Iroh never selects an unreachable relay as home, so they are inert until they
serve an Iroh 1.x relay. Keep them unresolvable until then.

### Transitional identity

Releases 0.12.0 through 0.13.0 advertised a separately derived Iroh 1.x
identity in guardian metadata, and clients that learned it use it without
falling back to the original identity. The guardian clears the advertisement on
startup but keeps serving that identity by default so those clients stay
connected. A client that learns the cleared metadata while running returns to
the original identity when reopened. The transitional listener binds to
`FM_BIND_API_NEXT`, which defaults to the API bind port plus 10, and only runs
for a federation configured with the Iroh API.

Keep the transitional listener enabled. A client that stored the transitional
identity for every guardian and stays offline through the migration sends no
requests to it, so a quiet `next` series of the Iroh API request metrics does
not show that such clients are gone. When the client comes back, the
transitional listener is the only way it can reach a guardian and learn the
cleared advertisement. A later release will remove the listener after a grace
period; until then `FM_IROH_NEXT_ENABLE=false` is only for federations that
never advertised it.
