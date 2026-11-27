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
direct IP transports for guardian P2P, the transitional Iroh 1.x API listener,
and guardian-origin Iroh 1.x API connections. Leave the variable unset or set it
to `true` or `1` to keep
the default direct-and-relay behavior. This local runtime option does not change
federation configuration, identities, or protocols and does not require another DKG.

In relay-only mode, the 1.x endpoints do not bind UDP sockets, advertise direct
IP addresses, or connect directly to peers. They ignore their configured IP bind
addresses. Direct-only connection overrides such as
`FM_IROH_CONNECT_OVERRIDES_PLAIN` cannot supply a usable path in this mode;
remove those overrides to use normal relay discovery.

Keep relays enabled (`FM_IROH_RELAYS_ENABLE` defaults to enabled), reachable,
and compatible with Iroh 1.x. Guardian P2P honors `FM_IROH_P2P_RELAY`; the
transitional API uses Iroh's default 1.x relays. Disabling both IP transports and
relays prevents guardian startup because the endpoints cannot bind. Relay outages
or poor relay connectivity can interrupt P2P, stall consensus or setup/DKG, and prevent API
access; relay-only operation also adds relay bandwidth and latency costs.

This is not a guardian-wide or process-wide IP privacy guarantee. It does not
change inbound or outbound Iroh 0.35 connections, TLS/WebSocket listeners, or
other network traffic. The legacy Iroh 0.35 API remains enabled for compatibility;
both inbound and outbound Iroh 0.35 connections can still use direct IP
transports. Relays and discovery services still receive network traffic from the
guardian. This option does not affect library clients or gateways.

## Guardian Iroh P2P upgrades

In Iroh-enabled federations, guardian-to-guardian P2P uses Iroh 1.x while the
client-facing guardian API continues to use the backwards-compatible Iroh 0.35
endpoint. Iroh 0.35 and 1.x P2P transports cannot connect to each other. Upgrades
across this boundary must therefore be coordinated. Consensus can continue while
a quorum (the required threshold of guardians) runs mutually compatible
software, so guardians may be upgraded in a staggered sequence. However, the old
transport loses quorum before the new transport gains it. Upgrade the guardians
in close succession to minimize this interval, during which neither group has
quorum and consensus cannot make progress. Rolling back across the incompatible
transport boundary is unsupported.

`FM_IROH_RELAY` remains the Iroh 0.35 API relay setting.
`FM_IROH_P2P_RELAY` configures Iroh 1.x relays for guardian P2P. If the latter is
unset, guardian P2P uses the Fedimint-operated Iroh 1.x relays; an explicit list
overrides that default. `FM_IROH_RELAYS_ENABLE=0` disables relays regardless of
the list. Do not configure a 0.35-only relay as an Iroh 1.x P2P relay.

Guardian P2P publishes only its relay address through Pkarr when one is
available. Without a relay address, it publishes its direct IP addresses instead
so other guardians can discover it by endpoint ID. This fallback is required for
relay-disabled deployments, but discloses the guardian's direct P2P addresses to
the configured Pkarr service.

## Transitional Iroh 1.0 client API

The client-facing API keeps its original identity and Iroh 0.35 listener for
deployed clients. It also starts an Iroh 1.0 listener with a separately derived
identity by default. Set `FM_IROH_NEXT_ENABLE=false` to disable it before it is
advertised. Its bind address is configured by `FM_BIND_API_NEXT` and defaults
to the original API bind port plus 10. The Iroh 1.0 listener and capable clients
use the Fedimint-operated Iroh 1.x relay set. `FM_IROH_RELAYS_ENABLE=0` disables
relays for the listener; `FM_IROH_RELAY` remains exclusive to the Iroh 0.35 API
and `FM_IROH_P2P_RELAY` only overrides guardian P2P relays. This
migration endpoint is only supported for a federation configured with the
legacy Iroh API. Its runtime default is independent of the DKG-only
`FM_ENABLE_IROH` option. Existing federations configured without the legacy
Iroh API continue without either Iroh listener and log a warning.

The Iroh 1.x default relay set selects Fedimint-operated home relays rather than
n0's public relays. It is not an egress allowlist: clients and guardians can still
dial peers through other relay URLs advertised in those peers' address records.
The set also lists `eu01.iroh.fedimint.org` and `us01.iroh.fedimint.org`, which
do not resolve yet and are reserved for a later move to Fedimint-owned domains.
Iroh never selects an unreachable relay as home, so they are inert until they
serve an Iroh 1.x relay. Keep them unresolvable until then.

Guardian metadata advertises the new identity in an optional field ignored by
older clients. Capable clients use the advertised identity without falling back
to the original identity. A client that learns the metadata while already
running applies it when reopened.

This rollout is forward-only. Once a guardian advertises its Iroh 1.0 API
identity, that listener must remain enabled and reachable. Disabling it or
downgrading to a binary without the listener is unsupported. After
advertisement, setting `FM_IROH_NEXT_ENABLE=false` makes startup fail while the
persisted advertisement exists. Omitting the setting keeps the listener enabled.
