# Fedimint networking

Default ports:

* fedimintd p2p: 8173
* fedimint API: 8174
* ln-gateway API: 8175

To be expanded.

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
unset, guardian P2P uses Iroh's default 1.x-compatible relays. Do not configure a
0.35-only relay as an Iroh 1.x P2P relay.

Guardian P2P publishes only its relay address through Pkarr when one is
available. Without a relay address, it publishes its direct IP addresses instead
so other guardians can discover it by endpoint ID. This fallback is required for
relay-disabled deployments, but discloses the guardian's direct P2P addresses to
the configured Pkarr service.

## Transitional Iroh 1.0 client API

The client-facing API keeps its original identity and Iroh 0.35 listener for
deployed clients. `FM_IROH_NEXT_ENABLE=true` additionally starts an Iroh 1.0
listener with a separately derived identity. Its bind address is configured by
`FM_BIND_API_NEXT` and defaults to the original API bind port plus 10. The Iroh
1.0 listener uses the default 1.x relay set; `FM_IROH_RELAY` remains exclusive
to the Iroh 0.35 API. This migration endpoint is only supported for a
federation configured with the legacy Iroh API. Enabling it at runtime does not
require setting the DKG-only `FM_ENABLE_IROH` option again.

Guardian metadata advertises the new identity in an optional field ignored by
older clients. Capable clients use the advertised identity without falling back
to the original identity. A client that learns the metadata while already
running applies it when reopened.

This rollout is forward-only. Once a guardian advertises its Iroh 1.0 API
identity, that listener must remain enabled and reachable. Disabling it or
downgrading to a binary without the listener is unsupported. After
advertisement, setting `FM_IROH_NEXT_ENABLE=false` or omitting the setting makes
startup fail while the persisted advertisement exists.
