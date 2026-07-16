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
quorum and consensus cannot make progress.

`FM_IROH_RELAY` remains the Iroh 0.35 API relay setting.
`FM_IROH_P2P_RELAY` configures Iroh 1.x relays for guardian P2P. If the latter is
unset, guardian P2P uses Iroh's default 1.x-compatible relays. Do not configure a
0.35-only relay as an Iroh 1.x P2P relay.

Guardian P2P publishes only its relay address through Pkarr when one is
available. Without a relay address, it publishes its direct IP addresses instead
so other guardians can discover it by endpoint ID. This fallback is required for
relay-disabled deployments, but discloses the guardian's direct P2P addresses to
the configured Pkarr service.
