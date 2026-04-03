# Tor Privacy Guarantees

This document describes the privacy guarantees provided by Fedimint's Tor integration, the current limitations, and recommendations for operators who require guardian anonymity.

## Overview

Fedimint supports Tor for protecting the network identity of guardians and clients. When properly configured, Tor prevents observers from linking a guardian's IP address to their role in the federation.

## Connection Types

Fedimint has two distinct network layers, each with different privacy considerations:

### P2P (Guardian-to-Guardian)

Guardian-to-guardian communication carries consensus messages. An observer who can identify guardian IP addresses can:

- Determine which servers participate in the federation
- Correlate transaction timing with network activity
- Target specific guardians for denial-of-service attacks

**Current implementation:** P2P connectivity uses either TCP+WebSocket or iroh (a peer-to-peer networking library). The transport is selected at federation setup time and cannot be changed after DKG (Distributed Key Generation) completes.

| Transport | Tor Support | Notes |
|-----------|-------------|-------|
| TCP+WebSocket | Yes | Guardians can advertise `.onion` addresses |
| iroh | Partial | iroh uses its own relay infrastructure; Tor support depends on iroh's transport layer |

### API (Client-to-Guardian)

Client-facing API connections carry wallet operations (deposits, withdrawals, balance queries). An observer who can identify client IP addresses can:

- Link clients to specific federations
- Estimate transaction volumes
- Correlate deposits and withdrawals by timing

**Current implementation:** The API layer serves HTTP endpoints on a configurable address. Clients can connect via Tor if the guardian exposes an `.onion` API endpoint.

## What Tor Protects

When Tor is correctly configured for both P2P and API connections:

| Threat | Protected? | Details |
|--------|------------|---------|
| Guardian IP identification | Yes | Guardian addresses are `.onion` only |
| Client IP identification | Yes | Clients connect via Tor circuits |
| Traffic analysis (timing) | Partial | Tor adds latency jitter but consensus rounds have predictable timing |
| Guardian-to-guardian linkage | Yes | `.onion` addresses prevent IP correlation |
| ISP-level surveillance | Yes | ISP sees Tor traffic, not Fedimint protocol |

## What Tor Does NOT Protect

| Threat | Protected? | Details |
|--------|------------|---------|
| Federation metadata on-chain | No | On-chain transactions (peg-in/peg-out) are publicly visible on the Bitcoin blockchain |
| Guardian count | No | The number of guardians is embedded in the federation's threshold parameters |
| Ecash token amounts | No | Denomination values are determined by the keyset |
| Compromised guardian | No | A malicious guardian can observe consensus data regardless of network privacy |

## Configuration

### Advertising Tor Addresses

During federation setup, each guardian can configure their advertised P2P and API addresses. To use Tor, guardians should:

1. Run a Tor hidden service on the guardian server
2. Configure the hidden service to forward to the local fedimintd P2P and API ports
3. Use the `.onion` address as the guardian's advertised address during setup

**Important:** The Tor address must be configured **before** DKG. After DKG completes, guardian addresses are committed to the federation's configuration and cannot be changed without recreating the federation.

### Client Configuration

Clients connecting to a Tor-enabled federation should:

1. Configure their Fedimint client to use a SOCKS5 proxy (typically `127.0.0.1:9050`)
2. Use the federation's `.onion` invite code
3. Verify that no DNS leaks occur during connection

## Limitations

### iroh Transport

Federations using iroh for P2P networking have additional privacy considerations:

- iroh uses relay servers for NAT traversal — relay operators can observe connection metadata
- iroh's peer discovery mechanism may reveal guardian identifiers to relay infrastructure
- Switching from iroh to Tor-only P2P after DKG is not currently supported

For federations requiring maximum guardian anonymity, TCP+WebSocket with Tor hidden services is recommended over iroh.

### Mixed Configurations

If some guardians use Tor and others do not:

- The non-Tor guardians' IP addresses are visible to all other guardians
- An observer compromising a non-Tor guardian can learn the IP addresses of other non-Tor guardians
- Tor-only guardians remain protected even if other guardians are compromised

**Recommendation:** Either all guardians use Tor, or operators should assume that guardian identities are not private.

### Lightning Gateway

The Lightning Gateway is a separate process that connects to both the federation and the Lightning Network. Gateway privacy considerations:

- The gateway must have a Lightning node with public channels — this inherently reveals network identity
- Gateway-to-federation connections can use Tor if the federation exposes `.onion` API endpoints
- The gateway operator's identity is typically known to the federation (it is an economic participant, not a guardian)

## Recommendations

### For Maximum Guardian Privacy

1. Use TCP+WebSocket transport (not iroh)
2. All guardians run Tor hidden services
3. All guardians advertise only `.onion` addresses
4. No guardian reveals their clearnet IP to any other guardian
5. Guardian servers are hosted with privacy-preserving providers
6. Each guardian is operated by an independent entity in a separate jurisdiction

### For Operational Federations

1. Evaluate whether guardian anonymity is required for your threat model
2. If using iroh, understand that relay infrastructure can observe connection metadata
3. Document your federation's privacy guarantees for clients
4. Consider the trade-off: Tor adds latency to consensus rounds, which may affect transaction throughput

## Related

- [Networking](./networking.md) — Default ports and network configuration
- [Deploying](./deploying.md) — Federation setup guide
- [Architecture](./architecture.md) — System design overview
