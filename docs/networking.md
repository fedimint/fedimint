# Fedimint networking

## Default Ports

| Service | Port | Protocol |
|---------|------|----------|
| fedimintd p2p | 8173 | TCP/WebSocket or iroh |
| fedimint API | 8174 | HTTP |
| ln-gateway API | 8175 | HTTP |

## Transport Options

Fedimint supports two transport modes for guardian-to-guardian (P2P) communication:

- **TCP + WebSocket** — Traditional networking. Supports Tor hidden services for guardian privacy.
- **iroh** — Peer-to-peer networking library with built-in NAT traversal. Uses relay infrastructure for connectivity.

The transport is selected during federation setup and committed after DKG. It cannot be changed without recreating the federation.

## Privacy

For information on Tor integration, privacy guarantees, and recommendations for guardian anonymity, see [Tor Privacy](./tor-privacy.md).
