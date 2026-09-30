# SPEC-guardian-p2p-delivery: Guardian P2P delivery and reconnection

## Record justification

The P2P connection manager, consensus protocols, DKG setup, and daemon
connection-age configuration jointly depend on the delivery and reconnection
boundary, so no single implementation artifact can coherently own the contract.

## Delivery and reconnection contract

Guardian P2P is not a reliable message-delivery API. Its bounded queues can drop
messages, and connection failure or retirement can discard in-flight traffic. A
successful send is not an application-level acknowledgement, and the connection
manager neither acknowledges nor replays messages. Reconnecting establishes a
new transport; it does not recover messages from the connection it replaces.

Consensus handles individual message loss through protocol recovery and
retransmission, but it still requires sufficient eventual communication among a
quorum to make progress. Setup/DKG sends messages once and has no recovery for
traffic lost across a reconnect. A disconnect does not necessarily lose setup
traffic, but loss can leave setup waiting for a message and require restarting
setup.

DKG disables max-age connection rotation. Outside DKG, replacement and optional
max-age retirement are checked between sends so they do not cancel an active
non-cancel-safe send. A pending send can therefore defer retirement; this is a
separate stalled-connection recovery limitation and is not addressed by
consensus tolerance of individual message loss.

Finishing a frame accepted during retirement would only remove one source of
loss; it would not make DKG reconnect-safe.

The P2P connection manager must drive send and receive concurrently. Serializing
them can deadlock an otherwise live connection when both peers are blocked by
transport flow control.

This specification refines the guardian networking boundary in
[ARCH-fedimint](ARCH-fedimint.md).
