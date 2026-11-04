# SPEC-guardian-p2p-delivery: Guardian P2P delivery and reconnection

## Record justification

The P2P connection manager, consensus protocols, DKG setup, and daemon
connection-age configuration depend on the delivery and reconnection
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

DKG disables max-age connection rotation. The send loop checks for replacement
and optional max-age retirement between sends so neither event cancels an active
non-cancel-safe send. A pending send defers retirement until it completes, fails,
or reaches the separate one-minute send timeout. A send timeout fails the
connection so the manager can adopt a queued replacement or reconnect; it can
discard the in-flight message even during DKG. Disabling max-age rotation does
not disable this timeout or make delivery reliable.

When the send half stops for replacement, max-age retirement, or send failure
(including a send timeout), the manager gives the receive half up to five seconds
to finish an already accepted frame and stop between frames. Shutdown skips this
grace. A drain timeout or receive failure can still discard in-flight work, and a completed
frame can still be lost if the incoming queue is full. This bounded drain
reduces one source of loss; it neither acknowledges delivery nor makes DKG
reconnect-safe.

The P2P connection manager must drive send and receive concurrently. Serializing
them can deadlock an otherwise live connection when both peers are blocked by
transport flow control.

This specification refines the guardian networking boundary in
[ARCH-fedimint](ARCH-fedimint.md).
