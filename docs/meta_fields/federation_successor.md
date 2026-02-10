# `federation_successor`

An invite code to a successor federation that users should migrate to. This field is typically used in conjunction with
[`federation_expiry_timestamp`](federation_expiry_timestamp.md) to inform clients where users should move their funds
before the current federation shuts down.

When set, clients can display this information to users and potentially provide a streamlined migration flow to the
successor federation.

## Structure
A string containing a valid Fedimint invite code (e.g., `fed11...`). The invite code should be parseable by
`fedimint_core::invite_code::InviteCode`.
