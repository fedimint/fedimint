# Proposal: Guardian profiles in signed metadata

Guardians can already set a name at federation setup. For [#3124], let each
guardian publish and update optional public profile fields without consensus or
changes to the client config.

Add an optional `profile` object to the JSON payload of
[`GuardianMetadata`](../fedimint-core/src/net/guardian_metadata.rs). It maps
string keys to string values. For example, this would sit alongside
`api_urls`, `pkarr_id_z32`, and `timestamp_secs` in the signed `content`:

```json
{
  "profile": {
    "domain": "guardian.example",
    "avatar_url": "https://guardian.example/avatar.png"
  }
}
```

Each guardian supplies its map locally and publishes it through the existing
signed metadata path. In the existing signing request, omitting `profile` leaves
it unchanged; a supplied map replaces it, and `{}` clears it. A profile edit
publishes a newer signed payload. Clients that use profiles read them from the
latest verified metadata for each peer via `guardian_metadata`, not from
federation-wide metadata.

Clients treat a missing or empty profile as no profile and ignore keys they
don't use. Older clients ignore the additional JSON field and still verify the
original signed bytes. There is no new endpoint or change to the signature
format.

A signature attributes the claim to a guardian; it does not verify ownership of
a domain, handle, or avatar. Treat the strings as untrusted display data, never
as inputs to routing or trust decisions. UI, external verification, and fetching
profile URLs are outside this proposal.

[#3124]: https://github.com/fedimint/fedimint/issues/3124
