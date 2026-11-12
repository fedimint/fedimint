# SPEC-dkg-version-compatibility: DKG version compatibility

## Status

Guardian setup implements the version projection below. This specification does not claim verified end-to-end compatibility between released binaries.

## Record justification

The contract spans daemon version construction, `PeerSetupCode` exchange, `SetupApi` admission and start checks, and `ServerConfigConsensus::code_version` checksumming, so no single implementation artifact can coherently own the end-to-end compatibility rule.

## Compatibility contract

For a new federation setup, each guardian identifies its running build with a valid semantic version. Setup codes carry the normalized `major.minor.patch` release plus the exact optional vendor string encoded as SemVer build metadata; prerelease metadata is omitted so the displayed value remains useful for diagnosing a rejected peer.

Two guardians are DKG-compatible exactly when their major and minor versions match and their optional vendor strings are equal. Patch and prerelease differences do not affect compatibility. An absent vendor string is distinct from every specified vendor string, and vendor strings compare exactly.

A guardian must validate its local version and reject a malformed or incompatible peer version when the peer setup code is added. It must revalidate every collected setup-code version immediately before starting DKG so stale or otherwise bypassed setup state cannot enter configuration generation.

Newly generated `ServerConfigConsensus::code_version` values must use the same compatibility identity as the early setup and start-DKG checks. Guardians admitted under patch or prerelease skew must therefore derive the same consensus-config checksum, while guardians from another major/minor series or vendor identity must not be admitted merely because their remaining configuration agrees.

This contract applies when every participating binary implements this compatibility projection.

## Setup-code and DKG compatibility policy

DKG backward compatibility is required only on release branches; trunk may make breaking DKG changes before release.

Guardians in the same major/minor/vendor compatibility group must be able to decode each other's serialized `PeerSetupCode` values and complete the whole DKG process together. Passing version admission alone does not satisfy this requirement.

Setup-code and DKG compatibility is not guaranteed across major/minor series or vendor identities.

This contract governs new setup and DKG only. It does not rewrite persisted configurations, promise general setup API compatibility beyond the setup-code and DKG requirement above, or define compatibility for upgrading an operating federation.

This specification refines the setup boundary in [ARCH-fedimint](ARCH-fedimint.md).
