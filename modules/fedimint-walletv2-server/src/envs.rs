/// Set to 1/true to stop this guardian from scanning its mempool for pending
/// receives.
///
/// Enumerating a mempool costs one transaction fetch per mempool entry the
/// guardian has not already cached, which on a busy mainnet node is a large
/// burst of RPC work every time the cache is cold. A guardian that would rather
/// not pay for it can turn the mempool half of the pending view off and report
/// confirmations only, exactly as an esplora-backed guardian already does.
pub const FM_WALLETV2_DISABLE_MEMPOOL_SCAN_ENV: &str = "FM_WALLETV2_DISABLE_MEMPOOL_SCAN";

/// Target size of each guardian's local FROST nonce buffer.
pub const FM_WALLETV2_FROST_NONCE_BUFFER_TARGET_ENV: &str = "FM_WALLETV2_FROST_NONCE_BUFFER_TARGET";

/// Test-only: peer id seated in every first FROST signing attempt.
///
/// Lets tests deterministically stall that attempt. Ignored outside test
/// environments, and every guardian of a federation must use the same value.
pub const FM_WALLETV2_FROST_TEST_FORCE_SIGNER_ENV: &str = "FM_WALLETV2_FROST_TEST_FORCE_SIGNER";
