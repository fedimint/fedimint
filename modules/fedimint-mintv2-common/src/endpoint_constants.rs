pub const SIGNATURE_SHARES_ENDPOINT: &str = "signature_shares";
pub const SIGNATURE_SHARES_RECOVERY_ENDPOINT: &str = "recovery_signature_shares";
pub const RECOVERY_SLICE_ENDPOINT: &str = "recovery_slice";
pub const RECOVERY_SLICE_HASH_ENDPOINT: &str = "recovery_slice_hash";
pub const RECOVERY_COUNT_ENDPOINT: &str = "recovery_count";

/// Maximum page size for recovery items and their consensus hash.
pub const RECOVERY_SLICE_SIZE: u64 = 10_000;
