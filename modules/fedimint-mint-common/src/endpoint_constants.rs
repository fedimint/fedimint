pub const AWAIT_OUTPUT_OUTCOME_ENDPOINT: &str = "await_output_outcome";
pub const NOTE_SPENT_ENDPOINT: &str = "note_spent";
pub const BLIND_NONCE_USED_ENDPOINT: &str = "blind_nonce_used";
pub const RECOVERY_COUNT_ENDPOINT: &str = "recovery_count";
pub const RECOVERY_SLICE_ENDPOINT: &str = "recovery_slice";
pub const RECOVERY_SLICE_HASH_ENDPOINT: &str = "recovery_slice_hash";

/// Maximum page size for recovery items and their consensus hash.
pub const RECOVERY_SLICE_SIZE: u64 = 10_000;
pub const RECOVERY_BLIND_NONCE_OUTPOINTS_ENDPOINT: &str = "recovery_blind_nonce_outpoints";
