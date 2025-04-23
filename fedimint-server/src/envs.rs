/// Environment variable for the session count determining when to cleanup old
/// checkpoints.
pub const FM_DB_CHECKPOINT_RETENTION_ENV: &str = "FM_DB_CHECKPOINT_RETENTION";

/// Default number of checkpoints from the current session should be retained on
/// disk.
pub const FM_DB_CHECKPOINT_RETENTION_DEFAULT: u64 = 1;
