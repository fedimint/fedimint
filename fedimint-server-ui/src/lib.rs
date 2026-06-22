pub mod dashboard;
pub mod setup;

pub(crate) const LOG_UI: &str = "fm::ui";

// Common route constants
pub const EXPLORER_IDX_ROUTE: &str = "/explorer";
pub const EXPLORER_ROUTE: &str = "/explorer/{session_idx}";
pub const DOWNLOAD_BACKUP_ROUTE: &str = "/download-backup";
pub const METRICS_ROUTE: &str = "/metrics";
