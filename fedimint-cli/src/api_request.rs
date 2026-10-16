use crate::client::ModuleSelector;

/// Routing and payload options for a raw developer API request.
pub(crate) struct ApiRequest {
    /// Method to invoke.
    pub(crate) method: String,
    /// JSON parameters, falling back to a literal string.
    pub(crate) params: String,
    /// Individual guardian, or federation consensus when absent.
    pub(crate) peer_id: Option<u16>,
    /// Optional guardian authentication.
    pub(crate) auth: Option<String>,
    /// Module API, or global API when absent.
    pub(crate) module: Option<ModuleSelector>,
}
