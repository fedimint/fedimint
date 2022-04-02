/// Provides an interface to call APIs of other modules
pub trait ModuleInterconect {
    /// Simulates a HTTP call to an API endpoint of another module. Unless an actual HTTP call this
    /// should be infallible though (except for invalid requests) and has lower latency.
    ///
    /// **CAUTION**: does not support URL parameters yet
    fn call(
        &self,
        module: &'static str,
        path: String,
        method: http_types::Method,
        data: serde_json::Value,
    ) -> http_types::Result<http_types::Response>;
}
