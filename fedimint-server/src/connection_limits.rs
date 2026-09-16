/// Configuration for connection and request limits
///
/// A zero limit wedges the iroh API rather than rejecting anything, so `new`
/// validates both values. The fields remain public for downstream source
/// compatibility, so the iroh API asserts the same invariant again during its
/// startup when the state is constructed in case a struct literal bypasses
/// `new`.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Maximum number of parallel requests per connection
    pub max_requests_per_connection: usize,
}

impl ConnectionLimits {
    /// Create new connection limits
    pub fn new(max_connections: usize, max_requests_per_connection: usize) -> Self {
        assert!(
            max_connections > 0,
            "iroh API connection limit must allow at least one connection"
        );
        assert!(
            max_requests_per_connection > 0,
            "iroh API request limit must allow at least one request per connection"
        );
        Self {
            max_connections,
            max_requests_per_connection,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionLimits;

    #[test]
    #[should_panic(expected = "iroh API connection limit must allow at least one connection")]
    fn rejects_zero_max_connections() {
        ConnectionLimits::new(0, 50);
    }

    #[test]
    #[should_panic(
        expected = "iroh API request limit must allow at least one request per connection"
    )]
    fn rejects_zero_max_requests_per_connection() {
        ConnectionLimits::new(1000, 0);
    }
}
