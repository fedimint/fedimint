/// Configuration for connection and request limits
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
        Self {
            max_connections,
            max_requests_per_connection,
        }
    }
}
