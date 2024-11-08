// Federation endpoints
pub const ADD_GATEWAY_ENDPOINT: &str = "add_gateway";
pub const AWAIT_INCOMING_CONTRACT_ENDPOINT: &str = "await_incoming_contract";
pub const AWAIT_PREIMAGE_ENDPOINT: &str = "await_preimage";
pub const CONSENSUS_BLOCK_COUNT_ENDPOINT: &str = "consensus_block_count";
pub const GATEWAYS_ENDPOINT: &str = "gateways";
pub const OUTGOING_CONTRACT_EXPIRATION_ENDPOINT: &str = "outgoing_contract_expiration";
pub const REMOVE_GATEWAY_ENDPOINT: &str = "remove_gateway";

// Gateway endpoints
pub const CREATE_BOLT11_INVOICE_ENDPOINT: &str = "/create_bolt11_invoice";
pub const ROUTING_INFO_ENDPOINT: &str = "/routing_info";
pub const SEND_PAYMENT_ENDPOINT: &str = "/send_payment";
