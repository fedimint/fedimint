// Federation endpoints
//
// NOTE: the four payment-wait endpoints below (`await_incoming_contract`,
// `await_preimage`, `await_incoming_contracts`, `decryption_key_share`) are
// also listed by name in `IROH_LNV2_WAIT_METHODS` in
// `fedimint-connectors/src/iroh.rs`, which gives them a shorter iroh request
// budget than other long-polls. That crate cannot depend on this one, so the
// names are duplicated there as literals, and renaming one here without
// updating there silently changes its budget. The three `await_*` names would
// still match that file's `await_`/`wait_` prefix heuristic and fall back to
// the 1-hour tier; `decryption_key_share` matches neither and would fall all
// the way back to the 60s prompt tier, which for a wait the gateway issues
// before funding acceptance means closing the shared pooled connection once a
// minute for the length of the wait.
pub const ADD_GATEWAY_ENDPOINT: &str = "add_gateway";
pub const AWAIT_INCOMING_CONTRACT_ENDPOINT: &str = "await_incoming_contract";
pub const AWAIT_PREIMAGE_ENDPOINT: &str = "await_preimage";
pub const AWAIT_INCOMING_CONTRACTS_ENDPOINT: &str = "await_incoming_contracts";
pub const DECRYPTION_KEY_SHARE_ENDPOINT: &str = "decryption_key_share";
pub const CONSENSUS_BLOCK_COUNT_ENDPOINT: &str = "consensus_block_count";
pub const GATEWAYS_ENDPOINT: &str = "gateways";
pub const OUTGOING_CONTRACT_EXPIRATION_ENDPOINT: &str = "outgoing_contract_expiration";
pub const REMOVE_GATEWAY_ENDPOINT: &str = "remove_gateway";

// Gateway endpoints
pub const CREATE_BOLT11_INVOICE_ENDPOINT: &str = "/create_bolt11_invoice";
pub const VERIFY_BOLT11_PREIMAGE_ENDPOINT: &str = "/verify_bolt11_preimage";
pub const ROUTING_INFO_ENDPOINT: &str = "/routing_info";
pub const SEND_PAYMENT_ENDPOINT: &str = "/send_payment";
