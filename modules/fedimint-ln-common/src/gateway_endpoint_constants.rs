/// Use `_` for word separator

pub const ADDRESS_ENDPOINT: &str = "/address";
pub const BACKUP_ENDPOINT: &str = "/backup";
pub const BALANCE_ENDPOINT: &str = "/balance";
pub const CONFIGURATION_ENDPOINT: &str = "/config";
pub const CONNECT_FED_ENDPOINT: &str = "/connect-fed"; // uses `-` for backwards compatibility
pub const CREATE_BOLT11_INVOICE_V2_ENDPOINT: &str = "/create_bolt11_invoice";
pub const GATEWAY_INFO_ENDPOINT: &str = "/info";
pub const GET_GATEWAY_ID_ENDPOINT: &str = "/id";
pub const GATEWAY_INFO_POST_ENDPOINT: &str = "/info";
pub const GET_FUNDING_ADDRESS_ENDPOINT: &str = "/get_funding_address";
pub const LEAVE_FED_ENDPOINT: &str = "/leave-fed"; // uses `-` for backwards compatibility
pub const LIST_ACTIVE_CHANNELS_ENDPOINT: &str = "/list_active_channels";
pub const OPEN_CHANNEL_ENDPOINT: &str = "/open_channel";
pub const CLOSE_CHANNELS_WITH_PEER_ENDPOINT: &str = "/close_channels_with_peer";
pub const RECEIVE_ECASH_ENDPOINT: &str = "/receive_ecash";
pub const ROUTING_INFO_V2_ENDPOINT: &str = "/routing_info";
pub const PAY_INVOICE_ENDPOINT: &str = "/pay_invoice";
pub const RESTORE_ENDPOINT: &str = "/restore";
pub const SEND_PAYMENT_V2_ENDPOINT: &str = "/send_payment";
pub const SET_CONFIGURATION_ENDPOINT: &str = "/set_configuration";
pub const SPEND_ECASH_ENDPOINT: &str = "/spend_ecash";
pub const WITHDRAW_ENDPOINT: &str = "/withdraw";
