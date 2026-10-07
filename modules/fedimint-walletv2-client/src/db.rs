use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    NextOutputIndex = 0x31,
    ValidAddressIndex = 0x32,
    ReservedAddress = 0x33,
    HighestUsedAddressIndex = 0x34,
    Rescan = 0x35,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct NextOutputIndexKey;

impl_db_record!(
    key = NextOutputIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextOutputIndex
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ValidAddressIndexKey(pub u64);

impl_db_record!(
    key = ValidAddressIndexKey,
    value = (),
    db_prefix = DbKeyPrefix::ValidAddressIndex
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ValidAddressIndexPrefix;

impl_db_lookup!(
    key = ValidAddressIndexKey,
    query_prefix = ValidAddressIndexPrefix
);

/// The reservation of the address at a valid index.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ReservedAddressKey(pub u64);

/// A reserved address: the operation following it and, once there is one, the
/// claim of the first payment made to it.
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct ReservedAddress {
    pub operation_id: OperationId,
    pub claim: Option<ReservedAddressClaim>,
}

/// The receive operation claiming the first payment made to a reserved
/// address.
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct ReservedAddressClaim {
    /// The federation's index of the output being claimed. A claim the
    /// federation rejects is replaced by the next claim of the same output.
    pub output_index: u64,
    pub operation_id: OperationId,
}

impl_db_record!(
    key = ReservedAddressKey,
    value = ReservedAddress,
    db_prefix = DbKeyPrefix::ReservedAddress,
    notify_on_modify = true,
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ReservedAddressPrefix;

impl_db_lookup!(
    key = ReservedAddressKey,
    query_prefix = ReservedAddressPrefix
);

/// The highest valid address index a payment has been found for. Only the
/// valid indices above it are still handed out.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct HighestUsedAddressIndexKey;

impl_db_record!(
    key = HighestUsedAddressIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::HighestUsedAddressIndex
);

/// A rescan of the federation's outputs, from when it is asked for until the
/// scanner has caught up with them again.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct RescanKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub enum RescanState {
    /// The scanner has not started over yet.
    Requested,
    /// The scanner started over from the federation's first output and has
    /// not caught up yet.
    Running,
}

impl_db_record!(
    key = RescanKey,
    value = RescanState,
    db_prefix = DbKeyPrefix::Rescan
);
