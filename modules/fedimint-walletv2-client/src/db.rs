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
    LowestUnusedAddressIndex = 0x34,
    RecoveryScan = 0x35,
    UnclaimedOutput = 0x36,
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

/// The lowest address index that is still handed out, zero if absent. Every
/// valid index below it was paid, or lies below one that was.
///
/// A reservation writes it back unchanged, so that its transaction conflicts
/// with one that found a payment to the address meanwhile.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct LowestUnusedAddressIndexKey;

impl_db_record!(
    key = LowestUnusedAddressIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::LowestUnusedAddressIndex
);

/// Where a recovery's scan of the federation's outputs stands. Absent in a
/// wallet that was not recovered.
///
/// It is kept once the scan is over. The client has a recovery prepared
/// every time it is opened until all of its modules have recovered, which
/// can be after this scan is over, and the scan must not start anew then.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct RecoveryScanKey;

/// See [`RecoveryScanKey`].
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub enum RecoveryScan {
    /// The output scanner has yet to catch up with the federation's outputs.
    /// Until it has, it keeps all the addresses derived that a reservation
    /// could have been made for, and no address is handed out.
    Scanning,
    /// The output scanner has caught up with the federation's outputs.
    Complete,
}

impl_db_record!(
    key = RecoveryScanKey,
    value = RecoveryScan,
    db_prefix = DbKeyPrefix::RecoveryScan,
    notify_on_modify = true,
);

/// An unspent output the output scanner found paid to one of this wallet's
/// addresses, by the federation's index of it. The value is the index its
/// address is derived at.
///
/// The scanner writes it before it moves on to the next output and removes
/// it once the output is claimed, turns out to be spent, or is not worth
/// claiming. A payment that cannot be claimed when it is found is therefore
/// not lost to the scan having passed it: it is claimed by a later pass, in
/// this run of the client or a later one.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnclaimedOutputKey(pub u64);

impl_db_record!(
    key = UnclaimedOutputKey,
    value = u64,
    db_prefix = DbKeyPrefix::UnclaimedOutput
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnclaimedOutputPrefix;

impl_db_lookup!(
    key = UnclaimedOutputKey,
    query_prefix = UnclaimedOutputPrefix
);
