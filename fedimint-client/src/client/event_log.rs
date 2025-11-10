use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use fedimint_eventlog::EventLogTrimableId;

use crate::db::DbKeyPrefixInternalReserved;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
pub(crate) struct DefaultApplicationEventLogKey;

impl_db_record!(
    key = DefaultApplicationEventLogKey,
    value = EventLogTrimableId,
    db_prefix = DbKeyPrefixInternalReserved::DefaultApplicationEventLogPos,
);
