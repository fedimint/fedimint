use std::sync::Arc;
use std::time::Duration;

use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::runtime::sleep;
use fedimint_core::util::FmtCompact as _;
use fedimint_logging::LOG_CLIENT;
use tracing::debug;

use crate::Client;
use crate::db::DecommissionAnnouncementKey;

pub(crate) async fn run_decommission_announcement_task(client: Arc<Client>) {
    loop {
        match client.api.decommission_announcement().await {
            Ok(announcement) => {
                let mut dbtx = client.db().begin_transaction().await;

                match announcement {
                    Some(a) => {
                        dbtx.insert_entry(&DecommissionAnnouncementKey, &a).await;
                    }
                    None => {
                        dbtx.remove_entry(&DecommissionAnnouncementKey).await;
                    }
                }

                dbtx.commit_tx().await;
            }
            Err(err) => {
                debug!(
                    target: LOG_CLIENT,
                    err = %err.fmt_compact(),
                    "Failed to fetch decommission announcement"
                );
            }
        }

        sleep(Duration::from_secs(86400)).await; // Check once a day
    }
}
