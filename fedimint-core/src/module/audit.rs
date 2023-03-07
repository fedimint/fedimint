use std::fmt::{Display, Formatter};

use futures::StreamExt;

use crate::core::ModuleInstanceId;
use crate::db::{DatabaseKey, DatabaseLookup, DatabaseRecord, ModuleDatabaseTransaction};

#[derive(Default)]
pub struct Audit {
    items: Vec<AuditItem>,
}

impl Audit {
    pub fn sum(&self) -> AuditItem {
        let mut sum = 0;

        for item in &self.items {
            sum += item.milli_sat;
        }
        AuditItem {
            name: "Total sats".to_string(),
            milli_sat: sum,
        }
    }

    pub async fn add_items<KP, F>(
        &mut self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        key_prefix: &KP,
        to_milli_sat: F,
    ) where
        KP: DatabaseLookup + 'static,
        KP::Record: DatabaseKey,
        F: Fn(KP::Record, <<KP as DatabaseLookup>::Record as DatabaseRecord>::Value) -> i64,
    {
        let mut new_items = dbtx
            .find_by_prefix(key_prefix)
            .await
            .map(|res| {
                let (key, value) = res.expect("DB error");
                let name = format!("{key:?}");
                let milli_sat = to_milli_sat(key, value);
                AuditItem { name, milli_sat }
            })
            .collect::<Vec<AuditItem>>()
            .await;
        self.items.append(&mut new_items);
    }
}

impl Display for Audit {
    fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("- Balance Sheet -")?;
        for item in &self.items {
            formatter.write_fmt(format_args!("\n{item}"))?;
        }
        formatter.write_fmt(format_args!("\n{}", self.sum()))
    }
}

pub struct AuditItem {
    pub name: String,
    pub milli_sat: i64,
}

impl Display for AuditItem {
    fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
        let sats = (self.milli_sat as f64) / 1000.0;
        formatter.write_fmt(format_args!("{:>+15.3}|{}", sats, self.name))
    }
}
