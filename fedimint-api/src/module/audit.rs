use crate::db::{Database, DatabaseKeyPrefix, DatabaseKeyPrefixConst};

use std::fmt::{Display, Formatter};

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

    pub fn add_items<KP, F>(&mut self, db: &Database, key_prefix: &KP, to_milli_sat: F)
    where
        KP: DatabaseKeyPrefix + DatabaseKeyPrefixConst + 'static,
        F: Fn(KP::Key, KP::Value) -> i64,
    {
        let mut new_items = db
            .find_by_prefix(key_prefix)
            .map(|res| {
                let (key, value) = res.expect("DB error");
                let name = format!("{:?}", key);
                let milli_sat = to_milli_sat(key, value);
                AuditItem { name, milli_sat }
            })
            .collect();
        self.items.append(&mut new_items);
    }
}

impl Display for Audit {
    fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("- Balance Sheet -")?;
        for item in &self.items {
            formatter.write_fmt(format_args!("\n{}", item))?;
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
