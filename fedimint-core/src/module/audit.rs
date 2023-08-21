use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use futures::StreamExt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::db::{DatabaseKey, DatabaseLookup, DatabaseRecord, ModuleDatabaseTransaction};

#[derive(Default)]
pub struct Audit {
    items: Vec<AuditItem>,
}

impl Audit {
    pub fn net_assets(&self) -> AuditItem {
        AuditItem {
            name: "Net assets (sats)".to_string(),
            milli_sat: calculate_net_assets(self.items.iter()),
            module_name: "".to_string(),
        }
    }

    pub async fn add_items<KP, F>(
        &mut self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        module_name: &str,
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
            .map(|(key, value)| {
                let name = format!("{key:?}");
                let milli_sat = to_milli_sat(key, value);
                AuditItem {
                    name,
                    milli_sat,
                    module_name: module_name.to_string(),
                }
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
        formatter.write_fmt(format_args!("\n{}", self.net_assets()))
    }
}

pub struct AuditItem {
    pub name: String,
    pub milli_sat: i64,
    pub module_name: String,
}

impl Display for AuditItem {
    fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
        let sats = (self.milli_sat as f64) / 1000.0;
        formatter.write_fmt(format_args!(
            "{:>+15.3}|{:>10}|{}",
            sats, self.module_name, self.name
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditSummary {
    pub net_assets: i64,
    pub module_summaries: HashMap<String, ModuleSummary>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ModuleSummary {
    pub net_assets: i64,
}

impl AuditSummary {
    pub fn from_audit(audit: &Audit) -> Self {
        AuditSummary {
            net_assets: calculate_net_assets(audit.items.iter()),
            module_summaries: generate_module_summaries(&audit.items),
        }
    }
}

fn generate_module_summaries(audit_items: &[AuditItem]) -> HashMap<String, ModuleSummary> {
    audit_items
        .iter()
        .map(|item| (item.module_name.clone(), item))
        .into_group_map()
        .into_iter()
        .map(|(module_name, module_audit_items)| {
            (
                module_name,
                ModuleSummary {
                    net_assets: calculate_net_assets(module_audit_items.into_iter()),
                },
            )
        })
        .collect()
}

fn calculate_net_assets<'a>(items: impl Iterator<Item = &'a AuditItem>) -> i64 {
    items.map(|item| item.milli_sat).sum()
}

#[test]
fn creates_audit_summary_from_audit() {
    let audit = Audit {
        items: vec![
            AuditItem {
                name: "ContractKey(...)".to_string(),
                milli_sat: -101_000,
                module_name: "ln".to_string(),
            },
            AuditItem {
                name: "IssuanceTotal".to_string(),
                milli_sat: -50_100_000,
                module_name: "mint".to_string(),
            },
            AuditItem {
                name: "Redemption(...)".to_string(),
                milli_sat: 101_000,
                module_name: "mint".to_string(),
            },
            AuditItem {
                name: "RedemptionTotal".to_string(),
                milli_sat: 100_000,
                module_name: "mint".to_string(),
            },
            AuditItem {
                name: "UTXOKey(...)".to_string(),
                milli_sat: 20_000_000,
                module_name: "wallet".to_string(),
            },
            AuditItem {
                name: "UTXOKey(...)".to_string(),
                milli_sat: 10_000_000,
                module_name: "wallet".to_string(),
            },
            AuditItem {
                name: "UTXOKey(...)".to_string(),
                milli_sat: 20_000_000,
                module_name: "wallet".to_string(),
            },
        ],
    };

    let audit_summary = AuditSummary::from_audit(&audit);
    let expected_audit_summary = AuditSummary {
        net_assets: 0,
        module_summaries: HashMap::from([
            (
                "ln".to_string(),
                ModuleSummary {
                    net_assets: -101_000,
                },
            ),
            (
                "mint".to_string(),
                ModuleSummary {
                    net_assets: -49_899_000,
                },
            ),
            (
                "wallet".to_string(),
                ModuleSummary {
                    net_assets: 50_000_000,
                },
            ),
        ]),
    };

    assert_eq!(audit_summary, expected_audit_summary);
}
