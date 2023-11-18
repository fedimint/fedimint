use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use fedimint_core::core::ModuleInstanceId;
use futures::StreamExt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::db::{
    DatabaseKey, DatabaseLookup, DatabaseRecord, DatabaseTransaction,
    IDatabaseTransactionOpsCoreTyped,
};
use crate::task::{MaybeSend, MaybeSync};

#[derive(Default)]
pub struct Audit {
    items: Vec<AuditItem>,
}

impl Audit {
    pub fn net_assets(&self) -> AuditItem {
        AuditItem {
            name: "Net assets (sats)".to_string(),
            milli_sat: calculate_net_assets(self.items.iter()),
            module_instance_id: None,
        }
    }

    pub async fn add_items<KP, F>(
        &mut self,
        dbtx: &mut DatabaseTransaction<'_, '_>,
        module_instance_id: ModuleInstanceId,
        key_prefix: &KP,
        to_milli_sat: F,
    ) where
        KP: DatabaseLookup + 'static + MaybeSend + MaybeSync,
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
                    module_instance_id: Some(module_instance_id),
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
    pub module_instance_id: Option<ModuleInstanceId>,
}

impl Display for AuditItem {
    fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
        let sats = (self.milli_sat as f64) / 1000.0;
        formatter.write_fmt(format_args!("{:>+15.3}|{}", sats, self.name))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditSummary {
    pub net_assets: i64,
    pub module_summaries: HashMap<ModuleInstanceId, ModuleSummary>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ModuleSummary {
    pub net_assets: i64,
    pub kind: String,
}

impl AuditSummary {
    pub fn from_audit(
        audit: &Audit,
        module_instance_id_to_kind: &HashMap<ModuleInstanceId, String>,
    ) -> Self {
        let empty_module_placeholders = module_instance_id_to_kind
            .iter()
            .map(|(id, _)| create_empty_module_placeholder(*id))
            .collect::<Vec<_>>();
        AuditSummary {
            net_assets: calculate_net_assets(audit.items.iter()),
            module_summaries: generate_module_summaries(
                audit.items.iter().chain(&empty_module_placeholders),
                module_instance_id_to_kind,
            ),
        }
    }
}

fn generate_module_summaries<'a>(
    audit_items: impl Iterator<Item = &'a AuditItem>,
    module_instance_id_to_kind: &HashMap<ModuleInstanceId, String>,
) -> HashMap<ModuleInstanceId, ModuleSummary> {
    audit_items
        .filter_map(|item| {
            item.module_instance_id
                .as_ref()
                .map(|module_instance_id| (module_instance_id, item))
        })
        .into_group_map()
        .into_iter()
        .map(|(module_instance_id, module_audit_items)| {
            let kind = module_instance_id_to_kind
                .get(module_instance_id)
                .expect("module instance id should have a kind")
                .to_string();
            (
                *module_instance_id,
                ModuleSummary {
                    net_assets: calculate_net_assets(module_audit_items.into_iter()),
                    kind,
                },
            )
        })
        .collect()
}

fn calculate_net_assets<'a>(items: impl Iterator<Item = &'a AuditItem>) -> i64 {
    items.map(|item| item.milli_sat).sum()
}

// Adding a placeholder ensures that a ModuleSummary exists even if the module
// does not have any AuditItems (e.g. from a lack of activity, db compaction,
// etc), which is useful for downstream consumers of AuditSummaries.
fn create_empty_module_placeholder(module_instance_id: ModuleInstanceId) -> AuditItem {
    AuditItem {
        name: "Module placeholder".to_string(),
        milli_sat: 0,
        module_instance_id: Some(module_instance_id),
    }
}

#[test]
fn creates_audit_summary_from_audit() {
    let audit = Audit {
        items: vec![
            AuditItem {
                name: "ContractKey(...)".to_string(),
                milli_sat: -101_000,
                module_instance_id: Some(0),
            },
            AuditItem {
                name: "IssuanceTotal".to_string(),
                milli_sat: -50_100_000,
                module_instance_id: Some(1),
            },
            AuditItem {
                name: "Redemption(...)".to_string(),
                milli_sat: 101_000,
                module_instance_id: Some(1),
            },
            AuditItem {
                name: "RedemptionTotal".to_string(),
                milli_sat: 100_000,
                module_instance_id: Some(1),
            },
            AuditItem {
                name: "UTXOKey(...)".to_string(),
                milli_sat: 20_000_000,
                module_instance_id: Some(2),
            },
            AuditItem {
                name: "UTXOKey(...)".to_string(),
                milli_sat: 10_000_000,
                module_instance_id: Some(2),
            },
            AuditItem {
                name: "UTXOKey(...)".to_string(),
                milli_sat: 20_000_000,
                module_instance_id: Some(2),
            },
        ],
    };

    let audit_summary = AuditSummary::from_audit(
        &audit,
        &HashMap::from([
            (0, "ln".to_string()),
            (1, "mint".to_string()),
            (2, "wallet".to_string()),
        ]),
    );
    let expected_audit_summary = AuditSummary {
        net_assets: 0,
        module_summaries: HashMap::from([
            (
                0,
                ModuleSummary {
                    net_assets: -101_000,
                    kind: "ln".to_string(),
                },
            ),
            (
                1,
                ModuleSummary {
                    net_assets: -49_899_000,
                    kind: "mint".to_string(),
                },
            ),
            (
                2,
                ModuleSummary {
                    net_assets: 50_000_000,
                    kind: "wallet".to_string(),
                },
            ),
        ]),
    };

    assert_eq!(audit_summary, expected_audit_summary);
}

#[test]
fn audit_summary_includes_placeholders() {
    let audit_summary = AuditSummary::from_audit(
        &Audit::default(),
        &HashMap::from([
            (0, "ln".to_string()),
            (1, "mint".to_string()),
            (2, "wallet".to_string()),
        ]),
    );
    let expected_audit_summary = AuditSummary {
        net_assets: 0,
        module_summaries: HashMap::from([
            (
                0,
                ModuleSummary {
                    net_assets: 0,
                    kind: "ln".to_string(),
                },
            ),
            (
                1,
                ModuleSummary {
                    net_assets: 0,
                    kind: "mint".to_string(),
                },
            ),
            (
                2,
                ModuleSummary {
                    net_assets: 0,
                    kind: "wallet".to_string(),
                },
            ),
        ]),
    };

    assert_eq!(audit_summary, expected_audit_summary);
}
