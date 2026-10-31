use std::collections::BTreeMap;
use std::str::FromStr as _;

use fedimint_core::PeerId;
use fedimint_core::core::{
    DynInput, DynModuleConsensusItem, DynOutput, DynUnknown, ModuleInstanceId, ModuleKind,
};
use fedimint_core::session_outcome::{AcceptedItem, ConsensusItem};
use fedimint_core::transaction::{Transaction, TransactionSignature};
use fedimint_lnv2_client::common::LightningConsensusItem;
use fedimint_meta_client::common::{MetaConsensusItem, MetaKey, MetaValue};

use super::view::{
    ItemDetails, ItemFilter, ItemTypeFilter, ItemView, ModuleItemContent, ModuleRef,
    SessionSummary, Style, format_item_line, format_session_line, format_utc_date_time,
    format_utc_time, item_json, session_json, truncate, variant_name,
};

const LNV2: ModuleInstanceId = 0;
const META: ModuleInstanceId = 1;
const MINTV2: ModuleInstanceId = 2;
const WALLETV2: ModuleInstanceId = 3;
/// Not part of the federation config
const UNKNOWN: ModuleInstanceId = 7;

const PLAIN: Style = Style { color: false };

fn kinds() -> BTreeMap<ModuleInstanceId, ModuleKind> {
    BTreeMap::from([
        (LNV2, ModuleKind::from_static_str("lnv2")),
        (META, ModuleKind::from_static_str("meta")),
        (MINTV2, ModuleKind::from_static_str("mintv2")),
        (WALLETV2, ModuleKind::from_static_str("walletv2")),
    ])
}

fn module(instance_id: ModuleInstanceId) -> ModuleRef {
    ModuleRef::new(instance_id, &kinds())
}

fn transaction(inputs: &[ModuleInstanceId], outputs: &[ModuleInstanceId]) -> Transaction {
    Transaction {
        inputs: inputs
            .iter()
            .map(|id| DynInput::from_typed(*id, DynUnknown(vec![1, 2, 3])))
            .collect(),
        outputs: outputs
            .iter()
            .map(|id| DynOutput::from_typed(*id, DynUnknown(vec![4, 5])))
            .collect(),
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    }
}

fn accepted(item: ConsensusItem, peer: u16) -> AcceptedItem {
    AcceptedItem {
        item,
        peer: PeerId::from(peer),
    }
}

fn tx_view(inputs: &[ModuleInstanceId], outputs: &[ModuleInstanceId]) -> ItemView {
    ItemView::from_accepted(
        42,
        0,
        &accepted(ConsensusItem::Transaction(transaction(inputs, outputs)), 1),
        &kinds(),
        true,
    )
}

fn lnv2_view(item: LightningConsensusItem) -> ItemView {
    ItemView::from_accepted(
        42,
        1,
        &accepted(
            ConsensusItem::Module(DynModuleConsensusItem::from_typed(LNV2, item)),
            2,
        ),
        &kinds(),
        true,
    )
}

fn meta_view() -> ItemView {
    ItemView::from_accepted(
        42,
        4,
        &accepted(
            ConsensusItem::Module(DynModuleConsensusItem::from_typed(
                META,
                MetaConsensusItem {
                    salt: 1,
                    key: MetaKey(0),
                    value: MetaValue::from_str("0102").expect("valid hex"),
                },
            )),
            2,
        ),
        &kinds(),
        true,
    )
}

fn undecodable_view(instance_id: ModuleInstanceId) -> ItemView {
    ItemView::from_accepted(
        42,
        2,
        &accepted(
            ConsensusItem::Module(DynModuleConsensusItem::from_typed(
                instance_id,
                DynUnknown(vec![0; 32]),
            )),
            0,
        ),
        &kinds(),
        true,
    )
}

fn other_view() -> ItemView {
    ItemView::from_accepted(
        42,
        3,
        &accepted(
            ConsensusItem::Default {
                variant: 9,
                bytes: vec![0; 12],
            },
            3,
        ),
        &kinds(),
        true,
    )
}

fn filter() -> ItemFilter {
    ItemFilter::default()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn variant_name_takes_leading_identifier() {
    assert_eq!(
        variant_name("BlockCountVote(123)").as_deref(),
        Some("BlockCountVote")
    );
    assert_eq!(
        variant_name("MetaConsensusItem { key: 0 }").as_deref(),
        Some("MetaConsensusItem")
    );
    assert_eq!(variant_name("Signatures").as_deref(), Some("Signatures"));
    assert_eq!(variant_name("(1, 2)"), None);
    assert_eq!(
        variant_name("AVeryLongVariantNameThatGoesOnAndOn(1)").as_deref(),
        Some("AVeryLongVariantN…")
    );
}

#[test]
fn truncate_is_char_aware() {
    assert_eq!(truncate("short", 10), "short");
    assert_eq!(truncate("exactly10!", 10), "exactly10!");
    assert_eq!(truncate("ääääääää", 4), "äää…");
}

#[test]
fn transaction_view_resolves_module_kinds() {
    let view = tx_view(&[MINTV2, MINTV2, UNKNOWN], &[LNV2]);
    let ItemDetails::Transaction {
        txid,
        inputs,
        outputs,
    } = &view.details
    else {
        panic!("expected a transaction, got {view:?}");
    };
    assert_eq!(
        *txid,
        transaction(&[MINTV2, MINTV2, UNKNOWN], &[LNV2]).tx_hash()
    );
    assert_eq!(
        inputs,
        &vec![module(MINTV2), module(MINTV2), module(UNKNOWN)]
    );
    assert_eq!(outputs, &vec![module(LNV2)]);
    assert_eq!(module(UNKNOWN).name(), "unknown#7");
    assert_eq!(view.peer, PeerId::from(1));
}

#[test]
fn module_item_view_extracts_variant_and_summary() {
    let view = lnv2_view(LightningConsensusItem::BlockCountVote(920_131));
    assert_eq!(
        view.details,
        ItemDetails::Module {
            module: module(LNV2),
            content: ModuleItemContent::Decoded {
                variant: Some("BlockCountVote".to_owned()),
                summary: "LNv2 Block Count 920131".to_owned(),
            },
        }
    );
    assert_eq!(view.unix_time_vote, None);

    let meta = meta_view();
    assert_eq!(
        meta.details,
        ItemDetails::Module {
            module: module(META),
            content: ModuleItemContent::Decoded {
                variant: Some("MetaConsensusItem".to_owned()),
                summary: "Meta - len: 2".to_owned(),
            },
        }
    );
    assert!(!meta.is_noise());
    assert!(filter().matches(&meta));
}

#[test]
fn unix_time_votes_are_extracted() {
    assert_eq!(
        lnv2_view(LightningConsensusItem::UnixTimeVote(1_700_000_000)).unix_time_vote,
        Some(1_700_000_000)
    );
}

#[test]
fn undecodable_module_item_is_not_noise() {
    let view = undecodable_view(UNKNOWN);
    assert_eq!(
        view.details,
        ItemDetails::Module {
            module: module(UNKNOWN),
            content: ModuleItemContent::Undecodable { len: 32 },
        }
    );
    assert!(!view.is_noise());
    assert!(filter().matches(&view));
}

#[test]
fn noise_is_hidden_unless_all() {
    for view in [
        lnv2_view(LightningConsensusItem::Default {
            variant: 5,
            bytes: vec![],
        }),
        lnv2_view(LightningConsensusItem::BlockCountVote(1)),
        lnv2_view(LightningConsensusItem::UnixTimeVote(1)),
        other_view(),
    ] {
        assert!(view.is_noise());
        assert!(!filter().matches(&view));
        assert!(
            ItemFilter {
                all: true,
                ..filter()
            }
            .matches(&view)
        );
    }
}

#[test]
fn only_filter_selects_item_type() {
    let tx = tx_view(&[MINTV2], &[MINTV2]);
    let ci = meta_view();

    let only_tx = ItemFilter {
        only: Some(ItemTypeFilter::Transactions),
        ..filter()
    };
    assert!(only_tx.matches(&tx));
    assert!(!only_tx.matches(&ci));

    let only_ci = ItemFilter {
        only: Some(ItemTypeFilter::ModuleItems),
        ..filter()
    };
    assert!(!only_ci.matches(&tx));
    assert!(only_ci.matches(&ci));

    // Unknown core items are neither
    let all = |only| ItemFilter {
        only: Some(only),
        all: true,
        ..filter()
    };
    assert!(!all(ItemTypeFilter::Transactions).matches(&other_view()));
    assert!(!all(ItemTypeFilter::ModuleItems).matches(&other_view()));
}

#[test]
fn module_filter_matches_items_and_touching_transactions() {
    let lnv2 = ItemFilter {
        modules: strings(&["lnv2"]),
        all: true,
        ..filter()
    };
    assert!(lnv2.matches(&tx_view(&[MINTV2], &[LNV2])));
    assert!(lnv2.matches(&tx_view(&[LNV2], &[MINTV2])));
    assert!(!lnv2.matches(&tx_view(&[MINTV2], &[MINTV2])));
    assert!(lnv2.matches(&lnv2_view(LightningConsensusItem::BlockCountVote(1))));
    assert!(!lnv2.matches(&undecodable_view(WALLETV2)));
    assert!(!lnv2.matches(&meta_view()));
    assert!(!lnv2.matches(&other_view()));

    // Noise stays hidden without `--all`
    assert!(
        !ItemFilter {
            all: false,
            ..lnv2.clone()
        }
        .matches(&lnv2_view(LightningConsensusItem::BlockCountVote(1)))
    );

    // Repeated values are ORed, kinds are case insensitive, ids work too
    let lnv2_or_wallet = ItemFilter {
        modules: strings(&["LNv2", "3"]),
        ..filter()
    };
    assert!(lnv2_or_wallet.matches(&undecodable_view(WALLETV2)));
    assert!(lnv2_or_wallet.matches(&tx_view(&[MINTV2], &[LNV2])));
    assert!(!lnv2_or_wallet.matches(&tx_view(&[MINTV2], &[MINTV2])));

    // Modules missing from the config can be selected by instance id
    let unknown = ItemFilter {
        modules: strings(&["7"]),
        ..filter()
    };
    assert!(unknown.matches(&undecodable_view(UNKNOWN)));
}

#[test]
fn input_output_filters_only_match_transactions() {
    let pay_ln = tx_view(&[MINTV2, MINTV2], &[LNV2, MINTV2]);
    let receive_ln = tx_view(&[LNV2], &[MINTV2]);
    let ci = meta_view();

    let output_lnv2 = ItemFilter {
        outputs: strings(&["lnv2"]),
        ..filter()
    };
    assert!(output_lnv2.matches(&pay_ln));
    assert!(!output_lnv2.matches(&receive_ln));
    assert!(!output_lnv2.matches(&ci));

    let input_lnv2 = ItemFilter {
        inputs: strings(&["lnv2"]),
        ..filter()
    };
    assert!(!input_lnv2.matches(&pay_ln));
    assert!(input_lnv2.matches(&receive_ln));
    assert!(!input_lnv2.matches(&ci));

    // Different criteria must all match
    let mint_in_ln_out = ItemFilter {
        inputs: strings(&["mintv2"]),
        outputs: strings(&["lnv2"]),
        ..filter()
    };
    assert!(mint_in_ln_out.matches(&pay_ln));
    assert!(!mint_in_ln_out.matches(&receive_ln));

    let wallet_and_ln_out = ItemFilter {
        modules: strings(&["walletv2"]),
        outputs: strings(&["lnv2"]),
        ..filter()
    };
    assert!(!wallet_and_ln_out.matches(&pay_ln));
}

#[test]
fn format_transaction_line() {
    let view = tx_view(&[MINTV2, MINTV2, MINTV2, UNKNOWN], &[LNV2, MINTV2, MINTV2]);
    let ItemDetails::Transaction { txid, .. } = &view.details else {
        panic!("expected a transaction");
    };
    assert_eq!(
        format_item_line(&view, PLAIN),
        format!(
            "     42.0    p1  tx  {}  mintv2×3 unknown#7 → lnv2 mintv2×2",
            txid.fmt_short()
        )
    );

    let no_outputs = tx_view(&[MINTV2], &[]);
    assert!(format_item_line(&no_outputs, PLAIN).ends_with("  mintv2 → -"));
}

#[test]
fn format_module_item_lines() {
    assert_eq!(
        format_item_line(
            &lnv2_view(LightningConsensusItem::BlockCountVote(920_131)),
            PLAIN
        ),
        "     42.1    p2  ci  lnv2      BlockCountVote      LNv2 Block Count 920131"
    );
    assert_eq!(
        format_item_line(&undecodable_view(UNKNOWN), PLAIN),
        "     42.2    p0  ci  unknown#7  (no decoder, 32 bytes)"
    );
    assert_eq!(
        format_item_line(&meta_view(), PLAIN),
        "     42.4    p2  ci  meta      MetaConsensusItem   Meta - len: 2"
    );
    assert_eq!(
        format_item_line(&other_view(), PLAIN),
        "     42.3    p3  ??  unknown core item variant 9 (12 bytes)"
    );
}

#[test]
fn format_lines_with_color_only_add_escape_codes() {
    let strip = |s: String| {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    let color = Style { color: true };

    for view in [
        tx_view(&[MINTV2, MINTV2], &[LNV2]),
        meta_view(),
        undecodable_view(UNKNOWN),
        other_view(),
    ] {
        let colored = format_item_line(&view, color);
        assert!(colored.contains('\x1b'));
        assert_eq!(strip(colored), format_item_line(&view, PLAIN));
    }
}

#[test]
fn session_summary_counts_items() {
    let views = [
        tx_view(&[MINTV2], &[LNV2]),
        tx_view(&[LNV2], &[MINTV2]),
        lnv2_view(LightningConsensusItem::BlockCountVote(1)),
        lnv2_view(LightningConsensusItem::UnixTimeVote(300)),
        lnv2_view(LightningConsensusItem::UnixTimeVote(100)),
        lnv2_view(LightningConsensusItem::UnixTimeVote(u64::MAX)),
        other_view(),
    ];
    let summary = SessionSummary::new(42, &views);
    assert_eq!(summary.transactions, 2);
    assert_eq!(summary.module_items, 4);
    assert_eq!(summary.other_items, 1);
    assert_eq!(summary.total(), 7);
    // The median is robust against a single outlier
    assert_eq!(summary.time_vote, Some(300));
    assert_eq!(SessionSummary::new(42, &views[..3]).time_vote, None);
}

#[test]
fn format_session_lines() {
    let mut summary = SessionSummary {
        session_idx: 31_390,
        transactions: 3,
        module_items: 9,
        other_items: 0,
        shown: 12,
        signed_at: None,
        time_vote: None,
    };
    assert_eq!(
        format_session_line(&summary, PLAIN),
        "━━ session 31390 ━━ 12 items: 3 tx, 9 ci"
    );

    summary.time_vote = Some(1_761_660_180);
    assert_eq!(
        format_session_line(&summary, PLAIN),
        "━━ session 31390 · ~2025-10-28 14:03 UTC ━━ 12 items: 3 tx, 9 ci"
    );

    // The observed signing time takes precedence over time votes
    summary.shown = 2;
    summary.other_items = 1;
    summary.signed_at = Some(1_761_660_202);
    assert_eq!(
        format_session_line(&summary, PLAIN),
        "━━ session 31390 · signed 14:03:22 UTC ━━ 13 items: 3 tx, 9 ci, 1 other ━━ 11 hidden"
    );

    let empty = SessionSummary {
        session_idx: 7,
        ..SessionSummary::default()
    };
    assert_eq!(format_session_line(&empty, PLAIN), "━━ session 7 ━━ empty");
}

#[test]
fn utc_date_time() {
    assert_eq!(format_utc_date_time(0), "~1970-01-01 00:00 UTC");
    assert_eq!(format_utc_date_time(1_793_175_540), "~2026-10-28 08:19 UTC");
    assert!(format_utc_date_time(u64::MAX).contains("invalid"));
}

#[test]
fn utc_time_wraps_days() {
    assert_eq!(format_utc_time(0), "00:00:00 UTC");
    assert_eq!(format_utc_time(86_399), "23:59:59 UTC");
    assert_eq!(format_utc_time(86_400 + 61), "00:01:01 UTC");
}

#[test]
fn json_lines() {
    let view = tx_view(&[MINTV2], &[LNV2, UNKNOWN]);
    let ItemDetails::Transaction { txid, .. } = &view.details else {
        panic!("expected a transaction");
    };
    assert_eq!(
        item_json(&view),
        serde_json::json!({
            "type": "item",
            "session": 42,
            "item": 0,
            "peer": 1,
            "signed": true,
            "item_type": "transaction",
            "txid": txid.fmt_full().to_string(),
            "inputs": [{"id": MINTV2, "kind": "mintv2"}],
            "outputs": [{"id": LNV2, "kind": "lnv2"}, {"id": UNKNOWN, "kind": null}],
        })
    );

    assert_eq!(
        item_json(&lnv2_view(LightningConsensusItem::UnixTimeVote(5))),
        serde_json::json!({
            "type": "item",
            "session": 42,
            "item": 1,
            "peer": 2,
            "signed": true,
            "item_type": "module",
            "module": {"id": LNV2, "kind": "lnv2"},
            "variant": "UnixTimeVote",
            "summary": "LNv2 Unix Time 5",
        })
    );

    let line = item_json(&undecodable_view(UNKNOWN)).to_string();
    assert!(!line.contains('\n'));

    assert_eq!(
        session_json(&SessionSummary {
            session_idx: 9,
            transactions: 1,
            module_items: 2,
            other_items: 0,
            shown: 1,
            signed_at: Some(100),
            time_vote: None,
        }),
        serde_json::json!({
            "type": "session",
            "session": 9,
            "items": 3,
            "transactions": 1,
            "module_items": 2,
            "other_items": 0,
            "shown": 1,
            "signed_at": 100,
            "time_vote": null,
        })
    );
}
