//! Pure (network-free) view of consensus history items: conversion from
//! [`AcceptedItem`], filtering and line/JSON formatting.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use fedimint_core::core::{DynModuleConsensusItem, DynUnknown, ModuleInstanceId, ModuleKind};
use fedimint_core::session_outcome::{AcceptedItem, ConsensusItem};
use fedimint_core::{PeerId, TransactionId};
use fedimint_lnv2_client::common::LightningConsensusItem as Lnv2ConsensusItem;
use serde_json::{Value, json};
use time::OffsetDateTime;

/// Max number of characters of a module consensus item's `Display` summary
const SUMMARY_MAX_CHARS: usize = 60;
/// Max number of characters of a module consensus item's variant name
const VARIANT_MAX_CHARS: usize = 18;
/// Width of the module kind column (fits `walletv2`)
const KIND_COLUMN_WIDTH: usize = 8;

/// Module consensus item variants hidden unless `--all` is given: periodic
/// guardian votes (block count, feerate, unix time) that make up most of a
/// session, protocol upgrade bookkeeping and placeholders for variants the
/// module itself does not understand.
pub const NOISE_VARIANTS: &[&str] = &[
    "BlockCount",
    "BlockCountVote",
    "Feerate",
    "UnixTimeVote",
    "ModuleConsensusVersion",
    "Default",
];

/// A reference to a module instance, as seen in a transaction input/output or
/// a module consensus item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRef {
    pub instance_id: ModuleInstanceId,
    /// `None` if the federation config does not contain the instance
    pub kind: Option<ModuleKind>,
}

impl ModuleRef {
    pub fn new(
        instance_id: ModuleInstanceId,
        kinds: &BTreeMap<ModuleInstanceId, ModuleKind>,
    ) -> Self {
        Self {
            instance_id,
            kind: kinds.get(&instance_id).cloned(),
        }
    }

    /// Human readable name: the module kind, or `unknown#<id>`
    pub fn name(&self) -> String {
        match &self.kind {
            Some(kind) => kind.as_str().to_owned(),
            None => format!("unknown#{}", self.instance_id),
        }
    }

    /// Whether `selector` (a module kind like `lnv2`, or an instance id)
    /// refers to this module
    pub fn matches(&self, selector: &str) -> bool {
        self.kind
            .as_ref()
            .is_some_and(|kind| kind.as_str().eq_ignore_ascii_case(selector))
            || self.instance_id.to_string() == selector
    }
}

/// What we know about the content of a module consensus item
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleItemContent {
    /// The client has a decoder for this module
    Decoded {
        /// Variant name, derived from the `Debug` representation
        variant: Option<String>,
        /// The item's `Display` representation
        summary: String,
    },
    /// No decoder available, only the raw length is known
    Undecodable { len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemDetails {
    Transaction {
        txid: TransactionId,
        inputs: Vec<ModuleRef>,
        outputs: Vec<ModuleRef>,
    },
    Module {
        module: ModuleRef,
        content: ModuleItemContent,
    },
    /// A core consensus item variant unknown to this client
    Other { variant: u64, len: usize },
}

/// One accepted consensus item, reduced to what we display
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemView {
    pub session_idx: u64,
    pub item_idx: usize,
    pub peer: PeerId,
    /// `false` for items of a session that is not signed yet (`--pending`)
    pub signed: bool,
    pub details: ItemDetails,
    /// Unix time voted for by the proposing guardian (LNv2 `UnixTimeVote`)
    pub unix_time_vote: Option<u64>,
}

impl ItemView {
    pub fn from_accepted(
        session_idx: u64,
        item_idx: usize,
        accepted: &AcceptedItem,
        kinds: &BTreeMap<ModuleInstanceId, ModuleKind>,
        signed: bool,
    ) -> Self {
        let mut unix_time_vote = None;
        let details = match &accepted.item {
            ConsensusItem::Transaction(tx) => ItemDetails::Transaction {
                txid: tx.tx_hash(),
                inputs: tx
                    .inputs
                    .iter()
                    .map(|input| ModuleRef::new(input.module_instance_id(), kinds))
                    .collect(),
                outputs: tx
                    .outputs
                    .iter()
                    .map(|output| ModuleRef::new(output.module_instance_id(), kinds))
                    .collect(),
            },
            ConsensusItem::Module(ci) => {
                if let Some(Lnv2ConsensusItem::UnixTimeVote(time)) =
                    ci.as_any().downcast_ref::<Lnv2ConsensusItem>()
                {
                    unix_time_vote = Some(*time);
                }
                ItemDetails::Module {
                    module: ModuleRef::new(ci.module_instance_id(), kinds),
                    content: module_item_content(ci),
                }
            }
            ConsensusItem::Default { variant, bytes } => ItemDetails::Other {
                variant: *variant,
                len: bytes.len(),
            },
        };

        Self {
            session_idx,
            item_idx,
            peer: accepted.peer,
            signed,
            details,
            unix_time_vote,
        }
    }

    /// Items that are hidden by default, see [`NOISE_VARIANTS`]
    pub fn is_noise(&self) -> bool {
        match &self.details {
            ItemDetails::Transaction { .. } => false,
            ItemDetails::Module { content, .. } => match content {
                ModuleItemContent::Decoded { variant, .. } => variant
                    .as_deref()
                    .is_some_and(|variant| NOISE_VARIANTS.contains(&variant)),
                ModuleItemContent::Undecodable { .. } => false,
            },
            ItemDetails::Other { .. } => true,
        }
    }
}

fn module_item_content(ci: &DynModuleConsensusItem) -> ModuleItemContent {
    if let Some(unknown) = ci.as_any().downcast_ref::<DynUnknown>() {
        return ModuleItemContent::Undecodable {
            len: unknown.0.len(),
        };
    }

    ModuleItemContent::Decoded {
        variant: variant_name(&format!("{:?}", &**ci)),
        summary: (**ci).to_string(),
    }
}

/// Extracts the leading identifier of a `Debug` representation, e.g.
/// `BlockCountVote` from `BlockCountVote(123)`
pub fn variant_name(debug: &str) -> Option<String> {
    let name: String = debug
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();

    (!name.is_empty()).then(|| truncate(&name, VARIANT_MAX_CHARS))
}

/// Truncates `s` to at most `max_chars` characters, marking truncation with
/// `…`
pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_owned();
    }

    let mut truncated: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

/// Restricts output to one type of consensus item
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ItemTypeFilter {
    /// Only transactions
    #[value(alias = "tx")]
    Transactions,
    /// Only module consensus items
    #[value(alias = "ci")]
    ModuleItems,
}

/// Item filter; all given criteria must match (a repeated criterion matches if
/// any of its values matches)
#[derive(Debug, Clone, Default)]
pub struct ItemFilter {
    pub only: Option<ItemTypeFilter>,
    /// Module CIs of these modules and transactions touching them
    pub modules: Vec<String>,
    /// Transactions with at least one input of these modules
    pub inputs: Vec<String>,
    /// Transactions with at least one output of these modules
    pub outputs: Vec<String>,
    /// Also show items considered noise, see [`ItemView::is_noise`]
    pub all: bool,
}

impl ItemFilter {
    pub fn matches(&self, item: &ItemView) -> bool {
        if !self.all && item.is_noise() {
            return false;
        }

        let any_match = |refs: &[ModuleRef], selectors: &[String]| -> bool {
            refs.iter()
                .any(|module| selectors.iter().any(|sel| module.matches(sel)))
        };

        match &item.details {
            ItemDetails::Transaction {
                inputs, outputs, ..
            } => {
                self.only != Some(ItemTypeFilter::ModuleItems)
                    && (self.modules.is_empty()
                        || any_match(inputs, &self.modules)
                        || any_match(outputs, &self.modules))
                    && (self.inputs.is_empty() || any_match(inputs, &self.inputs))
                    && (self.outputs.is_empty() || any_match(outputs, &self.outputs))
            }
            ItemDetails::Module { module, .. } => {
                self.only != Some(ItemTypeFilter::Transactions)
                    && (self.modules.is_empty()
                        || any_match(std::slice::from_ref(module), &self.modules))
                    && self.inputs.is_empty()
                    && self.outputs.is_empty()
            }
            ItemDetails::Other { .. } => {
                self.only.is_none()
                    && self.modules.is_empty()
                    && self.inputs.is_empty()
                    && self.outputs.is_empty()
            }
        }
    }
}

/// Per-session statistics, printed after the session's items
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionSummary {
    pub session_idx: u64,
    pub transactions: usize,
    pub module_items: usize,
    pub other_items: usize,
    /// Number of items that passed the filter
    pub shown: usize,
    /// Wall clock time (unix seconds) at which we observed the session being
    /// signed; only known for sessions we waited for
    pub signed_at: Option<u64>,
    /// Median of the unix times guardians voted for during the session, an
    /// approximation of when the session happened
    pub time_vote: Option<u64>,
}

impl SessionSummary {
    pub fn new(session_idx: u64, items: &[ItemView]) -> Self {
        let mut time_votes: Vec<u64> = items.iter().filter_map(|i| i.unix_time_vote).collect();
        time_votes.sort_unstable();

        let mut summary = Self {
            session_idx,
            time_vote: time_votes.get(time_votes.len() / 2).copied(),
            ..Self::default()
        };
        for item in items {
            match item.details {
                ItemDetails::Transaction { .. } => summary.transactions += 1,
                ItemDetails::Module { .. } => summary.module_items += 1,
                ItemDetails::Other { .. } => summary.other_items += 1,
            }
        }
        summary
    }

    pub fn total(&self) -> usize {
        self.transactions + self.module_items + self.other_items
    }
}

/// ANSI styling, a no-op if colors are disabled
#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub color: bool,
}

const DIM: &str = "2";
const BOLD: &str = "1";
const RED: &str = "31";
const GREEN: &str = "32";
const CYAN: &str = "36";
const BOLD_GREEN: &str = "1;32";
/// Colors assigned to peers and module kinds
const PALETTE: &[&str] = &["33", "35", "34", "36", "32", "91", "93", "95", "94", "96"];

impl Style {
    fn paint(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn peer(self, peer: PeerId) -> String {
        self.paint(
            PALETTE[peer.to_usize() % PALETTE.len()],
            &format!("p{peer}"),
        )
    }

    /// Paints a (pre-padded) module name in a color derived from the name, so
    /// each module kind keeps its color across lines
    fn module(self, module: &ModuleRef, padded: &str) -> String {
        if module.kind.is_none() {
            return self.paint(RED, padded);
        }
        let name = module.name();
        let hash = name.bytes().fold(0usize, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(usize::from(b))
        });
        self.paint(PALETTE[hash % PALETTE.len()], padded)
    }
}

/// Formats a list of module references as `kind×count` groups in order of
/// first appearance, e.g. `mintv2×3 lnv2`
pub fn format_module_counts(refs: &[ModuleRef], style: Style) -> String {
    if refs.is_empty() {
        return style.paint(DIM, "-");
    }

    let mut groups: Vec<(&ModuleRef, usize)> = vec![];
    for module in refs {
        match groups.iter_mut().find(|(m, _)| *m == module) {
            Some((_, count)) => *count += 1,
            None => groups.push((module, 1)),
        }
    }

    groups
        .into_iter()
        .map(|(module, count)| {
            let name = style.module(module, &module.name());
            if count > 1 {
                format!("{name}{}", style.paint(DIM, &format!("×{count}")))
            } else {
                name
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One line per item, e.g.
/// `31390.4    p2  tx  3f2a1b9c_8e7d6c5b  mintv2×3 → lnv2 mintv2`
pub fn format_item_line(item: &ItemView, style: Style) -> String {
    let mut line = format!(
        "{} {}  ",
        style.paint(
            DIM,
            &format!("{:>7}.{:<4}", item.session_idx, item.item_idx)
        ),
        style.peer(item.peer),
    );

    match &item.details {
        ItemDetails::Transaction {
            txid,
            inputs,
            outputs,
        } => {
            let _ = write!(
                line,
                "{}  {}  {} {} {}",
                style.paint(BOLD_GREEN, "tx"),
                style.paint(BOLD, &txid.fmt_short().to_string()),
                format_module_counts(inputs, style),
                style.paint(DIM, "→"),
                format_module_counts(outputs, style),
            );
        }
        ItemDetails::Module { module, content } => {
            let kind = format!("{:<KIND_COLUMN_WIDTH$}", module.name());
            let _ = write!(
                line,
                "{}  {}  ",
                style.paint(CYAN, "ci"),
                style.module(module, &kind)
            );
            match content {
                ModuleItemContent::Decoded { variant, summary } => {
                    let variant =
                        format!("{:<VARIANT_MAX_CHARS$}", variant.as_deref().unwrap_or("?"));
                    let _ = write!(
                        line,
                        "{}  {}",
                        variant,
                        style.paint(DIM, &truncate(summary, SUMMARY_MAX_CHARS))
                    );
                }
                ModuleItemContent::Undecodable { len } => {
                    let _ = write!(
                        line,
                        "{}",
                        style.paint(DIM, &format!("(no decoder, {len} bytes)"))
                    );
                }
            }
        }
        ItemDetails::Other { variant, len } => {
            let _ = write!(
                line,
                "{}  {}",
                style.paint(RED, "??"),
                style.paint(
                    DIM,
                    &format!("unknown core item variant {variant} ({len} bytes)")
                )
            );
        }
    }

    line
}

/// Session separator, printed after the session's items, e.g.
/// `━━ session 31390 · signed 14:03:22 UTC ━━ 12 items: 3 tx, 9 ci ━━ 10
/// hidden`
pub fn format_session_line(summary: &SessionSummary, style: Style) -> String {
    let sep = style.paint(DIM, "━━");
    let mut line = format!(
        "{sep} {}",
        style.paint(BOLD, &format!("session {}", summary.session_idx))
    );

    // Prefer the time we saw the session being signed over the guardians' time
    // votes, which are only minute precision
    if let Some(signed_at) = summary.signed_at {
        let _ = write!(
            line,
            " · {}",
            style.paint(GREEN, &format!("signed {}", format_utc_time(signed_at)))
        );
    } else if let Some(time_vote) = summary.time_vote {
        let _ = write!(
            line,
            " · {}",
            style.paint(DIM, &format_utc_date_time(time_vote))
        );
    }

    let total = summary.total();
    if total == 0 {
        let _ = write!(line, " {sep} {}", style.paint(DIM, "empty"));
        return line;
    }

    let mut parts = vec![format!("{} tx", summary.transactions)];
    parts.push(format!("{} ci", summary.module_items));
    if summary.other_items > 0 {
        parts.push(format!("{} other", summary.other_items));
    }
    let _ = write!(
        line,
        " {sep} {} item{}: {}",
        total,
        if total == 1 { "" } else { "s" },
        parts.join(", ")
    );
    if summary.shown < total {
        let _ = write!(
            line,
            " {sep} {}",
            style.paint(DIM, &format!("{} hidden", total - summary.shown))
        );
    }

    line
}

/// Formats unix seconds as `HH:MM:SS UTC`
pub fn format_utc_time(unix_secs: u64) -> String {
    let secs_of_day = unix_secs % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Formats unix seconds as `~YYYY-MM-DD HH:MM UTC`, the `~` indicating that
/// the time is approximate
pub fn format_utc_date_time(unix_secs: u64) -> String {
    match i64::try_from(unix_secs)
        .ok()
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
    {
        Some(time) => format!(
            "~{:04}-{:02}-{:02} {:02}:{:02} UTC",
            time.year(),
            u8::from(time.month()),
            time.day(),
            time.hour(),
            time.minute()
        ),
        None => format!("~{unix_secs} (invalid time)"),
    }
}

fn module_ref_json(module: &ModuleRef) -> Value {
    json!({
        "id": module.instance_id,
        "kind": module.kind.as_ref().map(ModuleKind::as_str),
    })
}

pub fn item_json(item: &ItemView) -> Value {
    let mut value = json!({
        "type": "item",
        "session": item.session_idx,
        "item": item.item_idx,
        "peer": item.peer,
        "signed": item.signed,
    });
    let details = match &item.details {
        ItemDetails::Transaction {
            txid,
            inputs,
            outputs,
        } => json!({
            "item_type": "transaction",
            "txid": txid.fmt_full().to_string(),
            "inputs": inputs.iter().map(module_ref_json).collect::<Vec<_>>(),
            "outputs": outputs.iter().map(module_ref_json).collect::<Vec<_>>(),
        }),
        ItemDetails::Module { module, content } => match content {
            ModuleItemContent::Decoded { variant, summary } => json!({
                "item_type": "module",
                "module": module_ref_json(module),
                "variant": variant,
                "summary": summary,
            }),
            ModuleItemContent::Undecodable { len } => json!({
                "item_type": "module",
                "module": module_ref_json(module),
                "variant": null,
                "len": len,
            }),
        },
        ItemDetails::Other { variant, len } => json!({
            "item_type": "other",
            "variant": variant,
            "len": len,
        }),
    };

    if let (Some(value), Value::Object(details)) = (value.as_object_mut(), details) {
        value.extend(details);
    }
    value
}

pub fn session_json(summary: &SessionSummary) -> Value {
    json!({
        "type": "session",
        "session": summary.session_idx,
        "items": summary.total(),
        "transactions": summary.transactions,
        "module_items": summary.module_items,
        "other_items": summary.other_items,
        "shown": summary.shown,
        "signed_at": summary.signed_at,
        "time_vote": summary.time_vote,
    })
}
