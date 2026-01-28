#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

// Backup and restore logic
pub mod backup;
/// Modularized Cli for sending and receiving out-of-band ecash
#[cfg(feature = "cli")]
mod cli;
/// Database keys used throughout the mint client module
pub mod client_db;
/// State machines for mint inputs
mod input;
/// State machines for out-of-band transmitted e-cash notes
mod oob;
/// State machines for mint outputs
pub mod output;

pub mod event;

/// API client impl for mint-specific requests
pub mod api;

pub mod repair_wallet;

use std::cmp::{Ordering, min};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail, ensure};
use api::MintFederationApi;
use async_stream::{stream, try_stream};
use backup::recovery::{MintRecovery, RecoveryStateV2};
use base64::Engine as _;
use bitcoin_hashes::{Hash, HashEngine as BitcoinHashEngine, sha256, sha256t};
use client_db::{
    DbKeyPrefix, NoteKeyPrefix, RecoveryFinalizedKey, RecoveryStateKey, RecoveryStateV2Key,
    ReusedNoteIndices, migrate_state_to_v2, migrate_to_v1,
};
use event::{NoteSpent, OOBNotesReissued, OOBNotesSpent, ReceivePaymentEvent, SendPaymentEvent};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::db::{ClientModuleMigrationFn, migrate_state};
use fedimint_client_module::module::init::{
    ClientModuleInit, ClientModuleInitArgs, ClientModuleRecoverArgs,
};
use fedimint_client_module::module::recovery::RecoveryProgress;
use fedimint_client_module::module::{
    ClientContext, ClientModule, IClientModule, OutPointRange, PrimaryModulePriority,
    PrimaryModuleSupport,
};
use fedimint_client_module::oplog::{OperationLogEntry, UpdateStreamOrOutcome};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::base32::{FEDIMINT_PREFIX, encode_prefixed};
use fedimint_core::config::{FederationId, FederationIdPrefix};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    AutocommitError, Database, DatabaseTransaction, DatabaseVersion,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::rand::prelude::IteratorRandom;
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::{All, Keypair, Secp256k1};
use fedimint_core::util::{BoxFuture, BoxStream, NextOrPending, SafeUrl};
use fedimint_core::{
    Amount, OutPoint, PeerId, Tiered, TieredCounts, TieredMulti, TransactionId, apply,
    async_trait_maybe_send, base32, push_db_pair_items,
};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_logging::LOG_CLIENT_MODULE_MINT;
pub use fedimint_mint_common as common;
use fedimint_mint_common::config::{FeeConsensus, MintClientConfig};
pub use fedimint_mint_common::*;
use futures::future::try_join_all;
use futures::{StreamExt, pin_mut};
use hex::ToHex;
use input::MintInputStateCreatedBundle;
use itertools::Itertools as _;
use oob::MintOOBStatesCreatedMulti;
use output::MintOutputStatesCreatedMulti;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tbs::AggregatePublicKey;
use thiserror::Error;
use tracing::{debug, warn};

use crate::backup::EcashBackup;
use crate::client_db::{
    CancelledOOBSpendKey, CancelledOOBSpendKeyPrefix, NextECashNoteIndexKey,
    NextECashNoteIndexKeyPrefix, NoteKey,
};
use crate::input::{MintInputCommon, MintInputStateMachine, MintInputStates};
use crate::oob::{MintOOBStateMachine, MintOOBStates};
use crate::output::{
    MintOutputCommon, MintOutputStateMachine, MintOutputStates, NoteIssuanceRequest,
};

const MINT_E_CASH_TYPE_CHILD_ID: ChildId = ChildId(0);

#[derive(Clone)]
struct PeerSelector {
    latency: Arc<RwLock<BTreeMap<PeerId, Duration>>>,
}

impl PeerSelector {
    fn new(peers: BTreeSet<PeerId>) -> Self {
        let latency = peers
            .into_iter()
            .map(|peer| (peer, Duration::ZERO))
            .collect();

        Self {
            latency: Arc::new(RwLock::new(latency)),
        }
    }

    fn choose_peer(&self) -> PeerId {
        let latency = self.latency.read().expect("poisoned");

        let peer_a = latency.iter().choose(&mut thread_rng()).expect("no peers");
        let peer_b = latency.iter().choose(&mut thread_rng()).expect("no peers");

        if peer_a.1 <= peer_b.1 {
            *peer_a.0
        } else {
            *peer_b.0
        }
    }

    fn report(&self, peer: PeerId, duration: Duration) {
        self.latency
            .write()
            .expect("poisoned")
            .entry(peer)
            .and_modify(|latency| *latency = *latency * 9 / 10 + duration / 10)
            .or_insert(duration);
    }

    fn remove(&self, peer: PeerId) {
        self.latency.write().expect("poisoned").remove(&peer);
    }
}

/// Downloads a slice with a pre-fetched hash for verification
async fn download_slice_with_hash(
    module_api: DynModuleApi,
    peer_selector: PeerSelector,
    start: u64,
    end: u64,
    expected_hash: sha256::Hash,
) -> Vec<RecoveryItem> {
    const TIMEOUT: Duration = Duration::from_secs(30);

    loop {
        let peer = peer_selector.choose_peer();
        let start_time = fedimint_core::time::now();

        match tokio::time::timeout(TIMEOUT, module_api.fetch_recovery_slice(peer, start, end))
            .await
            .map_err(Into::into)
            .and_then(|r| r)
        {
            Ok(data) => {
                let elapsed = fedimint_core::time::now()
                    .duration_since(start_time)
                    .unwrap_or(Duration::ZERO);

                peer_selector.report(peer, elapsed);

                if data.consensus_hash::<sha256::Hash>() == expected_hash {
                    return data;
                }

                peer_selector.remove(peer);
            }
            Err(..) => {
                peer_selector.report(peer, TIMEOUT);
            }
        }
    }
}

/// An encapsulation of [`FederationId`] and e-cash notes in the form of
/// [`TieredMulti<SpendableNote>`] for the purpose of spending e-cash
/// out-of-band. Also used for validating and reissuing such out-of-band notes.
///
/// ## Invariants
/// * Has to contain at least one `Notes` item
/// * Has to contain at least one `FederationIdPrefix` item
#[derive(Clone, Debug, Encodable, PartialEq, Eq)]
pub struct OOBNotes(Vec<OOBNotesPart>);

/// For extendability [`OOBNotes`] consists of parts, where client can ignore
/// ones they don't understand.
#[derive(Clone, Debug, Decodable, Encodable, PartialEq, Eq)]
enum OOBNotesPart {
    Notes(TieredMulti<SpendableNote>),
    FederationIdPrefix(FederationIdPrefix),
    /// Invite code to join the federation by which the e-cash was issued
    ///
    /// Introduced in 0.3.0
    Invite {
        // This is a vec for future-proofness, in case we want to include multiple guardian APIs
        peer_apis: Vec<(PeerId, SafeUrl)>,
        federation_id: FederationId,
    },
    ApiSecret(String),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl OOBNotes {
    pub fn new(
        federation_id_prefix: FederationIdPrefix,
        notes: TieredMulti<SpendableNote>,
    ) -> Self {
        Self(vec![
            OOBNotesPart::FederationIdPrefix(federation_id_prefix),
            OOBNotesPart::Notes(notes),
        ])
    }

    pub fn new_with_invite(notes: TieredMulti<SpendableNote>, invite: &InviteCode) -> Self {
        let mut data = vec![
            // FIXME: once we can break compatibility with 0.2 we can remove the prefix in case an
            // invite is present
            OOBNotesPart::FederationIdPrefix(invite.federation_id().to_prefix()),
            OOBNotesPart::Notes(notes),
            OOBNotesPart::Invite {
                peer_apis: vec![(invite.peer(), invite.url())],
                federation_id: invite.federation_id(),
            },
        ];
        if let Some(api_secret) = invite.api_secret() {
            data.push(OOBNotesPart::ApiSecret(api_secret));
        }
        Self(data)
    }

    pub fn federation_id_prefix(&self) -> FederationIdPrefix {
        self.0
            .iter()
            .find_map(|data| match data {
                OOBNotesPart::FederationIdPrefix(prefix) => Some(*prefix),
                OOBNotesPart::Invite { federation_id, .. } => Some(federation_id.to_prefix()),
                _ => None,
            })
            .expect("Invariant violated: OOBNotes does not contain a FederationIdPrefix")
    }

    pub fn notes(&self) -> &TieredMulti<SpendableNote> {
        self.0
            .iter()
            .find_map(|data| match data {
                OOBNotesPart::Notes(notes) => Some(notes),
                _ => None,
            })
            .expect("Invariant violated: OOBNotes does not contain any notes")
    }

    pub fn notes_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut notes_map = serde_json::Map::new();
        for notes in &self.0 {
            match notes {
                OOBNotesPart::Notes(notes) => {
                    let notes_json = serde_json::to_value(notes)?;
                    notes_map.insert("notes".to_string(), notes_json);
                }
                OOBNotesPart::FederationIdPrefix(prefix) => {
                    notes_map.insert(
                        "federation_id_prefix".to_string(),
                        serde_json::to_value(prefix.to_string())?,
                    );
                }
                OOBNotesPart::Invite {
                    peer_apis,
                    federation_id,
                } => {
                    let (peer_id, api) = peer_apis
                        .first()
                        .cloned()
                        .expect("Decoding makes sure peer_apis isn't empty");
                    notes_map.insert(
                        "invite".to_string(),
                        serde_json::to_value(InviteCode::new(
                            api,
                            peer_id,
                            *federation_id,
                            self.api_secret(),
                        ))?,
                    );
                }
                OOBNotesPart::ApiSecret(_) => { /* already covered inside `Invite` */ }
                OOBNotesPart::Default { variant, bytes } => {
                    notes_map.insert(
                        format!("default_{variant}"),
                        serde_json::to_value(bytes.encode_hex::<String>())?,
                    );
                }
            }
        }
        Ok(serde_json::Value::Object(notes_map))
    }

    pub fn federation_invite(&self) -> Option<InviteCode> {
        self.0.iter().find_map(|data| {
            let OOBNotesPart::Invite {
                peer_apis,
                federation_id,
            } = data
            else {
                return None;
            };
            let (peer_id, api) = peer_apis
                .first()
                .cloned()
                .expect("Decoding makes sure peer_apis isn't empty");
            Some(InviteCode::new(
                api,
                peer_id,
                *federation_id,
                self.api_secret(),
            ))
        })
    }

    fn api_secret(&self) -> Option<String> {
        self.0.iter().find_map(|data| {
            let OOBNotesPart::ApiSecret(api_secret) = data else {
                return None;
            };
            Some(api_secret.clone())
        })
    }
}

impl Decodable for OOBNotes {
    fn consensus_decode_partial<R: Read>(
        r: &mut R,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let inner =
            Vec::<OOBNotesPart>::consensus_decode_partial(r, &ModuleDecoderRegistry::default())?;

        // TODO: maybe write some macros for defining TLV structs?
        if !inner
            .iter()
            .any(|data| matches!(data, OOBNotesPart::Notes(_)))
        {
            return Err(DecodeError::from_str(
                "No e-cash notes were found in OOBNotes data",
            ));
        }

        let maybe_federation_id_prefix = inner.iter().find_map(|data| match data {
            OOBNotesPart::FederationIdPrefix(prefix) => Some(*prefix),
            _ => None,
        });

        let maybe_invite = inner.iter().find_map(|data| match data {
            OOBNotesPart::Invite {
                federation_id,
                peer_apis,
            } => Some((federation_id, peer_apis)),
            _ => None,
        });

        match (maybe_federation_id_prefix, maybe_invite) {
            (Some(p), Some((ip, _))) => {
                if p != ip.to_prefix() {
                    return Err(DecodeError::from_str(
                        "Inconsistent Federation ID provided in OOBNotes data",
                    ));
                }
            }
            (None, None) => {
                return Err(DecodeError::from_str(
                    "No Federation ID provided in OOBNotes data",
                ));
            }
            _ => {}
        }

        if let Some((_, invite)) = maybe_invite
            && invite.is_empty()
        {
            return Err(DecodeError::from_str("Invite didn't contain API endpoints"));
        }

        Ok(OOBNotes(inner))
    }
}

const BASE64_URL_SAFE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::general_purpose::PAD,
);

impl FromStr for OOBNotes {
    type Err = anyhow::Error;

    /// Decode a set of out-of-band e-cash notes from a base64 or base32 string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s: String = s.chars().filter(|&c| !c.is_whitespace()).collect();

        let oob_notes_bytes = if let Ok(oob_notes_bytes) =
            base32::decode_prefixed_bytes(FEDIMINT_PREFIX, &s)
        {
            oob_notes_bytes
        } else if let Ok(oob_notes_bytes) = BASE64_URL_SAFE.decode(&s) {
            oob_notes_bytes
        } else if let Ok(oob_notes_bytes) = base64::engine::general_purpose::STANDARD.decode(&s) {
            oob_notes_bytes
        } else {
            bail!("OOBNotes were not a well-formed base64(URL-safe) or base32 string");
        };

        let oob_notes =
            OOBNotes::consensus_decode_whole(&oob_notes_bytes, &ModuleDecoderRegistry::default())?;

        ensure!(!oob_notes.notes().is_empty(), "OOBNotes cannot be empty");

        Ok(oob_notes)
    }
}

impl Display for OOBNotes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let bytes = Encodable::consensus_encode_to_vec(self);

        f.write_str(&BASE64_URL_SAFE.encode(&bytes))
    }
}

impl Serialize for OOBNotes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OOBNotes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl OOBNotes {
    /// Returns the total value of all notes in msat as `Amount`
    pub fn total_amount(&self) -> Amount {
        self.notes().total_amount()
    }
}

/// The high-level state of a reissue operation started with
/// [`MintClientModule::reissue_external_notes`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReissueExternalNotesState {
    /// The operation has been created and is waiting to be accepted by the
    /// federation.
    Created,
    /// We are waiting for blind signatures to arrive but can already assume the
    /// transaction to be successful.
    Issuing,
    /// The operation has been completed successfully.
    Done,
    /// Some error happened and the operation failed.
    Failed(String),
}

/// The high-level state of a raw e-cash spend operation started with
/// [`MintClientModule::spend_notes_with_selector`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SpendOOBState {
    /// The e-cash has been selected and given to the caller
    Created,
    /// The user requested a cancellation of the operation, we are waiting for
    /// the outcome of the cancel transaction.
    UserCanceledProcessing,
    /// The user-requested cancellation was successful, we got all our money
    /// back.
    UserCanceledSuccess,
    /// The user-requested cancellation failed, the e-cash notes have been spent
    /// by someone else already.
    UserCanceledFailure,
    /// We tried to cancel the operation automatically after the timeout but
    /// failed, indicating the recipient reissued the e-cash to themselves,
    /// making the out-of-band spend **successful**.
    Success,
    /// We tried to cancel the operation automatically after the timeout and
    /// succeeded, indicating the recipient did not reissue the e-cash to
    /// themselves, meaning the out-of-band spend **failed**.
    Refunded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintOperationMeta {
    pub variant: MintOperationMetaVariant,
    pub amount: Amount,
    pub extra_meta: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MintOperationMetaVariant {
    // TODO: add migrations for operation log and clean up schema
    /// Either `legacy_out_point` or both `txid` and `out_point_indices` will be
    /// present.
    Reissuance {
        // Removed in 0.3.0:
        #[serde(skip_serializing, default, rename = "out_point")]
        legacy_out_point: Option<OutPoint>,
        // Introduced in 0.3.0:
        #[serde(default)]
        txid: Option<TransactionId>,
        // Introduced in 0.3.0:
        #[serde(default)]
        out_point_indices: Vec<u64>,
    },
    SpendOOB {
        requested_amount: Amount,
        oob_notes: OOBNotes,
    },
}

#[derive(Debug, Clone)]
pub struct MintClientInit;

const SLICE_SIZE: u64 = 10000;
const PARALLEL_HASH_REQUESTS: usize = 10;
const PARALLEL_SLICE_REQUESTS: usize = 10;

impl MintClientInit {
    #[allow(clippy::too_many_lines)]
    async fn recover_from_slices(
        &self,
        args: &ClientModuleRecoverArgs<Self>,
    ) -> anyhow::Result<()> {
        // Try to load existing state or create new one if we can fetch recovery count
        let mut state = if let Some(state) = args
            .db()
            .begin_transaction_nc()
            .await
            .get_value(&RecoveryStateV2Key)
            .await
        {
            state
        } else {
            // Try to fetch recovery count - if this fails, the endpoint doesn't exist
            let total_items = args.module_api().fetch_recovery_count().await?;

            RecoveryStateV2::new(
                total_items,
                args.cfg().tbs_pks.tiers().copied().collect(),
                args.module_root_secret(),
            )
        };

        if state.next_index == state.total_items {
            return Ok(());
        }

        let peer_selector = PeerSelector::new(args.api().all_peers().clone());

        let mut recovery_stream = futures::stream::iter(
            (state.next_index..state.total_items).step_by(SLICE_SIZE as usize),
        )
        .map(move |start| {
            let api = args.module_api().clone();
            let end = std::cmp::min(start + SLICE_SIZE, state.total_items);

            async move { (start, end, api.fetch_recovery_slice_hash(start, end).await) }
        })
        .buffered(PARALLEL_HASH_REQUESTS)
        .map(move |(start, end, hash)| {
            download_slice_with_hash(
                args.module_api().clone(),
                peer_selector.clone(),
                start,
                end,
                hash,
            )
        })
        .buffered(PARALLEL_SLICE_REQUESTS);

        let secret = args.module_root_secret().clone();

        loop {
            let items = recovery_stream
                .next()
                .await
                .expect("mint recovery stream finished before recovery is complete");

            for item in &items {
                match item {
                    RecoveryItem::Output { amount, nonce } => {
                        state.handle_output(*amount, *nonce, &secret);
                    }
                    RecoveryItem::Input { nonce } => {
                        state.handle_input(*nonce);
                    }
                }
            }

            state.next_index += items.len() as u64;

            let mut dbtx = args.db().begin_transaction().await;

            dbtx.insert_entry(&RecoveryStateV2Key, &state).await;

            if state.next_index == state.total_items {
                // Finalize recovery - create state machines for pending outputs
                let finalized = state.finalize();

                // Collect blind nonces to fetch outpoints from server
                let blind_nonces: Vec<BlindNonce> = finalized
                    .pending_notes
                    .iter()
                    .map(|(_, req)| BlindNonce(req.blinded_message()))
                    .collect();

                // Fetch outpoints for all blind nonces
                let outpoints = if blind_nonces.is_empty() {
                    vec![]
                } else {
                    args.module_api()
                        .fetch_blind_nonce_outpoints(blind_nonces)
                        .await
                        .context("Failed to fetch blind nonce outpoints")?
                };

                // Create state machines for pending notes
                let state_machines: Vec<MintClientStateMachines> = finalized
                    .pending_notes
                    .into_iter()
                    .zip(outpoints)
                    .map(|((amount, issuance_request), out_point)| {
                        MintClientStateMachines::Output(MintOutputStateMachine {
                            common: MintOutputCommon {
                                operation_id: OperationId::new_random(),
                                out_point_range: OutPointRange::new_single(
                                    out_point.txid,
                                    out_point.out_idx,
                                )
                                .expect("Can't overflow"),
                            },
                            state: MintOutputStates::Created(output::MintOutputStatesCreated {
                                amount,
                                issuance_request,
                            }),
                        })
                    })
                    .collect();

                let state_machines = args.context().map_dyn(state_machines).collect();

                args.context()
                    .add_state_machines_dbtx(&mut dbtx.to_ref_nc(), state_machines)
                    .await?;

                // Restore NextECashNoteIndexKey
                for (amount, note_idx) in finalized.next_note_idx {
                    dbtx.insert_entry(&NextECashNoteIndexKey(amount), &note_idx.as_u64())
                        .await;
                }

                dbtx.commit_tx().await;

                return Ok(());
            }

            dbtx.commit_tx().await;

            args.update_recovery_progress(RecoveryProgress {
                complete: state.next_index.try_into().unwrap_or(u32::MAX),
                total: state.total_items.try_into().unwrap_or(u32::MAX),
            });
        }
    }
}

impl ModuleInit for MintClientInit {
    type Common = MintCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut mint_client_items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Note => {
                    push_db_pair_items!(
                        dbtx,
                        NoteKeyPrefix,
                        NoteKey,
                        SpendableNoteUndecoded,
                        mint_client_items,
                        "Notes"
                    );
                }
                DbKeyPrefix::NextECashNoteIndex => {
                    push_db_pair_items!(
                        dbtx,
                        NextECashNoteIndexKeyPrefix,
                        NextECashNoteIndexKey,
                        u64,
                        mint_client_items,
                        "NextECashNoteIndex"
                    );
                }
                DbKeyPrefix::CancelledOOBSpend => {
                    push_db_pair_items!(
                        dbtx,
                        CancelledOOBSpendKeyPrefix,
                        CancelledOOBSpendKey,
                        (),
                        mint_client_items,
                        "CancelledOOBSpendKey"
                    );
                }
                DbKeyPrefix::RecoveryFinalized => {
                    if let Some(val) = dbtx.get_value(&RecoveryFinalizedKey).await {
                        mint_client_items.insert("RecoveryFinalized".to_string(), Box::new(val));
                    }
                }
                DbKeyPrefix::RecoveryState
                | DbKeyPrefix::ReusedNoteIndices
                | DbKeyPrefix::RecoveryStateV2
                | DbKeyPrefix::ExternalReservedStart
                | DbKeyPrefix::CoreInternalReservedStart
                | DbKeyPrefix::CoreInternalReservedEnd => {}
            }
        }

        Box::new(mint_client_items.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for MintClientInit {
    type Module = MintClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(MintClientModule {
            federation_id: *args.federation_id(),
            cfg: args.cfg().clone(),
            secret: args.module_root_secret().clone(),
            secp: Secp256k1::new(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            balance_update_sender: tokio::sync::watch::channel(()).0,
        })
    }

    async fn recover(
        &self,
        args: &ClientModuleRecoverArgs<Self>,
        snapshot: Option<&<Self::Module as ClientModule>::Backup>,
    ) -> anyhow::Result<()> {
        let mut dbtx = args.db().begin_transaction_nc().await;

        // Check if V2 (slice-based) recovery state exists
        if dbtx.get_value(&RecoveryStateV2Key).await.is_some() {
            return self.recover_from_slices(args).await;
        }

        // Check if V1 (session-based) recovery state exists
        if dbtx.get_value(&RecoveryStateKey).await.is_some() {
            return args
                .recover_from_history::<MintRecovery>(self, snapshot)
                .await;
        }

        // No existing recovery state - determine which to use based on endpoint
        // availability
        if args.module_api().fetch_recovery_count().await.is_ok() {
            // New endpoint available - use V2 slice-based recovery
            self.recover_from_slices(args).await
        } else {
            // Old federation - use V1 session-based recovery
            args.recover_from_history::<MintRecovery>(self, snapshot)
                .await
        }
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        let mut migrations: BTreeMap<DatabaseVersion, ClientModuleMigrationFn> = BTreeMap::new();
        migrations.insert(DatabaseVersion(0), |dbtx, _, _| {
            Box::pin(migrate_to_v1(dbtx))
        });
        migrations.insert(DatabaseVersion(1), |_, active_states, inactive_states| {
            Box::pin(async { migrate_state(active_states, inactive_states, migrate_state_to_v2) })
        });

        migrations
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(
            DbKeyPrefix::iter()
                .map(|p| p as u8)
                .chain(
                    DbKeyPrefix::ExternalReservedStart as u8
                        ..=DbKeyPrefix::CoreInternalReservedEnd as u8,
                )
                .collect(),
        )
    }
}

/// The `MintClientModule` is responsible for handling e-cash minting
/// operations. It interacts with the mint server to issue, reissue, and
/// validate e-cash notes.
///
/// # Derivable Secret
///
/// The `DerivableSecret` is a cryptographic secret that can be used to derive
/// other secrets. In the context of the `MintClientModule`, it is used to
/// derive the blinding and spend keys for e-cash notes. The `DerivableSecret`
/// is initialized when the `MintClientModule` is created and is kept private
/// within the module.
///
/// # Blinding Key
///
/// The blinding key is derived from the `DerivableSecret` and is used to blind
/// the e-cash note during the issuance process. This ensures that the mint
/// server cannot link the e-cash note to the client that requested it,
/// providing privacy for the client.
///
/// # Spend Key
///
/// The spend key is also derived from the `DerivableSecret` and is used to
/// spend the e-cash note. Only the client that possesses the `DerivableSecret`
/// can derive the correct spend key to spend the e-cash note. This ensures that
/// only the owner of the e-cash note can spend it.
pub struct MintClientModule {
    federation_id: FederationId,
    cfg: MintClientConfig,
    secret: DerivableSecret,
    secp: Secp256k1<All>,
    notifier: ModuleNotifier<MintClientStateMachines>,
    pub client_ctx: ClientContext<Self>,
    balance_update_sender: tokio::sync::watch::Sender<()>,
}

impl fmt::Debug for MintClientModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintClientModule")
            .field("federation_id", &self.federation_id)
            .field("cfg", &self.cfg)
            .field("notifier", &self.notifier)
            .field("client_ctx", &self.client_ctx)
            .finish_non_exhaustive()
    }
}

// TODO: wrap in Arc
#[derive(Clone)]
pub struct MintClientContext {
    pub federation_id: FederationId,
    pub client_ctx: ClientContext<MintClientModule>,
    pub mint_decoder: Decoder,
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub secret: DerivableSecret,
    // FIXME: putting a DB ref here is an antipattern, global context should become more powerful
    // but we need to consider it more carefully as its APIs will be harder to change.
    pub module_db: Database,
    /// Notifies subscribers when the balance changes
    pub balance_update_sender: tokio::sync::watch::Sender<()>,
}

impl fmt::Debug for MintClientContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintClientContext")
            .field("federation_id", &self.federation_id)
            .finish_non_exhaustive()
    }
}

impl MintClientContext {
    fn await_cancel_oob_payment(&self, operation_id: OperationId) -> BoxFuture<'static, ()> {
        let db = self.module_db.clone();
        Box::pin(async move {
            db.wait_key_exists(&CancelledOOBSpendKey(operation_id))
                .await;
        })
    }
}

impl Context for MintClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for MintClientModule {
    type Init = MintClientInit;
    type Common = MintModuleTypes;
    type Backup = EcashBackup;
    type ModuleStateMachineContext = MintClientContext;
    type States = MintClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        MintClientContext {
            federation_id: self.federation_id,
            client_ctx: self.client_ctx.clone(),
            mint_decoder: self.decoder(),
            tbs_pks: self.cfg.tbs_pks.clone(),
            peer_tbs_pks: self.cfg.peer_tbs_pks.clone(),
            secret: self.secret.clone(),
            module_db: self.client_ctx.module_db().clone(),
            balance_update_sender: self.balance_update_sender.clone(),
        }
    }

    fn input_fee(
        &self,
        amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(
            self.cfg.fee_consensus.fee(amount.get_bitcoin()),
        ))
    }

    async fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(input.maybe_v0_ref()?.amount))
    }

    fn output_fee(
        &self,
        amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(
            self.cfg.fee_consensus.fee(amount.get_bitcoin()),
        ))
    }

    async fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(output.maybe_v0_ref()?.amount))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }

    fn supports_backup(&self) -> bool {
        true
    }

    async fn backup(&self) -> anyhow::Result<EcashBackup> {
        self.client_ctx
            .module_db()
            .autocommit(
                |dbtx_ctx, _| {
                    Box::pin(async { self.prepare_plaintext_ecash_backup(dbtx_ctx).await })
                },
                None,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { last_error, .. } => {
                    anyhow!("Commit to DB failed: {last_error}")
                }
            })
    }

    fn supports_being_primary(&self) -> PrimaryModuleSupport {
        PrimaryModuleSupport::selected(PrimaryModulePriority::HIGH, [AmountUnit::BITCOIN])
    }

    async fn create_final_inputs_and_outputs(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        unit: AmountUnit,
        mut input_amount: Amount,
        mut output_amount: Amount,
    ) -> anyhow::Result<(
        ClientInputBundle<MintInput, MintClientStateMachines>,
        ClientOutputBundle<MintOutput, MintClientStateMachines>,
    )> {
        let consolidation_inputs = self.consolidate_notes(dbtx).await?;

        if unit != AmountUnit::BITCOIN {
            bail!("Module can only handle Bitcoin");
        }

        input_amount += consolidation_inputs
            .iter()
            .map(|input| input.0.amounts.get_bitcoin())
            .sum();

        output_amount += consolidation_inputs
            .iter()
            .map(|input| self.cfg.fee_consensus.fee(input.0.amounts.get_bitcoin()))
            .sum();

        let additional_inputs = self
            .create_sufficient_input(dbtx, output_amount.saturating_sub(input_amount))
            .await?;

        input_amount += additional_inputs
            .iter()
            .map(|input| input.0.amounts.get_bitcoin())
            .sum();

        output_amount += additional_inputs
            .iter()
            .map(|input| self.cfg.fee_consensus.fee(input.0.amounts.get_bitcoin()))
            .sum();

        let outputs = self
            .create_output(
                dbtx,
                operation_id,
                2,
                input_amount.saturating_sub(output_amount),
            )
            .await;

        Ok((
            create_bundle_for_inputs(
                [consolidation_inputs, additional_inputs].concat(),
                operation_id,
            ),
            outputs,
        ))
    }

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<()> {
        self.await_output_finalized(operation_id, out_point).await
    }

    async fn get_balance(&self, dbtx: &mut DatabaseTransaction<'_>, unit: AmountUnit) -> Amount {
        if unit != AmountUnit::BITCOIN {
            return Amount::ZERO;
        }
        self.get_note_counts_by_denomination(dbtx)
            .await
            .total_amount()
    }

    async fn get_balances(&self, dbtx: &mut DatabaseTransaction<'_>) -> Amounts {
        Amounts::new_bitcoin(
            <Self as ClientModule>::get_balance(self, dbtx, AmountUnit::BITCOIN).await,
        )
    }

    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()> {
        Box::pin(tokio_stream::wrappers::WatchStream::new(
            self.balance_update_sender.subscribe(),
        ))
    }

    async fn leave(&self, dbtx: &mut DatabaseTransaction<'_>) -> anyhow::Result<()> {
        let balance = ClientModule::get_balances(self, dbtx).await;

        for (unit, amount) in balance {
            if Amount::from_units(0) < amount {
                bail!("Outstanding balance: {amount}, unit: {unit:?}");
            }
        }

        if !self.client_ctx.get_own_active_states().await.is_empty() {
            bail!("Pending operations")
        }
        Ok(())
    }

    async fn handle_rpc(
        &self,
        method: String,
        request: serde_json::Value,
    ) -> BoxStream<'_, anyhow::Result<serde_json::Value>> {
        Box::pin(try_stream! {
            match method.as_str() {
                "reissue_external_notes" => {
                    let req: ReissueExternalNotesRequest = serde_json::from_value(request)?;
                    let result = self.reissue_external_notes(req.oob_notes, req.extra_meta).await?;
                    yield serde_json::to_value(result)?;
                }
                "subscribe_reissue_external_notes" => {
                    let req: SubscribeReissueExternalNotesRequest = serde_json::from_value(request)?;
                    let stream = self.subscribe_reissue_external_notes(req.operation_id).await?;
                    for await state in stream.into_stream() {
                        yield serde_json::to_value(state)?;
                    }
                }
                "spend_notes" => {
                    let req: SpendNotesRequest = serde_json::from_value(request)?;
                    let result = self.spend_notes_with_selector(
                        &SelectNotesWithExactAmount,
                        req.amount,
                        req.try_cancel_after,
                        req.include_invite,
                        req.extra_meta
                    ).await?;
                    yield serde_json::to_value(result)?;
                }
                "spend_notes_expert" => {
                    let req: SpendNotesExpertRequest = serde_json::from_value(request)?;
                    let result = self.spend_notes_with_selector(
                        &SelectNotesWithAtleastAmount,
                        req.min_amount,
                        req.try_cancel_after,
                        req.include_invite,
                        req.extra_meta
                    ).await?;
                    yield serde_json::to_value(result)?;
                }
                "validate_notes" => {
                    let req: ValidateNotesRequest = serde_json::from_value(request)?;
                    let result = self.validate_notes(&req.oob_notes)?;
                    yield serde_json::to_value(result)?;
                }
                "try_cancel_spend_notes" => {
                    let req: TryCancelSpendNotesRequest = serde_json::from_value(request)?;
                    let result = self.try_cancel_spend_notes(req.operation_id).await;
                    yield serde_json::to_value(result)?;
                }
                "subscribe_spend_notes" => {
                    let req: SubscribeSpendNotesRequest = serde_json::from_value(request)?;
                    let stream = self.subscribe_spend_notes(req.operation_id).await?;
                    for await state in stream.into_stream() {
                        yield serde_json::to_value(state)?;
                    }
                }
                "await_spend_oob_refund" => {
                    let req: AwaitSpendOobRefundRequest = serde_json::from_value(request)?;
                    let value = self.await_spend_oob_refund(req.operation_id).await;
                    yield serde_json::to_value(value)?;
                }
                "note_counts_by_denomination" => {
                    let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;
                    let note_counts = self.get_note_counts_by_denomination(&mut dbtx).await;
                    yield serde_json::to_value(note_counts)?;
                }
                _ => {
                    Err(anyhow::format_err!("Unknown method: {}", method))?;
                    unreachable!()
                },
            }
        })
    }
}

#[derive(Deserialize)]
struct ReissueExternalNotesRequest {
    oob_notes: OOBNotes,
    extra_meta: serde_json::Value,
}

#[derive(Deserialize)]
struct SubscribeReissueExternalNotesRequest {
    operation_id: OperationId,
}

/// Caution: if no notes of the correct denomination are available the next
/// bigger note will be selected. You might want to use `spend_notes` instead.
#[derive(Deserialize)]
struct SpendNotesExpertRequest {
    min_amount: Amount,
    try_cancel_after: Duration,
    include_invite: bool,
    extra_meta: serde_json::Value,
}

#[derive(Deserialize)]
struct SpendNotesRequest {
    amount: Amount,
    try_cancel_after: Duration,
    include_invite: bool,
    extra_meta: serde_json::Value,
}

#[derive(Deserialize)]
struct ValidateNotesRequest {
    oob_notes: OOBNotes,
}

#[derive(Deserialize)]
struct TryCancelSpendNotesRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct SubscribeSpendNotesRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct AwaitSpendOobRefundRequest {
    operation_id: OperationId,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum ReissueExternalNotesError {
    #[error("Federation ID does not match")]
    WrongFederationId,
    #[error("We already reissued these notes")]
    AlreadyReissued,
}

impl MintClientModule {
    async fn create_sufficient_input(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        min_amount: Amount,
    ) -> anyhow::Result<Vec<(ClientInput<MintInput>, SpendableNote)>> {
        if min_amount == Amount::ZERO {
            return Ok(vec![]);
        }

        let selected_notes = Self::select_notes(
            dbtx,
            &SelectNotesWithAtleastAmount,
            min_amount,
            self.cfg.fee_consensus.clone(),
        )
        .await?;

        for (amount, note) in selected_notes.iter_items() {
            debug!(target: LOG_CLIENT_MODULE_MINT, %amount, %note, "Spending note as sufficient input to fund a tx");
            MintClientModule::delete_spendable_note(&self.client_ctx, dbtx, amount, note).await;
        }

        let sender = self.balance_update_sender.clone();
        dbtx.on_commit(move || sender.send_replace(()));

        let inputs = self.create_input_from_notes(selected_notes)?;

        assert!(!inputs.is_empty());

        Ok(inputs)
    }

    /// Returns the number of held e-cash notes per denomination
    #[deprecated(
        since = "0.5.0",
        note = "Use `get_note_counts_by_denomination` instead"
    )]
    pub async fn get_notes_tier_counts(&self, dbtx: &mut DatabaseTransaction<'_>) -> TieredCounts {
        self.get_note_counts_by_denomination(dbtx).await
    }

    /// Pick [`SpendableNote`]s by given counts, when available
    ///
    /// Return the notes picked, and counts of notes that were not available.
    pub async fn get_available_notes_by_tier_counts(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        counts: TieredCounts,
    ) -> (TieredMulti<SpendableNoteUndecoded>, TieredCounts) {
        dbtx.find_by_prefix(&NoteKeyPrefix)
            .await
            .fold(
                (TieredMulti::<SpendableNoteUndecoded>::default(), counts),
                |(mut notes, mut counts), (key, note)| async move {
                    let amount = key.amount;
                    if 0 < counts.get(amount) {
                        counts.dec(amount);
                        notes.push(amount, note);
                    }

                    (notes, counts)
                },
            )
            .await
    }

    // TODO: put "notes per denomination" default into cfg
    /// Creates a mint output close to the given `amount`, issuing e-cash
    /// notes such that the client holds `notes_per_denomination` notes of each
    /// e-cash note denomination held.
    pub async fn create_output(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        notes_per_denomination: u16,
        exact_amount: Amount,
    ) -> ClientOutputBundle<MintOutput, MintClientStateMachines> {
        if exact_amount == Amount::ZERO {
            return ClientOutputBundle::new(vec![], vec![]);
        }

        let denominations = represent_amount(
            exact_amount,
            &self.get_note_counts_by_denomination(dbtx).await,
            &self.cfg.tbs_pks,
            notes_per_denomination,
            &self.cfg.fee_consensus,
        );

        let mut outputs = Vec::new();
        let mut issuance_requests = Vec::new();

        for (amount, num) in denominations.iter() {
            for _ in 0..num {
                let (issuance_request, blind_nonce) = self.new_ecash_note(amount, dbtx).await;

                debug!(
                    %amount,
                    "Generated issuance request"
                );

                outputs.push(ClientOutput {
                    output: MintOutput::new_v0(amount, blind_nonce),
                    amounts: Amounts::new_bitcoin(amount),
                });

                issuance_requests.push((amount, issuance_request));
            }
        }

        let state_generator = Arc::new(move |out_point_range: OutPointRange| {
            assert_eq!(out_point_range.count(), issuance_requests.len());
            vec![MintClientStateMachines::Output(MintOutputStateMachine {
                common: MintOutputCommon {
                    operation_id,
                    out_point_range,
                },
                state: MintOutputStates::CreatedMulti(MintOutputStatesCreatedMulti {
                    issuance_requests: out_point_range
                        .into_iter()
                        .map(|out_point| out_point.out_idx)
                        .zip(issuance_requests.clone())
                        .collect(),
                }),
            })]
        });

        ClientOutputBundle::new(
            outputs,
            vec![ClientOutputSM {
                state_machines: state_generator,
            }],
        )
    }

    /// Returns the number of held e-cash notes per denomination
    pub async fn get_note_counts_by_denomination(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> TieredCounts {
        dbtx.find_by_prefix(&NoteKeyPrefix)
            .await
            .fold(
                TieredCounts::default(),
                |mut acc, (key, _note)| async move {
                    acc.inc(key.amount, 1);
                    acc
                },
            )
            .await
    }

    /// Returns the number of held e-cash notes per denomination
    #[deprecated(
        since = "0.5.0",
        note = "Use `get_note_counts_by_denomination` instead"
    )]
    pub async fn get_wallet_summary(&self, dbtx: &mut DatabaseTransaction<'_>) -> TieredCounts {
        self.get_note_counts_by_denomination(dbtx).await
    }

    /// Estimates the total fees to spend all currently held notes.
    ///
    /// This is useful for calculating max withdrawable amounts, where all
    /// notes will be spent. Notes that are uneconomical to spend (fee >= value)
    /// are excluded from the calculation since the wallet won't spend them.
    pub async fn estimate_spend_all_fees(&self) -> Amount {
        let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;
        let note_counts = self.get_note_counts_by_denomination(&mut dbtx).await;

        note_counts
            .iter()
            .filter_map(|(amount, count)| {
                let note_fee = self.cfg.fee_consensus.fee(amount);
                if note_fee < amount {
                    note_fee.checked_mul(count as u64)
                } else {
                    None
                }
            })
            .fold(Amount::ZERO, |acc, fee| {
                acc.checked_add(fee).expect("fee sum overflow")
            })
    }

    /// Wait for the e-cash notes to be retrieved. If this is not possible
    /// because another terminal state was reached an error describing the
    /// failure is returned.
    pub async fn await_output_finalized(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<()> {
        let stream = self
            .notifier
            .subscribe(operation_id)
            .await
            .filter_map(|state| async {
                let MintClientStateMachines::Output(state) = state else {
                    return None;
                };

                if state.common.txid() != out_point.txid
                    || !state
                        .common
                        .out_point_range
                        .out_idx_iter()
                        .contains(&out_point.out_idx)
                {
                    return None;
                }

                match state.state {
                    MintOutputStates::Succeeded(_) => Some(Ok(())),
                    MintOutputStates::Aborted(_) => Some(Err(anyhow!("Transaction was rejected"))),
                    MintOutputStates::Failed(failed) => Some(Err(anyhow!(
                        "Failed to finalize transaction: {}",
                        failed.error
                    ))),
                    MintOutputStates::Created(_) | MintOutputStates::CreatedMulti(_) => None,
                }
            });
        pin_mut!(stream);

        stream.next_or_pending().await
    }

    /// Provisional implementation of note consolidation
    ///
    /// When a certain denomination crosses the threshold of notes allowed,
    /// spend some chunk of them as inputs.
    ///
    /// Return notes and the sume of their amount.
    pub async fn consolidate_notes(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> anyhow::Result<Vec<(ClientInput<MintInput>, SpendableNote)>> {
        /// At how many notes of the same denomination should we try to
        /// consolidate
        const MAX_NOTES_PER_TIER_TRIGGER: usize = 8;
        /// Number of notes per tier to leave after threshold was crossed
        const MIN_NOTES_PER_TIER: usize = 4;
        /// Maximum number of notes to consolidate per one tx,
        /// to limit the size of a transaction produced.
        const MAX_NOTES_TO_CONSOLIDATE_IN_TX: usize = 20;
        // it's fine, it's just documentation
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MIN_NOTES_PER_TIER <= MAX_NOTES_PER_TIER_TRIGGER);
        }

        let counts = self.get_note_counts_by_denomination(dbtx).await;

        let should_consolidate = counts
            .iter()
            .any(|(_, count)| MAX_NOTES_PER_TIER_TRIGGER < count);

        if !should_consolidate {
            return Ok(vec![]);
        }

        let mut max_count = MAX_NOTES_TO_CONSOLIDATE_IN_TX;

        let excessive_counts: TieredCounts = counts
            .iter()
            .map(|(amount, count)| {
                let take = (count.saturating_sub(MIN_NOTES_PER_TIER)).min(max_count);

                max_count -= take;
                (amount, take)
            })
            .collect();

        let (selected_notes, unavailable) = self
            .get_available_notes_by_tier_counts(dbtx, excessive_counts)
            .await;

        debug_assert!(
            unavailable.is_empty(),
            "Can't have unavailable notes on a subset of all notes: {unavailable:?}"
        );

        if !selected_notes.is_empty() {
            debug!(target: LOG_CLIENT_MODULE_MINT, note_num=selected_notes.count_items(), denominations_msats=?selected_notes.iter_items().map(|(amount, _)| amount.msats).collect::<Vec<_>>(), "Will consolidate excessive notes");
        }

        let mut selected_notes_decoded = vec![];
        for (amount, note) in selected_notes.iter_items() {
            let spendable_note_decoded = note.decode()?;
            debug!(target: LOG_CLIENT_MODULE_MINT, %amount, %note, "Consolidating note");
            Self::delete_spendable_note(&self.client_ctx, dbtx, amount, &spendable_note_decoded)
                .await;
            selected_notes_decoded.push((amount, spendable_note_decoded));
        }

        let sender = self.balance_update_sender.clone();
        dbtx.on_commit(move || sender.send_replace(()));

        self.create_input_from_notes(selected_notes_decoded.into_iter().collect())
    }

    /// Create a mint input from external, potentially untrusted notes
    #[allow(clippy::type_complexity)]
    pub fn create_input_from_notes(
        &self,
        notes: TieredMulti<SpendableNote>,
    ) -> anyhow::Result<Vec<(ClientInput<MintInput>, SpendableNote)>> {
        let mut inputs_and_notes = Vec::new();

        for (amount, spendable_note) in notes.into_iter_items() {
            let key = self
                .cfg
                .tbs_pks
                .get(amount)
                .ok_or(anyhow!("Invalid amount tier: {amount}"))?;

            let note = spendable_note.note();

            if !note.verify(*key) {
                bail!("Invalid note");
            }

            inputs_and_notes.push((
                ClientInput {
                    input: MintInput::new_v0(amount, note),
                    keys: vec![spendable_note.spend_key],
                    amounts: Amounts::new_bitcoin(amount),
                },
                spendable_note,
            ));
        }

        Ok(inputs_and_notes)
    }

    async fn spend_notes_oob(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        notes_selector: &impl NotesSelector,
        amount: Amount,
        try_cancel_after: Duration,
    ) -> anyhow::Result<(
        OperationId,
        Vec<MintClientStateMachines>,
        TieredMulti<SpendableNote>,
    )> {
        ensure!(
            amount > Amount::ZERO,
            "zero-amount out-of-band spends are not supported"
        );

        let selected_notes =
            Self::select_notes(dbtx, notes_selector, amount, FeeConsensus::zero()).await?;

        let operation_id = spendable_notes_to_operation_id(&selected_notes);

        for (amount, note) in selected_notes.iter_items() {
            debug!(target: LOG_CLIENT_MODULE_MINT, %amount, %note, "Spending note as oob");
            MintClientModule::delete_spendable_note(&self.client_ctx, dbtx, amount, note).await;
        }

        let sender = self.balance_update_sender.clone();
        dbtx.on_commit(move || sender.send_replace(()));

        let state_machines = vec![MintClientStateMachines::OOB(MintOOBStateMachine {
            operation_id,
            state: MintOOBStates::CreatedMulti(MintOOBStatesCreatedMulti {
                spendable_notes: selected_notes.clone().into_iter_items().collect(),
                timeout: fedimint_core::time::now() + try_cancel_after,
            }),
        })];

        Ok((operation_id, state_machines, selected_notes))
    }

    pub async fn await_spend_oob_refund(&self, operation_id: OperationId) -> SpendOOBRefund {
        Box::pin(
            self.notifier
                .subscribe(operation_id)
                .await
                .filter_map(|state| async {
                    let MintClientStateMachines::OOB(state) = state else {
                        return None;
                    };

                    match state.state {
                        MintOOBStates::TimeoutRefund(refund) => Some(SpendOOBRefund {
                            user_triggered: false,
                            transaction_ids: vec![refund.refund_txid],
                        }),
                        MintOOBStates::UserRefund(refund) => Some(SpendOOBRefund {
                            user_triggered: true,
                            transaction_ids: vec![refund.refund_txid],
                        }),
                        MintOOBStates::UserRefundMulti(refund) => Some(SpendOOBRefund {
                            user_triggered: true,
                            transaction_ids: vec![refund.refund_txid],
                        }),
                        MintOOBStates::Created(_) | MintOOBStates::CreatedMulti(_) => None,
                    }
                }),
        )
        .next_or_pending()
        .await
    }

    /// Select notes with `requested_amount` using `notes_selector`.
    async fn select_notes(
        dbtx: &mut DatabaseTransaction<'_>,
        notes_selector: &impl NotesSelector,
        requested_amount: Amount,
        fee_consensus: FeeConsensus,
    ) -> anyhow::Result<TieredMulti<SpendableNote>> {
        let note_stream = dbtx
            .find_by_prefix_sorted_descending(&NoteKeyPrefix)
            .await
            .map(|(key, note)| (key.amount, note));

        notes_selector
            .select_notes(note_stream, requested_amount, fee_consensus)
            .await?
            .into_iter_items()
            .map(|(amt, snote)| Ok((amt, snote.decode()?)))
            .collect::<anyhow::Result<TieredMulti<_>>>()
    }

    async fn get_all_spendable_notes(
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> TieredMulti<SpendableNoteUndecoded> {
        (dbtx
            .find_by_prefix(&NoteKeyPrefix)
            .await
            .map(|(key, note)| (key.amount, note))
            .collect::<Vec<_>>()
            .await)
            .into_iter()
            .collect()
    }

    async fn get_next_note_index(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        amount: Amount,
    ) -> NoteIndex {
        NoteIndex(
            dbtx.get_value(&NextECashNoteIndexKey(amount))
                .await
                .unwrap_or(0),
        )
    }

    /// Derive the note `DerivableSecret` from the Mint's `secret` the `amount`
    /// tier and `note_idx`
    ///
    /// Static to help re-use in other places, that don't have a whole [`Self`]
    /// available
    ///
    /// # E-Cash Note Creation
    ///
    /// When creating an e-cash note, the `MintClientModule` first derives the
    /// blinding and spend keys from the `DerivableSecret`. It then creates a
    /// `NoteIssuanceRequest` containing the blinded spend key and sends it to
    /// the mint server. The mint server signs the blinded spend key and
    /// returns it to the client. The client can then unblind the signed
    /// spend key to obtain the e-cash note, which can be spent using the
    /// spend key.
    pub fn new_note_secret_static(
        secret: &DerivableSecret,
        amount: Amount,
        note_idx: NoteIndex,
    ) -> DerivableSecret {
        assert_eq!(secret.level(), 2);
        debug!(?secret, %amount, %note_idx, "Deriving new mint note");
        secret
            .child_key(MINT_E_CASH_TYPE_CHILD_ID) // TODO: cache
            .child_key(ChildId(note_idx.as_u64()))
            .child_key(ChildId(amount.msats))
    }

    /// We always keep track of an incrementing index in the database and use
    /// it as part of the derivation path for the note secret. This ensures that
    /// we never reuse the same note secret twice.
    async fn new_note_secret(
        &self,
        amount: Amount,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> DerivableSecret {
        let new_idx = self.get_next_note_index(dbtx, amount).await;
        dbtx.insert_entry(&NextECashNoteIndexKey(amount), &new_idx.next().as_u64())
            .await;
        Self::new_note_secret_static(&self.secret, amount, new_idx)
    }

    pub async fn new_ecash_note(
        &self,
        amount: Amount,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> (NoteIssuanceRequest, BlindNonce) {
        let secret = self.new_note_secret(amount, dbtx).await;
        NoteIssuanceRequest::new(&self.secp, &secret)
    }

    /// Try to reissue e-cash notes received from a third party to receive them
    /// in our wallet. The progress and outcome can be observed using
    /// [`MintClientModule::subscribe_reissue_external_notes`].
    /// Can return error of type [`ReissueExternalNotesError`]
    pub async fn reissue_external_notes<M: Serialize + Send>(
        &self,
        oob_notes: OOBNotes,
        extra_meta: M,
    ) -> anyhow::Result<OperationId> {
        let notes = oob_notes.notes().clone();
        let federation_id_prefix = oob_notes.federation_id_prefix();

        ensure!(
            notes.total_amount() > Amount::ZERO,
            "Reissuing zero-amount e-cash isn't supported"
        );

        if federation_id_prefix != self.federation_id.to_prefix() {
            bail!(ReissueExternalNotesError::WrongFederationId);
        }

        let operation_id = OperationId(
            notes
                .consensus_hash::<sha256t::Hash<OOBReissueTag>>()
                .to_byte_array(),
        );

        let amount = notes.total_amount();
        let mint_inputs = self.create_input_from_notes(notes)?;

        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_dyn(create_bundle_for_inputs(mint_inputs, operation_id)),
        );

        let extra_meta = serde_json::to_value(extra_meta)
            .expect("MintClientModule::reissue_external_notes extra_meta is serializable");
        let operation_meta_gen = move |change_range: OutPointRange| MintOperationMeta {
            variant: MintOperationMetaVariant::Reissuance {
                legacy_out_point: None,
                txid: Some(change_range.txid()),
                out_point_indices: change_range
                    .into_iter()
                    .map(|out_point| out_point.out_idx)
                    .collect(),
            },
            amount,
            extra_meta: extra_meta.clone(),
        };

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                MintCommonInit::KIND.as_str(),
                operation_meta_gen,
                tx,
            )
            .await
            .context(ReissueExternalNotesError::AlreadyReissued)?;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        self.client_ctx
            .log_event(&mut dbtx, OOBNotesReissued { amount })
            .await;

        self.client_ctx
            .log_event(
                &mut dbtx,
                ReceivePaymentEvent {
                    operation_id,
                    amount,
                },
            )
            .await;

        dbtx.commit_tx().await;

        Ok(operation_id)
    }

    /// Subscribe to updates on the progress of a reissue operation started with
    /// [`MintClientModule::reissue_external_notes`].
    pub async fn subscribe_reissue_external_notes(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<ReissueExternalNotesState>> {
        let operation = self.mint_operation(operation_id).await?;
        let (txid, out_points) = match operation.meta::<MintOperationMeta>().variant {
            MintOperationMetaVariant::Reissuance {
                legacy_out_point,
                txid,
                out_point_indices,
            } => {
                // Either txid or legacy_out_point will be present, so we should always
                // have a source for the txid
                let txid = txid
                    .or(legacy_out_point.map(|out_point| out_point.txid))
                    .context("Empty reissuance not permitted, this should never happen")?;

                let out_points = out_point_indices
                    .into_iter()
                    .map(|out_idx| OutPoint { txid, out_idx })
                    .chain(legacy_out_point)
                    .collect::<Vec<_>>();

                (txid, out_points)
            }
            MintOperationMetaVariant::SpendOOB { .. } => bail!("Operation is not a reissuance"),
        };

        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                yield ReissueExternalNotesState::Created;

                match client_ctx
                    .transaction_updates(operation_id)
                    .await
                    .await_tx_accepted(txid)
                    .await
                {
                    Ok(()) => {
                        yield ReissueExternalNotesState::Issuing;
                    }
                    Err(e) => {
                        yield ReissueExternalNotesState::Failed(format!("Transaction not accepted {e:?}"));
                        return;
                    }
                }

                for out_point in out_points {
                    if let Err(e) = client_ctx.self_ref().await_output_finalized(operation_id, out_point).await {
                        yield ReissueExternalNotesState::Failed(e.to_string());
                        return;
                    }
                }
                yield ReissueExternalNotesState::Done;
            }}
        ))
    }

    /// Fetches and removes notes of *at least* amount `min_amount` from the
    /// wallet to be sent to the recipient out of band. These spends can be
    /// canceled by calling [`MintClientModule::try_cancel_spend_notes`] as long
    /// as the recipient hasn't reissued the e-cash notes themselves yet.
    ///
    /// The client will also automatically attempt to cancel the operation after
    /// `try_cancel_after` time has passed. This is a safety mechanism to avoid
    /// users forgetting about failed out-of-band transactions. The timeout
    /// should be chosen such that the recipient (who is potentially offline at
    /// the time of receiving the e-cash notes) had a reasonable timeframe to
    /// come online and reissue the notes themselves.
    #[deprecated(
        since = "0.5.0",
        note = "Use `spend_notes_with_selector` instead, with `SelectNotesWithAtleastAmount` to maintain the same behavior"
    )]
    pub async fn spend_notes<M: Serialize + Send>(
        &self,
        min_amount: Amount,
        try_cancel_after: Duration,
        include_invite: bool,
        extra_meta: M,
    ) -> anyhow::Result<(OperationId, OOBNotes)> {
        self.spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            min_amount,
            try_cancel_after,
            include_invite,
            extra_meta,
        )
        .await
    }

    /// Fetches and removes notes from the wallet to be sent to the recipient
    /// out of band. The note selection algorithm is determined by
    /// `note_selector`. See the [`NotesSelector`] trait for available
    /// implementations.
    ///
    /// These spends can be canceled by calling
    /// [`MintClientModule::try_cancel_spend_notes`] as long
    /// as the recipient hasn't reissued the e-cash notes themselves yet.
    ///
    /// The client will also automatically attempt to cancel the operation after
    /// `try_cancel_after` time has passed. This is a safety mechanism to avoid
    /// users forgetting about failed out-of-band transactions. The timeout
    /// should be chosen such that the recipient (who is potentially offline at
    /// the time of receiving the e-cash notes) had a reasonable timeframe to
    /// come online and reissue the notes themselves.
    pub async fn spend_notes_with_selector<M: Serialize + Send>(
        &self,
        notes_selector: &impl NotesSelector,
        requested_amount: Amount,
        try_cancel_after: Duration,
        include_invite: bool,
        extra_meta: M,
    ) -> anyhow::Result<(OperationId, OOBNotes)> {
        let federation_id_prefix = self.federation_id.to_prefix();
        let extra_meta = serde_json::to_value(extra_meta)
            .expect("MintClientModule::spend_notes extra_meta is serializable");

        self.client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let extra_meta = extra_meta.clone();
                    Box::pin(async {
                        let (operation_id, states, notes) = self
                            .spend_notes_oob(
                                dbtx,
                                notes_selector,
                                requested_amount,
                                try_cancel_after,
                            )
                            .await?;

                        let oob_notes = if include_invite {
                            OOBNotes::new_with_invite(
                                notes,
                                &self.client_ctx.get_invite_code().await,
                            )
                        } else {
                            OOBNotes::new(federation_id_prefix, notes)
                        };

                        self.client_ctx
                            .add_state_machines_dbtx(
                                dbtx,
                                self.client_ctx.map_dyn(states).collect(),
                            )
                            .await?;
                        self.client_ctx
                            .add_operation_log_entry_dbtx(
                                dbtx,
                                operation_id,
                                MintCommonInit::KIND.as_str(),
                                MintOperationMeta {
                                    variant: MintOperationMetaVariant::SpendOOB {
                                        requested_amount,
                                        oob_notes: oob_notes.clone(),
                                    },
                                    amount: oob_notes.total_amount(),
                                    extra_meta,
                                },
                            )
                            .await;
                        self.client_ctx
                            .log_event(
                                dbtx,
                                OOBNotesSpent {
                                    requested_amount,
                                    spent_amount: oob_notes.total_amount(),
                                    timeout: try_cancel_after,
                                    include_invite,
                                },
                            )
                            .await;

                        self.client_ctx
                            .log_event(
                                dbtx,
                                SendPaymentEvent {
                                    operation_id,
                                    amount: oob_notes.total_amount(),
                                    oob_notes: encode_prefixed(FEDIMINT_PREFIX, &oob_notes),
                                },
                            )
                            .await;

                        Ok((operation_id, oob_notes))
                    })
                },
                Some(100),
            )
            .await
            .map_err(|e| match e {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { last_error, .. } => {
                    anyhow!("Commit to DB failed: {last_error}")
                }
            })
    }

    /// Send e-cash notes for the requested amount.
    ///
    /// When this method removes ecash notes from the local database it will do
    /// so atomically with creating a `SendPaymentEvent` that contains the notes
    /// in out of band serilaized from. Hence it is critical for the integrator
    /// to display this event to ensure the user always has access to his funds.
    ///
    /// This method operates in two modes:
    ///
    /// 1. **Offline mode**: If exact notes are available in the wallet, they
    ///    are spent immediately without contacting the federation. A
    ///    `SendPaymentEvent` is emitted and the notes are returned.
    ///
    /// 2. **Online mode**: If exact notes are not available, the method
    ///    contacts the federation to trigger a reissuance transaction to obtain
    ///    the proper denominations. The method will block until the reissuance
    ///    completes, at which point a `SendPaymentEvent` is emitted and the
    ///    notes are returned.
    ///
    /// If the method enters online mode and is cancelled, e.g. the future is
    /// dropped, before the reissue transaction is confirmed, any reissued notes
    /// will be returned to the wallet and we do not emit a `SendPaymentEvent`.
    ///
    /// Before selection of the ecash notes the amount is rounded up to the
    /// nearest multiple of 512 msat.
    pub async fn send_oob_notes<M: Serialize + Send>(
        &self,
        amount: Amount,
        extra_meta: M,
    ) -> anyhow::Result<OOBNotes> {
        // Round up to the nearest multiple of 512 msat
        let amount = Amount::from_msats(amount.msats.div_ceil(512) * 512);

        let extra_meta = serde_json::to_value(extra_meta)
            .expect("MintClientModule::send_oob_notes extra_meta is serializable");

        // Try to spend exact notes from our current balance
        let oob_notes: Option<OOBNotes> = self
            .client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let extra_meta = extra_meta.clone();
                    Box::pin(async {
                        self.try_spend_exact_notes_dbtx(
                            dbtx,
                            amount,
                            self.federation_id,
                            extra_meta,
                        )
                        .await
                        .map(Ok::<OOBNotes, anyhow::Error>)
                        .transpose()
                    })
                },
                Some(100),
            )
            .await
            .expect("Failed to commit dbtx after 100 retries");

        if let Some(oob_notes) = oob_notes {
            return Ok(oob_notes);
        }

        // Verify we're online
        self.client_ctx
            .global_api()
            .session_count()
            .await
            .context("Cannot reach federation to reissue notes")?;

        let operation_id = OperationId::new_random();

        // Create outputs for reissuance using the existing create_output function
        let output_bundle = self
            .create_output(
                &mut self.client_ctx.module_db().begin_transaction_nc().await,
                operation_id,
                1, // notes_per_denomination
                amount,
            )
            .await;

        // Combine the output bundle state machines with the send state machine
        let combined_bundle = ClientOutputBundle::new(
            output_bundle.outputs().to_vec(),
            output_bundle.sms().to_vec(),
        );

        let outputs = self.client_ctx.make_client_outputs(combined_bundle);

        let em_clone = extra_meta.clone();

        // Submit reissuance transaction with the state machines
        let out_point_range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                MintCommonInit::KIND.as_str(),
                move |change_range: OutPointRange| MintOperationMeta {
                    variant: MintOperationMetaVariant::Reissuance {
                        legacy_out_point: None,
                        txid: Some(change_range.txid()),
                        out_point_indices: change_range
                            .into_iter()
                            .map(|out_point| out_point.out_idx)
                            .collect(),
                    },
                    amount,
                    extra_meta: em_clone.clone(),
                },
                TransactionBuilder::new().with_outputs(outputs),
            )
            .await
            .context("Failed to submit reissuance transaction")?;

        // Wait for outputs to be finalized
        self.client_ctx
            .await_primary_module_outputs(operation_id, out_point_range.into_iter().collect())
            .await
            .context("Failed to await output finalization")?;

        // Recursively call send_oob_notes to try again with the reissued notes
        Box::pin(self.send_oob_notes(amount, extra_meta)).await
    }

    /// Try to spend exact notes from the current balance.
    /// Returns `Some(OOBNotes)` if exact notes are available, `None` otherwise.
    async fn try_spend_exact_notes_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        amount: Amount,
        federation_id: FederationId,
        extra_meta: serde_json::Value,
    ) -> Option<OOBNotes> {
        let selected_notes = Self::select_notes(
            dbtx,
            &SelectNotesWithExactAmount,
            amount,
            FeeConsensus::zero(),
        )
        .await
        .ok()?;

        // Remove notes from our database
        for (note_amount, note) in selected_notes.iter_items() {
            MintClientModule::delete_spendable_note(&self.client_ctx, dbtx, note_amount, note)
                .await;
        }

        let sender = self.balance_update_sender.clone();
        dbtx.on_commit(move || sender.send_replace(()));

        let operation_id = spendable_notes_to_operation_id(&selected_notes);

        let oob_notes = OOBNotes::new(federation_id.to_prefix(), selected_notes);

        // Log the send operation with notes immediately available
        self.client_ctx
            .add_operation_log_entry_dbtx(
                dbtx,
                operation_id,
                MintCommonInit::KIND.as_str(),
                MintOperationMeta {
                    variant: MintOperationMetaVariant::SpendOOB {
                        requested_amount: amount,
                        oob_notes: oob_notes.clone(),
                    },
                    amount: oob_notes.total_amount(),
                    extra_meta,
                },
            )
            .await;

        self.client_ctx
            .log_event(
                dbtx,
                SendPaymentEvent {
                    operation_id,
                    amount: oob_notes.total_amount(),
                    oob_notes: encode_prefixed(FEDIMINT_PREFIX, &oob_notes),
                },
            )
            .await;

        Some(oob_notes)
    }

    /// Validate the given notes and return the total amount of the notes.
    /// Validation checks that:
    /// - the federation ID is correct
    /// - the note has a valid signature
    /// - the spend key is correct.
    pub fn validate_notes(&self, oob_notes: &OOBNotes) -> anyhow::Result<Amount> {
        let federation_id_prefix = oob_notes.federation_id_prefix();
        let notes = oob_notes.notes().clone();

        if federation_id_prefix != self.federation_id.to_prefix() {
            bail!("Federation ID does not match");
        }

        let tbs_pks = &self.cfg.tbs_pks;

        for (idx, (amt, snote)) in notes.iter_items().enumerate() {
            let key = tbs_pks
                .get(amt)
                .ok_or_else(|| anyhow!("Note {idx} uses an invalid amount tier {amt}"))?;

            let note = snote.note();
            if !note.verify(*key) {
                bail!("Note {idx} has an invalid federation signature");
            }

            let expected_nonce = Nonce(snote.spend_key.public_key());
            if note.nonce != expected_nonce {
                bail!("Note {idx} cannot be spent using the supplied spend key");
            }
        }

        Ok(notes.total_amount())
    }

    /// Contacts the mint and checks if the supplied notes were already spent.
    ///
    /// **Caution:** This reduces privacy and can lead to race conditions. **DO
    /// NOT** rely on it for receiving funds unless you really know what you are
    /// doing.
    pub async fn check_note_spent(&self, oob_notes: &OOBNotes) -> anyhow::Result<bool> {
        use crate::api::MintFederationApi;

        let api_client = self.client_ctx.module_api();
        let any_spent = try_join_all(oob_notes.notes().iter().flat_map(|(_, notes)| {
            notes
                .iter()
                .map(|note| api_client.check_note_spent(note.nonce()))
        }))
        .await?
        .into_iter()
        .any(|spent| spent);

        Ok(any_spent)
    }

    /// Try to cancel a spend operation started with
    /// [`MintClientModule::spend_notes_with_selector`]. If the e-cash notes
    /// have already been spent this operation will fail which can be
    /// observed using [`MintClientModule::subscribe_spend_notes`].
    pub async fn try_cancel_spend_notes(&self, operation_id: OperationId) {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        dbtx.insert_entry(&CancelledOOBSpendKey(operation_id), &())
            .await;
        if let Err(e) = dbtx.commit_tx_result().await {
            warn!("We tried to cancel the same OOB spend multiple times concurrently: {e}");
        }
    }

    /// Subscribe to updates on the progress of a raw e-cash spend operation
    /// started with [`MintClientModule::spend_notes_with_selector`].
    pub async fn subscribe_spend_notes(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<SpendOOBState>> {
        let operation = self.mint_operation(operation_id).await?;
        if !matches!(
            operation.meta::<MintOperationMeta>().variant,
            MintOperationMetaVariant::SpendOOB { .. }
        ) {
            bail!("Operation is not a out-of-band spend");
        }

        let client_ctx = self.client_ctx.clone();

        Ok(self
            .client_ctx
            .outcome_or_updates(operation, operation_id, move || {
                stream! {
                    yield SpendOOBState::Created;

                    let self_ref = client_ctx.self_ref();

                    let refund = self_ref
                        .await_spend_oob_refund(operation_id)
                        .await;

                    if refund.user_triggered {
                        yield SpendOOBState::UserCanceledProcessing;
                    }

                    let mut success = true;

                    for txid in refund.transaction_ids {
                        debug!(
                            target: LOG_CLIENT_MODULE_MINT,
                            %txid,
                            operation_id=%operation_id.fmt_short(),
                            "Waiting for oob refund txid"
                        );
                        if client_ctx
                            .transaction_updates(operation_id)
                            .await
                            .await_tx_accepted(txid)
                            .await.is_err() {
                                success = false;
                            }
                    }

                    debug!(
                        target: LOG_CLIENT_MODULE_MINT,
                        operation_id=%operation_id.fmt_short(),
                        %success,
                        "Done waiting for all refund oob txids"
                     );

                    match (refund.user_triggered, success) {
                        (true, true) => {
                            yield SpendOOBState::UserCanceledSuccess;
                        },
                        (true, false) => {
                            yield SpendOOBState::UserCanceledFailure;
                        },
                        (false, true) => {
                            yield SpendOOBState::Refunded;
                        },
                        (false, false) => {
                            yield SpendOOBState::Success;
                        }
                    }
                }
            }))
    }

    async fn mint_operation(&self, operation_id: OperationId) -> anyhow::Result<OperationLogEntry> {
        let operation = self.client_ctx.get_operation(operation_id).await?;

        if operation.operation_module_kind() != MintCommonInit::KIND.as_str() {
            bail!("Operation is not a mint operation");
        }

        Ok(operation)
    }

    async fn delete_spendable_note(
        client_ctx: &ClientContext<MintClientModule>,
        dbtx: &mut DatabaseTransaction<'_>,
        amount: Amount,
        note: &SpendableNote,
    ) {
        client_ctx
            .log_event(
                dbtx,
                NoteSpent {
                    nonce: note.nonce(),
                },
            )
            .await;
        dbtx.remove_entry(&NoteKey {
            amount,
            nonce: note.nonce(),
        })
        .await
        .expect("Must deleted existing spendable note");
    }

    pub async fn advance_note_idx(&self, amount: Amount) -> anyhow::Result<DerivableSecret> {
        let db = self.client_ctx.module_db().clone();

        Ok(db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async {
                        Ok::<DerivableSecret, anyhow::Error>(
                            self.new_note_secret(amount, dbtx).await,
                        )
                    })
                },
                None,
            )
            .await?)
    }

    /// Returns secrets for the note indices that were reused by previous
    /// clients with same client secret.
    pub async fn reused_note_secrets(&self) -> Vec<(Amount, NoteIssuanceRequest, BlindNonce)> {
        self.client_ctx
            .module_db()
            .begin_transaction_nc()
            .await
            .get_value(&ReusedNoteIndices)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(amount, note_idx)| {
                let secret = Self::new_note_secret_static(&self.secret, amount, note_idx);
                let (request, blind_nonce) =
                    NoteIssuanceRequest::new(fedimint_core::secp256k1::SECP256K1, &secret);
                (amount, request, blind_nonce)
            })
            .collect()
    }
}

pub fn spendable_notes_to_operation_id(
    spendable_selected_notes: &TieredMulti<SpendableNote>,
) -> OperationId {
    OperationId(
        spendable_selected_notes
            .consensus_hash::<sha256t::Hash<OOBSpendTag>>()
            .to_byte_array(),
    )
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpendOOBRefund {
    pub user_triggered: bool,
    pub transaction_ids: Vec<TransactionId>,
}

/// Defines a strategy for selecting e-cash notes given a specific target amount
/// and fee per note transaction input.
#[apply(async_trait_maybe_send!)]
pub trait NotesSelector<Note = SpendableNoteUndecoded>: Send + Sync {
    /// Select notes from stream for `requested_amount`.
    /// The stream must produce items in non- decreasing order of amount.
    async fn select_notes(
        &self,
        // FIXME: async trait doesn't like maybe_add_send
        #[cfg(not(target_family = "wasm"))] stream: impl futures::Stream<Item = (Amount, Note)> + Send,
        #[cfg(target_family = "wasm")] stream: impl futures::Stream<Item = (Amount, Note)>,
        requested_amount: Amount,
        fee_consensus: FeeConsensus,
    ) -> anyhow::Result<TieredMulti<Note>>;
}

/// Select notes with total amount of *at least* `request_amount`. If more than
/// requested amount of notes are returned it was because exact change couldn't
/// be made, and the next smallest amount will be returned.
///
/// The caller can request change from the federation.
pub struct SelectNotesWithAtleastAmount;

#[apply(async_trait_maybe_send!)]
impl<Note: Send> NotesSelector<Note> for SelectNotesWithAtleastAmount {
    async fn select_notes(
        &self,
        #[cfg(not(target_family = "wasm"))] stream: impl futures::Stream<Item = (Amount, Note)> + Send,
        #[cfg(target_family = "wasm")] stream: impl futures::Stream<Item = (Amount, Note)>,
        requested_amount: Amount,
        fee_consensus: FeeConsensus,
    ) -> anyhow::Result<TieredMulti<Note>> {
        Ok(select_notes_from_stream(stream, requested_amount, fee_consensus).await?)
    }
}

/// Select notes with total amount of *exactly* `request_amount`. If the amount
/// cannot be represented with the available denominations an error is returned,
/// this **does not** mean that the balance is too low.
pub struct SelectNotesWithExactAmount;

#[apply(async_trait_maybe_send!)]
impl<Note: Send> NotesSelector<Note> for SelectNotesWithExactAmount {
    async fn select_notes(
        &self,
        #[cfg(not(target_family = "wasm"))] stream: impl futures::Stream<Item = (Amount, Note)> + Send,
        #[cfg(target_family = "wasm")] stream: impl futures::Stream<Item = (Amount, Note)>,
        requested_amount: Amount,
        fee_consensus: FeeConsensus,
    ) -> anyhow::Result<TieredMulti<Note>> {
        let notes = select_notes_from_stream(stream, requested_amount, fee_consensus).await?;

        if notes.total_amount() != requested_amount {
            bail!(
                "Could not select notes with exact amount. Requested amount: {}. Selected amount: {}",
                requested_amount,
                notes.total_amount()
            );
        }

        Ok(notes)
    }
}

// We are using a greedy algorithm to select notes. We start with the largest
// then proceed to the lowest tiers/denominations.
// But there is a catch: we don't know if there are enough notes in the lowest
// tiers, so we need to save a big note in case the sum of the following
// small notes are not enough.
async fn select_notes_from_stream<Note>(
    stream: impl futures::Stream<Item = (Amount, Note)>,
    requested_amount: Amount,
    fee_consensus: FeeConsensus,
) -> Result<TieredMulti<Note>, InsufficientBalanceError> {
    if requested_amount == Amount::ZERO {
        return Ok(TieredMulti::default());
    }
    let mut stream = Box::pin(stream);
    let mut selected = vec![];
    // This is the big note we save in case the sum of the following small notes are
    // not sufficient to cover the pending amount
    // The tuple is (amount, note, checkpoint), where checkpoint is the index where
    // the note should be inserted on the selected vector if it is needed
    let mut last_big_note_checkpoint: Option<(Amount, Note, usize)> = None;
    let mut pending_amount = requested_amount;
    let mut previous_amount: Option<Amount> = None; // used to assert descending order
    loop {
        if let Some((note_amount, note)) = stream.next().await {
            assert!(
                previous_amount.is_none_or(|previous| previous >= note_amount),
                "notes are not sorted in descending order"
            );
            previous_amount = Some(note_amount);

            if note_amount <= fee_consensus.fee(note_amount) {
                continue;
            }

            match note_amount.cmp(&(pending_amount + fee_consensus.fee(note_amount))) {
                Ordering::Less => {
                    // keep adding notes until we have enough
                    pending_amount += fee_consensus.fee(note_amount);
                    pending_amount -= note_amount;
                    selected.push((note_amount, note));
                }
                Ordering::Greater => {
                    // probably we don't need this big note, but we'll keep it in case the
                    // following small notes don't add up to the
                    // requested amount
                    last_big_note_checkpoint = Some((note_amount, note, selected.len()));
                }
                Ordering::Equal => {
                    // exactly enough notes, return
                    selected.push((note_amount, note));

                    let notes: TieredMulti<Note> = selected.into_iter().collect();

                    assert!(
                        notes.total_amount().msats
                            >= requested_amount.msats
                                + notes
                                    .iter()
                                    .map(|note| fee_consensus.fee(note.0))
                                    .sum::<Amount>()
                                    .msats
                    );

                    return Ok(notes);
                }
            }
        } else {
            assert!(pending_amount > Amount::ZERO);
            if let Some((big_note_amount, big_note, checkpoint)) = last_big_note_checkpoint {
                // the sum of the small notes don't add up to the pending amount, remove
                // them
                selected.truncate(checkpoint);
                // and use the big note to cover it
                selected.push((big_note_amount, big_note));

                let notes: TieredMulti<Note> = selected.into_iter().collect();

                assert!(
                    notes.total_amount().msats
                        >= requested_amount.msats
                            + notes
                                .iter()
                                .map(|note| fee_consensus.fee(note.0))
                                .sum::<Amount>()
                                .msats
                );

                // so now we have enough to cover the requested amount, return
                return Ok(notes);
            }

            let total_amount = requested_amount.saturating_sub(pending_amount);
            // not enough notes, return
            return Err(InsufficientBalanceError {
                requested_amount,
                total_amount,
            });
        }
    }
}

#[derive(Debug, Clone, Error)]
pub struct InsufficientBalanceError {
    pub requested_amount: Amount,
    pub total_amount: Amount,
}

impl std::fmt::Display for InsufficientBalanceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Insufficient balance: requested {} but only {} available",
            self.requested_amount, self.total_amount
        )
    }
}

/// Old and no longer used, will be deleted in the future
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
enum MintRestoreStates {
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Old and no longer used, will be deleted in the future
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MintRestoreStateMachine {
    operation_id: OperationId,
    state: MintRestoreStates,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MintClientStateMachines {
    Output(MintOutputStateMachine),
    Input(MintInputStateMachine),
    OOB(MintOOBStateMachine),
    // Removed in https://github.com/fedimint/fedimint/pull/4035 , now ignored
    Restore(MintRestoreStateMachine),
}

impl IntoDynInstance for MintClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for MintClientStateMachines {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            MintClientStateMachines::Output(issuance_state) => {
                sm_enum_variant_translation!(
                    issuance_state.transitions(context, global_context),
                    MintClientStateMachines::Output
                )
            }
            MintClientStateMachines::Input(redemption_state) => {
                sm_enum_variant_translation!(
                    redemption_state.transitions(context, global_context),
                    MintClientStateMachines::Input
                )
            }
            MintClientStateMachines::OOB(oob_state) => {
                sm_enum_variant_translation!(
                    oob_state.transitions(context, global_context),
                    MintClientStateMachines::OOB
                )
            }
            MintClientStateMachines::Restore(_) => {
                sm_enum_variant_translation!(vec![], MintClientStateMachines::Restore)
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            MintClientStateMachines::Output(issuance_state) => issuance_state.operation_id(),
            MintClientStateMachines::Input(redemption_state) => redemption_state.operation_id(),
            MintClientStateMachines::OOB(oob_state) => oob_state.operation_id(),
            MintClientStateMachines::Restore(r) => r.operation_id,
        }
    }
}

/// A [`Note`] with associated secret key that allows to proof ownership (spend
/// it)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SpendableNote {
    pub signature: tbs::Signature,
    pub spend_key: Keypair,
}

impl fmt::Debug for SpendableNote {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpendableNote")
            .field("nonce", &self.nonce())
            .field("signature", &self.signature)
            .field("spend_key", &self.spend_key)
            .finish()
    }
}
impl fmt::Display for SpendableNote {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.nonce().fmt(f)
    }
}

impl SpendableNote {
    pub fn nonce(&self) -> Nonce {
        Nonce(self.spend_key.public_key())
    }

    fn note(&self) -> Note {
        Note {
            nonce: self.nonce(),
            signature: self.signature,
        }
    }

    pub fn to_undecoded(&self) -> SpendableNoteUndecoded {
        SpendableNoteUndecoded {
            signature: self
                .signature
                .consensus_encode_to_vec()
                .try_into()
                .expect("Encoded size always correct"),
            spend_key: self.spend_key,
        }
    }
}

/// A version of [`SpendableNote`] that didn't decode the `signature` yet
///
/// **Note**: signature decoding from raw bytes is faliable, as not all bytes
/// are valid signatures. Therefore this type must not be used for external
/// data, and should be limited to optimizing reading from internal database.
///
/// The signature bytes will be validated in [`Self::decode`].
///
/// Decoding [`tbs::Signature`] is somewhat CPU-intensive (see benches in this
/// crate), and when most of the result will be filtered away or completely
/// unused, it makes sense to skip/delay decoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Encodable, Decodable, Serialize)]
pub struct SpendableNoteUndecoded {
    // Need to keep this in sync with `tbs::Signature`, but there's a test
    // verifying they serialize and decode the same.
    #[serde(serialize_with = "serdect::array::serialize_hex_lower_or_bin")]
    pub signature: [u8; 48],
    pub spend_key: Keypair,
}

impl fmt::Display for SpendableNoteUndecoded {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.nonce().fmt(f)
    }
}

impl fmt::Debug for SpendableNoteUndecoded {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpendableNote")
            .field("nonce", &self.nonce())
            .field("signature", &"[raw]")
            .field("spend_key", &self.spend_key)
            .finish()
    }
}

impl SpendableNoteUndecoded {
    fn nonce(&self) -> Nonce {
        Nonce(self.spend_key.public_key())
    }

    pub fn decode(self) -> anyhow::Result<SpendableNote> {
        Ok(SpendableNote {
            signature: Decodable::consensus_decode_partial_from_finite_reader(
                &mut self.signature.as_slice(),
                &ModuleRegistry::default(),
            )?,
            spend_key: self.spend_key,
        })
    }
}

/// An index used to deterministically derive [`Note`]s
///
/// We allow converting it to u64 and incrementing it, but
/// messing with it should be somewhat restricted to prevent
/// silly errors.
#[derive(
    Copy,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Encodable,
    Decodable,
    Default,
    PartialOrd,
    Ord,
)]
pub struct NoteIndex(u64);

impl NoteIndex {
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }

    fn prev(self) -> Option<Self> {
        self.0.checked_sub(0).map(Self)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    // Private. If it turns out it is useful outside,
    // we can relax and convert to `From<u64>`
    // Actually used in tests RN, so cargo complains in non-test builds.
    #[allow(unused)]
    pub fn from_u64(v: u64) -> Self {
        Self(v)
    }

    pub fn advance(&mut self) {
        *self = self.next();
    }
}

impl std::fmt::Display for NoteIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

struct OOBSpendTag;

impl sha256t::Tag for OOBSpendTag {
    fn engine() -> sha256::HashEngine {
        let mut engine = sha256::HashEngine::default();
        engine.input(b"oob-spend");
        engine
    }
}

struct OOBReissueTag;

impl sha256t::Tag for OOBReissueTag {
    fn engine() -> sha256::HashEngine {
        let mut engine = sha256::HashEngine::default();
        engine.input(b"oob-reissue");
        engine
    }
}

/// Determines the denominations to use when representing an amount
///
/// Algorithm tries to leave the user with a target number of
/// `denomination_sets` starting at the lowest denomination.  `self`
/// gives the denominations that the user already has.
pub fn represent_amount<K>(
    amount: Amount,
    current_denominations: &TieredCounts,
    tiers: &Tiered<K>,
    denomination_sets: u16,
    fee_consensus: &FeeConsensus,
) -> TieredCounts {
    let mut remaining_amount = amount;
    let mut denominations = TieredCounts::default();

    // try to hit the target `denomination_sets`
    for tier in tiers.tiers() {
        let notes = current_denominations.get(*tier);
        let missing_notes = u64::from(denomination_sets).saturating_sub(notes as u64);
        let possible_notes = remaining_amount / (*tier + fee_consensus.fee(*tier));

        let add_notes = min(possible_notes, missing_notes);
        denominations.inc(*tier, add_notes as usize);
        remaining_amount -= (*tier + fee_consensus.fee(*tier)) * add_notes;
    }

    // if there is a remaining amount, add denominations with a greedy algorithm
    for tier in tiers.tiers().rev() {
        let res = remaining_amount / (*tier + fee_consensus.fee(*tier));
        remaining_amount -= (*tier + fee_consensus.fee(*tier)) * res;
        denominations.inc(*tier, res as usize);
    }

    let represented: u64 = denominations
        .iter()
        .map(|(k, v)| (k + fee_consensus.fee(k)).msats * (v as u64))
        .sum();

    assert!(represented <= amount.msats);
    assert!(represented + fee_consensus.fee(Amount::from_msats(1)).msats >= amount.msats);

    denominations
}

pub(crate) fn create_bundle_for_inputs(
    inputs_and_notes: Vec<(ClientInput<MintInput>, SpendableNote)>,
    operation_id: OperationId,
) -> ClientInputBundle<MintInput, MintClientStateMachines> {
    let mut inputs = Vec::new();
    let mut input_states = Vec::new();

    for (input, spendable_note) in inputs_and_notes {
        input_states.push((input.amounts.clone(), spendable_note));
        inputs.push(input);
    }

    let input_sm = Arc::new(move |out_point_range: OutPointRange| {
        debug_assert_eq!(out_point_range.into_iter().count(), input_states.len());

        vec![MintClientStateMachines::Input(MintInputStateMachine {
            common: MintInputCommon {
                operation_id,
                out_point_range,
            },
            state: MintInputStates::CreatedBundle(MintInputStateCreatedBundle {
                notes: input_states
                    .iter()
                    .map(|(amounts, note)| (amounts.expect_only_bitcoin(), *note))
                    .collect(),
            }),
        })]
    });

    ClientInputBundle::new(
        inputs,
        vec![ClientInputSM {
            state_machines: input_sm,
        }],
    )
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;
    use std::str::FromStr;

    use bitcoin_hashes::Hash;
    use fedimint_core::base32::FEDIMINT_PREFIX;
    use fedimint_core::config::FederationId;
    use fedimint_core::encoding::Decodable;
    use fedimint_core::invite_code::InviteCode;
    use fedimint_core::module::registry::ModuleRegistry;
    use fedimint_core::{
        Amount, OutPoint, PeerId, Tiered, TieredCounts, TieredMulti, TransactionId,
    };
    use fedimint_mint_common::config::FeeConsensus;
    use itertools::Itertools;
    use serde_json::json;

    use crate::{
        MintOperationMetaVariant, OOBNotes, OOBNotesPart, SpendableNote, SpendableNoteUndecoded,
        represent_amount, select_notes_from_stream,
    };

    #[test]
    fn represent_amount_targets_denomination_sets() {
        fn tiers(tiers: Vec<u64>) -> Tiered<()> {
            tiers
                .into_iter()
                .map(|tier| (Amount::from_sats(tier), ()))
                .collect()
        }

        fn denominations(denominations: Vec<(Amount, usize)>) -> TieredCounts {
            TieredCounts::from_iter(denominations)
        }

        let starting = notes(vec![
            (Amount::from_sats(1), 1),
            (Amount::from_sats(2), 3),
            (Amount::from_sats(3), 2),
        ])
        .summary();
        let tiers = tiers(vec![1, 2, 3, 4]);

        // target 3 tiers will fill out the 1 and 3 denominations
        assert_eq!(
            represent_amount(
                Amount::from_sats(6),
                &starting,
                &tiers,
                3,
                &FeeConsensus::zero()
            ),
            denominations(vec![(Amount::from_sats(1), 3), (Amount::from_sats(3), 1),])
        );

        // target 2 tiers will fill out the 1 and 4 denominations
        assert_eq!(
            represent_amount(
                Amount::from_sats(6),
                &starting,
                &tiers,
                2,
                &FeeConsensus::zero()
            ),
            denominations(vec![(Amount::from_sats(1), 2), (Amount::from_sats(4), 1)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_avg_test() {
        let max_amount = Amount::from_sats(1_000_000);
        let tiers = Tiered::gen_denominations(2, max_amount);
        let tiered = represent_amount::<()>(
            max_amount,
            &TieredCounts::default(),
            &tiers,
            3,
            &FeeConsensus::zero(),
        );

        let mut total_notes = 0;
        for multiplier in 1..100 {
            let stream = reverse_sorted_note_stream(tiered.iter().collect());
            let select = select_notes_from_stream(
                stream,
                Amount::from_sats(multiplier * 1000),
                FeeConsensus::zero(),
            )
            .await;
            total_notes += select.unwrap().into_iter_items().count();
        }
        assert_eq!(total_notes / 100, 10);
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_exact_amount_with_minimum_notes() {
        let f = || {
            reverse_sorted_note_stream(vec![
                (Amount::from_sats(1), 10),
                (Amount::from_sats(5), 10),
                (Amount::from_sats(20), 10),
            ])
        };
        assert_eq!(
            select_notes_from_stream(f(), Amount::from_sats(7), FeeConsensus::zero())
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(1), 2), (Amount::from_sats(5), 1)])
        );
        assert_eq!(
            select_notes_from_stream(f(), Amount::from_sats(20), FeeConsensus::zero())
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(20), 1)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_next_smallest_amount_if_exact_change_cannot_be_made() {
        let stream = reverse_sorted_note_stream(vec![
            (Amount::from_sats(1), 1),
            (Amount::from_sats(5), 5),
            (Amount::from_sats(20), 5),
        ]);
        assert_eq!(
            select_notes_from_stream(stream, Amount::from_sats(7), FeeConsensus::zero())
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(5), 2)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_uses_big_note_if_small_amounts_are_not_sufficient() {
        let stream = reverse_sorted_note_stream(vec![
            (Amount::from_sats(1), 3),
            (Amount::from_sats(5), 3),
            (Amount::from_sats(20), 2),
        ]);
        assert_eq!(
            select_notes_from_stream(stream, Amount::from_sats(39), FeeConsensus::zero())
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(20), 2)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_error_if_amount_is_too_large() {
        let stream = reverse_sorted_note_stream(vec![(Amount::from_sats(10), 1)]);
        let error = select_notes_from_stream(stream, Amount::from_sats(100), FeeConsensus::zero())
            .await
            .unwrap_err();
        assert_eq!(error.total_amount, Amount::from_sats(10));
    }

    fn reverse_sorted_note_stream(
        notes: Vec<(Amount, usize)>,
    ) -> impl futures::Stream<Item = (Amount, String)> {
        futures::stream::iter(
            notes
                .into_iter()
                // We are creating `number` dummy notes of `amount` value
                .flat_map(|(amount, number)| vec![(amount, "dummy note".into()); number])
                .sorted()
                .rev(),
        )
    }

    fn notes(notes: Vec<(Amount, usize)>) -> TieredMulti<String> {
        notes
            .into_iter()
            .flat_map(|(amount, number)| vec![(amount, "dummy note".into()); number])
            .collect()
    }

    #[test]
    fn decoding_empty_oob_notes_fails() {
        let empty_oob_notes =
            OOBNotes::new(FederationId::dummy().to_prefix(), TieredMulti::default());
        let oob_notes_string = empty_oob_notes.to_string();

        let res = oob_notes_string.parse::<OOBNotes>();

        assert!(res.is_err(), "An empty OOB notes string should not parse");
    }

    fn test_roundtrip_serialize_str<T, F>(data: T, assertions: F)
    where
        T: FromStr + Display + crate::Encodable + crate::Decodable,
        <T as FromStr>::Err: std::fmt::Debug,
        F: Fn(T),
    {
        let data_parsed = data.to_string().parse().expect("Deserialization failed");

        assertions(data_parsed);

        let data_parsed = crate::base32::encode_prefixed(FEDIMINT_PREFIX, &data)
            .parse()
            .expect("Deserialization failed");

        assertions(data_parsed);

        assertions(data);
    }

    #[test]
    fn notes_encode_decode() {
        let federation_id_1 =
            FederationId(bitcoin_hashes::sha256::Hash::from_byte_array([0x21; 32]));
        let federation_id_prefix_1 = federation_id_1.to_prefix();
        let federation_id_2 =
            FederationId(bitcoin_hashes::sha256::Hash::from_byte_array([0x42; 32]));
        let federation_id_prefix_2 = federation_id_2.to_prefix();

        let notes = vec![(
            Amount::from_sats(1),
            SpendableNote::consensus_decode_hex("a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd", &ModuleRegistry::default()).unwrap(),
        )]
        .into_iter()
        .collect::<TieredMulti<_>>();

        // Can decode inviteless notes
        let notes_no_invite = OOBNotes::new(federation_id_prefix_1, notes.clone());
        test_roundtrip_serialize_str(notes_no_invite, |oob_notes| {
            assert_eq!(oob_notes.notes(), &notes);
            assert_eq!(oob_notes.federation_id_prefix(), federation_id_prefix_1);
            assert_eq!(oob_notes.federation_invite(), None);
        });

        // Can decode notes with invite
        let invite = InviteCode::new(
            "wss://foo.bar".parse().unwrap(),
            PeerId::from(0),
            federation_id_1,
            None,
        );
        let notes_invite = OOBNotes::new_with_invite(notes.clone(), &invite);
        test_roundtrip_serialize_str(notes_invite, |oob_notes| {
            assert_eq!(oob_notes.notes(), &notes);
            assert_eq!(oob_notes.federation_id_prefix(), federation_id_prefix_1);
            assert_eq!(oob_notes.federation_invite(), Some(invite.clone()));
        });

        // Can decode notes without federation id prefix, so we can optionally remove it
        // in the future
        let notes_no_prefix = OOBNotes(vec![
            OOBNotesPart::Notes(notes.clone()),
            OOBNotesPart::Invite {
                peer_apis: vec![(PeerId::from(0), "wss://foo.bar".parse().unwrap())],
                federation_id: federation_id_1,
            },
        ]);
        test_roundtrip_serialize_str(notes_no_prefix, |oob_notes| {
            assert_eq!(oob_notes.notes(), &notes);
            assert_eq!(oob_notes.federation_id_prefix(), federation_id_prefix_1);
        });

        // Rejects notes with inconsistent federation id
        let notes_inconsistent = OOBNotes(vec![
            OOBNotesPart::Notes(notes),
            OOBNotesPart::Invite {
                peer_apis: vec![(PeerId::from(0), "wss://foo.bar".parse().unwrap())],
                federation_id: federation_id_1,
            },
            OOBNotesPart::FederationIdPrefix(federation_id_prefix_2),
        ]);
        let notes_inconsistent_str = notes_inconsistent.to_string();
        assert!(notes_inconsistent_str.parse::<OOBNotes>().is_err());
    }

    #[test]
    fn spendable_note_undecoded_sanity() {
        // TODO: add more hex dumps to the loop
        #[allow(clippy::single_element_loop)]
        for note_hex in [
            "a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd",
        ] {
            let note =
                SpendableNote::consensus_decode_hex(note_hex, &ModuleRegistry::default()).unwrap();
            let note_undecoded =
                SpendableNoteUndecoded::consensus_decode_hex(note_hex, &ModuleRegistry::default())
                    .unwrap()
                    .decode()
                    .unwrap();
            assert_eq!(note, note_undecoded,);
            assert_eq!(
                serde_json::to_string(&note).unwrap(),
                serde_json::to_string(&note_undecoded).unwrap(),
            );
        }
    }

    #[test]
    fn reissuance_meta_compatibility_02_03() {
        let dummy_outpoint = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };

        let old_meta_json = json!({
            "reissuance": {
                "out_point": dummy_outpoint
            }
        });

        let old_meta: MintOperationMetaVariant =
            serde_json::from_value(old_meta_json).expect("parsing old reissuance meta failed");
        assert_eq!(
            old_meta,
            MintOperationMetaVariant::Reissuance {
                legacy_out_point: Some(dummy_outpoint),
                txid: None,
                out_point_indices: vec![],
            }
        );

        let new_meta_json = serde_json::to_value(MintOperationMetaVariant::Reissuance {
            legacy_out_point: None,
            txid: Some(dummy_outpoint.txid),
            out_point_indices: vec![0],
        })
        .expect("serializing always works");
        assert_eq!(
            new_meta_json,
            json!({
                "reissuance": {
                    "txid": dummy_outpoint.txid,
                    "out_point_indices": [dummy_outpoint.out_idx],
                }
            })
        );
    }
}
