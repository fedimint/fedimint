// Backup and restore logic
pub(crate) mod backup;
/// Database keys used throughout the mint client module
mod client_db;
/// State machines for mint inputs
mod input;
/// State machines for out-of-band transmitted e-cash notes
mod oob;
/// State machines for mint outputs
mod output;

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context as _};
use async_stream::stream;
use backup::recovery::{MintRestoreStateMachine, MintRestoreStates};
use bitcoin_hashes::{sha256, sha256t, Hash, HashEngine as BitcoinHashEngine};
use client_db::DbKeyPrefix;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::oplog::{OperationLogEntry, UpdateStreamOrOutcome};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, Executor, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::api::{DynGlobalApi, GlobalFederationApi};
use fedimint_core::config::{FederationId, FederationIdPrefix};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{
    AutocommitError, DatabaseTransaction, DatabaseTransactionRef, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_pair_items, Amount, OutPoint, PeerId, Tiered,
    TieredMulti, TieredSummary, TransactionId,
};
use fedimint_derive_secret::{ChildId, DerivableSecret};
pub use fedimint_mint_common as common;
use fedimint_mint_common::config::MintClientConfig;
pub use fedimint_mint_common::*;
use futures::{pin_mut, StreamExt};
use secp256k1::{All, KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tbs::AggregatePublicKey;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::backup::recovery::MintRestoreInProgressState;
use crate::backup::EcashBackup;
use crate::client_db::{
    NextECashNoteIndexKey, NextECashNoteIndexKeyPrefix, NoteKey, NoteKeyPrefix,
};
use crate::input::{
    MintInputCommon, MintInputStateCreated, MintInputStateMachine, MintInputStates,
};
use crate::oob::{MintOOBStateMachine, MintOOBStates, MintOOBStatesCreated};
use crate::output::{
    MintOutputCommon, MintOutputStateMachine, MintOutputStates, MintOutputStatesCreated,
    NoteIssuanceRequest,
};

const MINT_E_CASH_TYPE_CHILD_ID: ChildId = ChildId(0);

const MINT_BACKUP_RESTORE_OPERATION_ID: OperationId = OperationId([0x01; 32]);

pub const LOG_TARGET: &str = "client::module::mint";

/// An encapsulation of [`FederationId`] and e-cash notes in the form of
/// [`TieredMulti<SpendableNote>`] for the purpose of spending e-cash
/// out-of-band. Also used for validating and reissuing such out-of-band notes.
///
/// ## Invariants
/// * Has to contain at least one `Notes` item
/// * Has to contain at least one `FederationIdPrefix` item
#[derive(Clone, Debug, Encodable)]
pub struct OOBNotes(Vec<OOBNotesData>);

#[derive(Clone, Debug, Decodable, Encodable)]
enum OOBNotesData {
    Notes(TieredMulti<SpendableNote>),
    FederationIdPrefix(FederationIdPrefix),
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
            OOBNotesData::FederationIdPrefix(federation_id_prefix),
            OOBNotesData::Notes(notes),
        ])
    }

    pub fn federation_id_prefix(&self) -> FederationIdPrefix {
        self.0
            .iter()
            .find_map(|data| match data {
                OOBNotesData::FederationIdPrefix(prefix) => Some(*prefix),
                _ => None,
            })
            .expect("Invariant violated: OOBNotes does not contain a FederationIdPrefix")
    }

    pub fn notes(&self) -> &TieredMulti<SpendableNote> {
        self.0
            .iter()
            .find_map(|data| match data {
                OOBNotesData::Notes(notes) => Some(notes),
                _ => None,
            })
            .expect("Invariant violated: OOBNotes does not contain any notes")
    }
}

impl Decodable for OOBNotes {
    fn consensus_decode<R: Read>(
        r: &mut R,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let inner = Vec::<OOBNotesData>::consensus_decode(r, &ModuleDecoderRegistry::default())?;

        // TODO: maybe write some macros for defining TLV structs?
        if !inner
            .iter()
            .any(|data| matches!(data, OOBNotesData::Notes(_)))
        {
            return Err(DecodeError::from_str(
                "No e-cash notes were found in OOBNotes data",
            ));
        }

        if !inner
            .iter()
            .any(|data| matches!(data, OOBNotesData::FederationIdPrefix(_)))
        {
            return Err(DecodeError::from_str(
                "No Federation ID provided in OOBNotes data",
            ));
        }

        Ok(OOBNotes(inner))
    }
}

impl FromStr for OOBNotes {
    type Err = anyhow::Error;

    /// Decode a set of out-of-band e-cash notes from a base64 string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::decode(s)?;
        let oob_notes: OOBNotes = Decodable::consensus_decode(
            &mut std::io::Cursor::new(bytes),
            &ModuleDecoderRegistry::default(),
        )?;

        ensure!(!oob_notes.notes().is_empty(), "OOBNotes cannot be empty");

        Ok(oob_notes)
    }
}

impl Display for OOBNotes {
    /// Base64 encode a set of e-cash notes for out-of-band spending.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut bytes = Vec::new();
        Encodable::consensus_encode(self, &mut bytes).expect("encodes correctly");
        f.write_str(&base64::encode(&bytes))
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
/// [`MintClientModule::spend_notes`].
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
    pub variant: MintOperationMetaVariants,
    pub amount: Amount,
    pub extra_meta: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MintOperationMetaVariants {
    Reissuance {
        out_point: OutPoint,
    },
    SpendOOB {
        requested_amount: Amount,
        oob_notes: OOBNotes,
    },
}

#[derive(Debug, Clone)]
pub struct MintClientInit;

#[apply(async_trait_maybe_send!)]
impl ModuleInit for MintClientInit {
    type Common = MintCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
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
                        SpendableNote,
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
        let (cancel_oob_payment_bc, _) = tokio::sync::broadcast::channel(16);
        Ok(MintClientModule {
            federation_id: *args.federation_id(),
            cfg: args.cfg().clone(),
            secret: args.module_root_secret().clone(),
            secp: Secp256k1::new(),
            notifier: args.notifier().clone(),
            cancel_oob_payment_bc,
            client_ctx: args.context(),
        })
    }
}

/// The `MintClientModule` is responsible for handling e-cash minting
/// operations. It interacts with the mint server to issue, reissue, and
/// validate e-cash notes.
///
/// # DerivableSecret
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
#[derive(Debug)]
pub struct MintClientModule {
    federation_id: FederationId,
    cfg: MintClientConfig,
    secret: DerivableSecret,
    secp: Secp256k1<All>,
    notifier: ModuleNotifier<DynGlobalClientContext, MintClientStateMachines>,
    cancel_oob_payment_bc: tokio::sync::broadcast::Sender<OperationId>,
    client_ctx: ClientContext<Self>,
}

// TODO: wrap in Arc
#[derive(Debug, Clone)]
pub struct MintClientContext {
    pub mint_decoder: Decoder,
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub secret: DerivableSecret,
    pub cancel_oob_payment_bc: tokio::sync::broadcast::Sender<OperationId>,
}

impl MintClientContext {
    fn subscribe_cancel_oob_payment(&self) -> tokio::sync::broadcast::Receiver<OperationId> {
        self.cancel_oob_payment_bc.subscribe()
    }
}

impl Context for MintClientContext {}

#[apply(async_trait_maybe_send!)]
impl ClientModule for MintClientModule {
    type Init = MintClientInit;
    type Common = MintModuleTypes;
    type ModuleStateMachineContext = MintClientContext;
    type States = MintClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        MintClientContext {
            mint_decoder: self.decoder(),
            tbs_pks: self.cfg.tbs_pks.clone(),
            peer_tbs_pks: self.cfg.peer_tbs_pks.clone(),
            secret: self.secret.clone(),
            cancel_oob_payment_bc: self.cancel_oob_payment_bc.clone(),
        }
    }

    fn input_amount(
        &self,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        let input = input.maybe_v0_ref()?;
        Some(TransactionItemAmount {
            amount: input.amount,
            fee: self.cfg.fee_consensus.note_spend_abs,
        })
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        let output = output.maybe_v0_ref()?;

        Some(TransactionItemAmount {
            amount: output.amount,
            fee: self.cfg.fee_consensus.note_issuance_abs,
        })
    }

    async fn handle_cli_command(
        &self,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        if args.is_empty() {
            return Err(anyhow::format_err!(
                "Expected to be called with at leas 1 arguments: <command> …"
            ));
        }

        let command = args[0].to_string_lossy();

        // FIXME: make instance-aware
        match command.as_ref() {
            "reissue" => {
                if args.len() != 2 {
                    return Err(anyhow::format_err!(
                        "`reissue` command expects 1 argument: <notes>"
                    ));
                }

                let oob_notes = args[1]
                    .to_string_lossy()
                    .parse::<OOBNotes>()
                    .map_err(|e| anyhow::format_err!("invalid notes format: {e}"))?;

                let amount = oob_notes.total_amount();

                let operation_id = self.reissue_external_notes(oob_notes, ()).await?;
                let mut updates = self
                    .subscribe_reissue_external_notes(operation_id)
                    .await
                    .unwrap()
                    .into_stream();

                while let Some(update) = updates.next().await {
                    if let ReissueExternalNotesState::Failed(e) = update {
                        bail!("Reissue failed: {e}");
                    }

                    info!("Update: {:?}", update);
                }

                Ok(serde_json::to_value(amount).unwrap())
            }
            command => Err(anyhow::format_err!(
                "Unknown command: {command}, supported commands: reissue"
            )),
        }
    }

    fn supports_backup(&self) -> bool {
        true
    }

    async fn backup(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
        executor: Executor<DynGlobalClientContext>,
        api: DynGlobalApi,
        module_instance_id: ModuleInstanceId,
    ) -> anyhow::Result<Vec<u8>> {
        let backup = self
            .prepare_plaintext_ecash_backup(dbtx, executor, api, module_instance_id)
            .await?;

        Ok(backup.consensus_encode_to_vec()?)
    }

    async fn restore(
        &self,
        // dbtx: &mut ModuleDatabaseTransaction<'_>,
        dbtx: &mut DatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
        executor: Executor<DynGlobalClientContext>,
        api: DynGlobalApi,
        snapshot: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        if !Self::get_all_spendable_notes(
            &mut dbtx.dbtx_ref_with_prefix_module_id(module_instance_id),
        )
        .await
        .is_empty()
        {
            warn!(
                target: LOG_TARGET,
                "Can not start recovery - existing spendable notes found"
            );
            bail!("Found existing spendable notes. Mint module recovery must be started on an empty state.")
        }

        if executor
            .get_active_states()
            .await
            .into_iter()
            .any(|s| s.0.module_instance_id() == module_instance_id)
        {
            warn!(
                target: LOG_TARGET,
                "Can not start recovery - existing state machines found"
            );
            bail!("Found existing active state machines. Mint module recovery must be started on an empty state.")
        }

        let snapshot = snapshot
            .map(|mut s| EcashBackup::consensus_decode(&mut s, &Default::default()))
            .transpose()?
            .unwrap_or(EcashBackup::new_empty());

        let current_session_count = api.session_count().await?;
        let state = MintRestoreInProgressState::from_backup(
            current_session_count,
            snapshot,
            30,
            self.cfg.tbs_pks.clone(),
            self.cfg.peer_tbs_pks.clone(),
            &self.secret,
        );

        debug!(target: LOG_TARGET, "Creating MintRestoreStateMachine");

        executor
            .add_state_machines_dbtx(
                dbtx,
                vec![DynState::from_typed(
                    module_instance_id,
                    MintClientStateMachines::Restore(MintRestoreStateMachine {
                        operation_id: MINT_BACKUP_RESTORE_OPERATION_ID,
                        state: MintRestoreStates::InProgress(state),
                    }),
                )],
            )
            .await?;

        Ok(())
    }

    async fn wipe(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
        _module_instance_id: ModuleInstanceId,
        _executor: Executor<DynGlobalClientContext>,
    ) -> anyhow::Result<()> {
        debug!(target: LOG_TARGET, "Wiping mint module state");
        Self::wipe_all_spendable_notes(dbtx).await;
        // TODO: wipe active states or all states?
        Ok(())
    }

    fn supports_being_primary(&self) -> bool {
        true
    }

    async fn create_sufficient_input(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<Vec<ClientInput<MintInput, MintClientStateMachines>>> {
        self.create_input(dbtx, operation_id, min_amount).await
    }

    async fn create_exact_output(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
        operation_id: OperationId,
        amount: Amount,
    ) -> Vec<ClientOutput<MintOutput, MintClientStateMachines>> {
        // FIXME: don't hardcode notes per denomination
        self.create_output(dbtx, operation_id, 2, amount).await
    }

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<Amount> {
        self.await_output_finalized(operation_id, out_point).await
    }

    async fn get_balance(&self, dbtx: &mut DatabaseTransactionRef<'_>) -> Amount {
        self.get_wallet_summary(dbtx).await.total_amount()
    }

    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()> {
        Box::pin(
            self.notifier
                .subscribe_all_operations()
                .await
                .filter_map(|state| async move {
                    match state {
                        MintClientStateMachines::Output(MintOutputStateMachine {
                            state: MintOutputStates::Succeeded(_),
                            ..
                        }) => Some(()),
                        MintClientStateMachines::Input(MintInputStateMachine {
                            state: MintInputStates::Created(_),
                            ..
                        }) => Some(()),
                        // We only trigger on created since refunds are already covered under the
                        // output state
                        MintClientStateMachines::OOB(MintOOBStateMachine {
                            state: MintOOBStates::Created(_),
                            ..
                        }) => Some(()),
                        // We don't want to scare users, so we only trigger on success instead of
                        // showing incremental progress. Ideally the balance isn't shown to them
                        // during recovery anyway.
                        MintClientStateMachines::Restore(MintRestoreStateMachine {
                            state: MintRestoreStates::Success(_),
                            ..
                        }) => Some(()),
                        _ => None,
                    }
                }),
        )
    }

    async fn leave(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
        module_instance_id: ModuleInstanceId,
        executor: Executor<DynGlobalClientContext>,
        _api: DynGlobalApi,
    ) -> anyhow::Result<()> {
        let balance = ClientModule::get_balance(self, dbtx).await;
        if Amount::from_sats(0) < balance {
            bail!("Outstanding balance: {balance}");
        }

        if executor
            .get_active_states()
            .await
            .into_iter()
            .any(|s| s.0.module_instance_id() == module_instance_id)
        {
            bail!("Pending operations")
        }
        Ok(())
    }
}

impl MintClientModule {
    /// Returns the number of held e-cash notes per denomination
    pub async fn get_wallet_summary(&self, dbtx: &mut DatabaseTransactionRef<'_>) -> TieredSummary {
        dbtx.find_by_prefix(&NoteKeyPrefix)
            .await
            .fold(
                TieredSummary::default(),
                |mut acc, (key, _note)| async move {
                    acc.inc(key.amount, 1);
                    acc
                },
            )
            .await
    }

    // TODO: put "notes per denomination" default into cfg
    /// Creates a mint output with exactly the given `amount`, issuing e-cash
    /// notes such that the client holds `notes_per_denomination` notes of each
    /// e-cash note denomination held.
    pub async fn create_output(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
        operation_id: OperationId,
        notes_per_denomination: u16,
        exact_amount: Amount,
    ) -> Vec<ClientOutput<MintOutput, MintClientStateMachines>> {
        assert!(
            exact_amount > Amount::ZERO,
            "zero-amount outputs are not supported"
        );

        let denominations = TieredSummary::represent_amount(
            exact_amount,
            &self.get_wallet_summary(dbtx).await,
            &self.cfg.tbs_pks,
            notes_per_denomination,
        );

        let mut outputs = Vec::new();

        for (amount, num) in denominations.iter() {
            for _ in 0..num {
                let (issuance_request, blind_nonce) = self.new_ecash_note(amount, dbtx).await;

                let state_generator = Arc::new(move |txid, out_idx| {
                    vec![MintClientStateMachines::Output(MintOutputStateMachine {
                        common: MintOutputCommon {
                            operation_id,
                            out_point: OutPoint { txid, out_idx },
                        },
                        state: MintOutputStates::Created(MintOutputStatesCreated {
                            amount,
                            issuance_request,
                        }),
                    })]
                });

                debug!(
                    %amount,
                    "Generated issuance request"
                );

                outputs.push(ClientOutput {
                    output: MintOutput::new_v0(amount, blind_nonce),
                    state_machines: state_generator,
                });
            }
        }

        outputs
    }

    /// Wait for the e-cash notes to be retrieved. If this is not possible
    /// because another terminal state was reached an error describing the
    /// failure is returned.
    pub async fn await_output_finalized(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<Amount> {
        let stream = self
            .notifier
            .subscribe(operation_id)
            .await
            .filter_map(|state| async move {
                let MintClientStateMachines::Output(state) = state else {
                    return None;
                };

                if state.common.out_point != out_point {
                    return None;
                }

                match state.state {
                    MintOutputStates::Succeeded(succeeded) => Some(Ok(succeeded.amount)),
                    MintOutputStates::Aborted(_) => Some(Err(anyhow!("Transaction was rejected"))),
                    MintOutputStates::Failed(failed) => Some(Err(anyhow!(
                        "Failed to finalize transaction: {}",
                        failed.error
                    ))),
                    _ => None,
                }
            });
        pin_mut!(stream);

        stream.next_or_pending().await
    }

    // FIXME: use lazy e-cash note loading implemented in #2183
    /// Creates a mint input of at least `min_amount`.
    pub async fn create_input(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<Vec<ClientInput<MintInput, MintClientStateMachines>>> {
        assert!(
            min_amount > Amount::ZERO,
            "zero-amount inputs are not supported"
        );

        let spendable_selected_notes =
            Self::select_notes(dbtx, &SelectNotesWithAtleastAmount, min_amount).await?;

        for (amount, note) in spendable_selected_notes.iter_items() {
            dbtx.remove_entry(&NoteKey {
                amount,
                nonce: note.nonce(),
            })
            .await;
        }

        self.create_input_from_notes(operation_id, spendable_selected_notes)
            .await
    }

    /// Create a mint input from external, potentially untrusted notes
    pub async fn create_input_from_notes(
        &self,
        operation_id: OperationId,
        notes: TieredMulti<SpendableNote>,
    ) -> anyhow::Result<Vec<ClientInput<MintInput, MintClientStateMachines>>> {
        let mut inputs = Vec::new();

        for (amount, spendable_note) in notes.into_iter() {
            let key = self
                .cfg
                .tbs_pks
                .get(amount)
                .ok_or(anyhow!("Invalid amount tier: {amount}"))?;

            let note = spendable_note.note();

            if !note.verify(*key) {
                bail!("Invalid note");
            }

            let sm_gen = Arc::new(move |txid, input_idx| {
                vec![MintClientStateMachines::Input(MintInputStateMachine {
                    common: MintInputCommon {
                        operation_id,
                        txid,
                        input_idx,
                    },
                    state: MintInputStates::Created(MintInputStateCreated {
                        amount,
                        spendable_note,
                    }),
                })]
            });

            inputs.push(ClientInput {
                input: MintInput::new_v0(amount, note),
                keys: vec![spendable_note.spend_key],
                state_machines: sm_gen,
            });
        }

        Ok(inputs)
    }

    async fn spend_notes_oob(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
        notes_selector: &impl NotesSelector<SpendableNote>,
        requested_amount: Amount,
        try_cancel_after: Duration,
    ) -> anyhow::Result<(
        OperationId,
        Vec<MintClientStateMachines>,
        TieredMulti<SpendableNote>,
    )> {
        ensure!(
            requested_amount > Amount::ZERO,
            "zero-amount out-of-band spends are not supported"
        );

        let spendable_selected_notes =
            Self::select_notes(dbtx, notes_selector, requested_amount).await?;

        let operation_id = spendable_notes_to_operation_id(&spendable_selected_notes);

        for (amount, note) in spendable_selected_notes.iter_items() {
            dbtx.remove_entry(&NoteKey {
                amount,
                nonce: note.nonce(),
            })
            .await;
        }

        let mut state_machines = Vec::new();

        for (amount, spendable_note) in spendable_selected_notes.clone() {
            state_machines.push(MintClientStateMachines::OOB(MintOOBStateMachine {
                operation_id,
                state: MintOOBStates::Created(MintOOBStatesCreated {
                    amount,
                    spendable_note,
                    timeout: fedimint_core::time::now() + try_cancel_after,
                }),
            }));
        }

        Ok((operation_id, state_machines, spendable_selected_notes))
    }

    pub async fn await_spend_oob_refund(&self, operation_id: OperationId) -> SpendOOBRefund {
        Box::pin(
            self.notifier
                .subscribe(operation_id)
                .await
                .filter_map(|state| async move {
                    let MintClientStateMachines::OOB(state) = state else {
                        return None;
                    };

                    match state.state {
                        MintOOBStates::TimeoutRefund(refund) => Some(SpendOOBRefund {
                            user_triggered: false,
                            transaction_id: refund.refund_txid,
                        }),
                        MintOOBStates::UserRefund(refund) => Some(SpendOOBRefund {
                            user_triggered: true,
                            transaction_id: refund.refund_txid,
                        }),
                        MintOOBStates::Created(_) => None,
                    }
                }),
        )
        .next_or_pending()
        .await
    }

    pub async fn await_restore_finished(&self) -> anyhow::Result<Amount> {
        let mut restore_stream = self
            .notifier
            .subscribe(MINT_BACKUP_RESTORE_OPERATION_ID)
            .await;
        while let Some(restore_step) = restore_stream.next().await {
            match restore_step {
                MintClientStateMachines::Restore(MintRestoreStateMachine {
                    state: MintRestoreStates::Success(amount),
                    ..
                }) => {
                    return Ok(amount);
                }
                MintClientStateMachines::Restore(MintRestoreStateMachine {
                    state: MintRestoreStates::Failed(error),
                    ..
                }) => {
                    return Err(anyhow!("Restore failed: {}", error.reason));
                }
                _ => {}
            }
        }

        Err(anyhow!("Restore stream closed without success or failure"))
    }

    /// Select notes with `requested_amount` using `notes_selector`.
    async fn select_notes(
        dbtx: &mut DatabaseTransactionRef<'_>,
        notes_selector: &impl NotesSelector<SpendableNote>,
        requested_amount: Amount,
    ) -> anyhow::Result<TieredMulti<SpendableNote>> {
        let note_stream = dbtx
            .find_by_prefix_sorted_descending(&NoteKeyPrefix)
            .await
            .map(|(key, note)| (key.amount, note));
        notes_selector
            .select_notes(note_stream, requested_amount)
            .await
    }

    async fn get_all_spendable_notes(
        dbtx: &mut DatabaseTransactionRef<'_>,
    ) -> TieredMulti<SpendableNote> {
        TieredMulti::from_iter(
            (dbtx
                .find_by_prefix(&NoteKeyPrefix)
                .await
                .map(|(key, note)| (key.amount, note))
                .collect::<Vec<_>>()
                .await)
                .into_iter(),
        )
    }

    async fn wipe_all_spendable_notes(dbtx: &mut DatabaseTransactionRef<'_>) {
        debug!(target: LOG_TARGET, "Wiping all spendable notes");
        dbtx.remove_by_prefix(&NoteKeyPrefix).await;
        assert!(Self::get_all_spendable_notes(dbtx).await.is_empty());
    }

    async fn get_next_note_index(
        &self,
        dbtx: &mut DatabaseTransactionRef<'_>,
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
        dbtx: &mut DatabaseTransactionRef<'_>,
    ) -> DerivableSecret {
        let new_idx = self.get_next_note_index(dbtx, amount).await;
        dbtx.insert_entry(&NextECashNoteIndexKey(amount), &new_idx.next().as_u64())
            .await;
        Self::new_note_secret_static(&self.secret, amount, new_idx)
    }

    pub async fn new_ecash_note(
        &self,
        amount: Amount,
        dbtx: &mut DatabaseTransactionRef<'_>,
    ) -> (NoteIssuanceRequest, BlindNonce) {
        let secret = self.new_note_secret(amount, dbtx).await;
        NoteIssuanceRequest::new(&self.secp, secret)
    }

    /// Try to reissue e-cash notes received from a third party to receive them
    /// in our wallet. The progress and outcome can be observed using
    /// [`MintClientModule::subscribe_reissue_external_notes`].
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
            bail!("Federation ID does not match");
        }

        let operation_id = OperationId(
            notes
                .consensus_hash::<sha256t::Hash<OOBReissueTag>>()
                .into_inner(),
        );

        let amount = notes.total_amount();
        let mint_input = self.create_input_from_notes(operation_id, notes).await?;

        let tx =
            TransactionBuilder::new().with_inputs(self.client_ctx.map_dyn(mint_input).collect());

        let extra_meta = serde_json::to_value(extra_meta)
            .expect("MintClientModule::reissue_external_notes extra_meta is serializable");
        let operation_meta_gen = move |txid, _| MintOperationMeta {
            variant: MintOperationMetaVariants::Reissuance {
                out_point: OutPoint { txid, out_idx: 0 },
            },
            amount,
            extra_meta: extra_meta.clone(),
        };

        let change = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                MintCommonInit::KIND.as_str(),
                operation_meta_gen,
                tx,
            )
            .await
            .context("We already reissued these notes")?
            .1;

        self.client_ctx
            .await_primary_module_outputs(operation_id, change)
            .await?;

        Ok(operation_id)
    }

    /// Subscribe to updates on the progress of a reissue operation started with
    /// [`MintClientModule::reissue_external_notes`].
    pub async fn subscribe_reissue_external_notes(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<ReissueExternalNotesState>> {
        let operation = self.mint_operation(operation_id).await?;
        let out_point = match operation.meta::<MintOperationMeta>().variant {
            MintOperationMetaVariants::Reissuance { out_point } => out_point,
            _ => bail!("Operation is not a reissuance"),
        };

        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, move || {
            stream! {
                yield ReissueExternalNotesState::Created;

                match client_ctx
                    .transaction_updates(operation_id)
                    .await
                    .await_tx_accepted(out_point.txid)
                    .await
                {
                    Ok(()) => {
                        yield ReissueExternalNotesState::Issuing;
                    }
                    Err(e) => {
                        yield ReissueExternalNotesState::Failed(format!("Transaction not accepted {e:?}"));
                    }
                }

                match client_ctx.self_ref().await_output_finalized(operation_id, out_point).await {
                    Ok(_) => {
                        yield ReissueExternalNotesState::Done;
                    },
                    Err(e) => {
                        yield ReissueExternalNotesState::Failed(e.to_string());
                    },
                }
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
    pub async fn spend_notes<M: Serialize + Send>(
        &self,
        min_amount: Amount,
        try_cancel_after: Duration,
        extra_meta: M,
    ) -> anyhow::Result<(OperationId, OOBNotes)> {
        self.spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            min_amount,
            try_cancel_after,
            extra_meta,
        )
        .await
    }

    /// Same as `spend_notes` but allows different to select notes to be used.
    pub async fn spend_notes_with_selector<M: Serialize + Send>(
        &self,
        notes_selector: &impl NotesSelector<SpendableNote>,
        requested_amount: Amount,
        try_cancel_after: Duration,
        extra_meta: M,
    ) -> anyhow::Result<(OperationId, OOBNotes)> {
        let mint_id = self.client_ctx.module_instance_id();
        let federation_id_prefix = self.federation_id.to_prefix();
        let extra_meta = serde_json::to_value(extra_meta)
            .expect("MintClientModule::spend_notes extra_meta is serializable");

        self.client_ctx
            .global_db()
            .autocommit(
                move |dbtx| {
                    let extra_meta = extra_meta.clone();
                    Box::pin(async move {
                        let (operation_id, states, notes) = self
                            .spend_notes_oob(
                                &mut dbtx.dbtx_ref_with_prefix_module_id(mint_id),
                                notes_selector,
                                requested_amount,
                                try_cancel_after,
                            )
                            .await?;
                        let oob_notes = OOBNotes::new(federation_id_prefix, notes);

                        let dyn_states = states.into_iter().map(|s| s.into_dyn(mint_id)).collect();

                        self.client_ctx.add_state_machines(dbtx, dyn_states).await?;
                        self.client_ctx
                            .add_operation_log_entry(
                                dbtx,
                                operation_id,
                                MintCommonInit::KIND.as_str(),
                                MintOperationMeta {
                                    variant: MintOperationMetaVariants::SpendOOB {
                                        requested_amount,
                                        oob_notes: oob_notes.clone(),
                                    },
                                    amount: oob_notes.total_amount(),
                                    extra_meta,
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

    /// Validate the given notes and return the total amount of the notes.
    /// Validation checks that:
    /// - the federation ID is correct
    /// - the note has a valid signature
    /// - the spend key is correct.
    pub async fn validate_notes(&self, oob_notes: OOBNotes) -> anyhow::Result<Amount> {
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

            let expected_nonce = Nonce(snote.spend_key.x_only_public_key().0);
            if note.nonce != expected_nonce {
                bail!("Note {idx} cannot be spent using the supplied spend key");
            }
        }

        Ok(notes.total_amount())
    }

    /// Try to cancel a spend operation started with
    /// [`MintClientModule::spend_notes`]. If the e-cash notes have already been
    /// spent this operation will fail which can be observed using
    /// [`MintClientModule::subscribe_spend_notes`].
    pub async fn try_cancel_spend_notes(&self, operation_id: OperationId) {
        // TODO: make robust by writing to the DB, this can fail
        let _ = self.cancel_oob_payment_bc.send(operation_id);
    }

    /// Subscribe to updates on the progress of a raw e-cash spend operation
    /// started with [`MintClientModule::spend_notes`].
    pub async fn subscribe_spend_notes(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<SpendOOBState>> {
        let operation = self.mint_operation(operation_id).await?;
        if !matches!(
            operation.meta::<MintOperationMeta>().variant,
            MintOperationMetaVariants::SpendOOB { .. }
        ) {
            bail!("Operation is not a out-of-band spend");
        };

        let client_ctx = self.client_ctx.clone();

        let global_db = self.client_ctx.global_db();
        Ok(
            operation.outcome_or_updates(&global_db, operation_id, move || {
                stream! {
                    yield SpendOOBState::Created;

                    let self_ref = client_ctx.self_ref();

                    let refund = self_ref
                        .await_spend_oob_refund(operation_id)
                        .await;

                    if refund.user_triggered {
                        yield SpendOOBState::UserCanceledProcessing;

                        match client_ctx
                            .transaction_updates(operation_id)
                            .await
                            .await_tx_accepted(refund.transaction_id)
                            .await
                        {
                            Ok(()) => {
                                yield SpendOOBState::UserCanceledSuccess;
                            },
                            Err(_) => {
                                yield SpendOOBState::UserCanceledFailure;
                            }
                        }
                    } else {
                        match client_ctx
                            .transaction_updates(operation_id)
                            .await
                            .await_tx_accepted(refund.transaction_id)
                            .await
                        {
                            Ok(()) => {
                                yield SpendOOBState::Refunded;
                            },
                            Err(_) => {
                                yield SpendOOBState::Success;
                            }
                        }
                    }
                }
            }),
        )
    }

    async fn mint_operation(&self, operation_id: OperationId) -> anyhow::Result<OperationLogEntry> {
        let operation = self
            .client_ctx
            .get_operation(operation_id)
            .await
            .ok_or(anyhow!("Operation not found"))?;

        if operation.operation_module_kind() != MintCommonInit::KIND.as_str() {
            bail!("Operation is not a mint operation");
        }

        Ok(operation)
    }
}

pub fn spendable_notes_to_operation_id(
    spendable_selected_notes: &TieredMulti<SpendableNote>,
) -> OperationId {
    OperationId(
        spendable_selected_notes
            .consensus_hash::<sha256t::Hash<OOBSpendTag>>()
            .into_inner(),
    )
}

pub struct SpendOOBRefund {
    pub user_triggered: bool,
    pub transaction_id: TransactionId,
}

#[apply(async_trait_maybe_send!)]
pub trait NotesSelector<Note>: Send + Sync {
    /// Select notes from stream for requested_amount.
    /// The stream must produce items in non- decreasing order of amount.
    async fn select_notes(
        &self,
        // FIXME: async trait doesn't like maybe_add_send
        #[cfg(not(target_family = "wasm"))] stream: impl futures::Stream<Item = (Amount, Note)> + Send,
        #[cfg(target_family = "wasm")] stream: impl futures::Stream<Item = (Amount, Note)>,
        requested_amount: Amount,
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
    ) -> anyhow::Result<TieredMulti<Note>> {
        Ok(select_notes_from_stream(stream, requested_amount).await?)
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
                previous_amount.map_or(true, |previous| previous >= note_amount),
                "notes are not sorted in descending order"
            );
            previous_amount = Some(note_amount);
            match note_amount.cmp(&pending_amount) {
                Ordering::Less => {
                    // keep adding notes until we have enough
                    pending_amount -= note_amount;
                    selected.push((note_amount, note))
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
                    return Ok(selected.into_iter().collect());
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
                // so now we have enough to cover the requested amount, return
                return Ok(selected.into_iter().collect());
            } else {
                let total_amount = requested_amount - pending_amount;
                // not enough notes, return
                return Err(InsufficientBalanceError {
                    requested_amount,
                    total_amount,
                });
            }
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

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum MintClientStateMachines {
    Output(MintOutputStateMachine),
    Input(MintInputStateMachine),
    OOB(MintOOBStateMachine),
    Restore(MintRestoreStateMachine),
}

impl IntoDynInstance for MintClientStateMachines {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for MintClientStateMachines {
    type ModuleContext = MintClientContext;
    type GlobalContext = DynGlobalClientContext;

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
            MintClientStateMachines::Restore(restore_state) => {
                sm_enum_variant_translation!(
                    restore_state.transitions(context, global_context),
                    MintClientStateMachines::Restore
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            MintClientStateMachines::Output(issuance_state) => issuance_state.operation_id(),
            MintClientStateMachines::Input(redemption_state) => redemption_state.operation_id(),
            MintClientStateMachines::OOB(oob_state) => oob_state.operation_id(),
            MintClientStateMachines::Restore(state) => state.operation_id(),
        }
    }
}

/// A [`Note`] with associated secret key that allows to proof ownership (spend
/// it)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SpendableNote {
    pub signature: tbs::Signature,
    pub spend_key: KeyPair,
}

impl SpendableNote {
    fn nonce(&self) -> Nonce {
        Nonce(self.spend_key.x_only_public_key().0)
    }

    fn note(&self) -> Note {
        Note {
            nonce: self.nonce(),
            signature: self.signature,
        }
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

    pub fn as_u64(self) -> u64 {
        self.0
    }

    // Private. If it turns out it is useful outside,
    // we can relax and convert to `From<u64>`
    // Actually used in tests RN, so cargo complains in non-test builds.
    #[allow(unused)]
    fn from_u64(v: u64) -> Self {
        Self(v)
    }

    pub fn advance(&mut self) {
        *self = self.next()
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

#[cfg(test)]
mod tests {
    use fedimint_core::config::FederationId;
    use fedimint_core::{Amount, Tiered, TieredMulti, TieredSummary};
    use itertools::Itertools;

    use crate::{select_notes_from_stream, OOBNotes};

    #[test_log::test(tokio::test)]
    async fn select_notes_avg_test() {
        let max_amount = Amount::from_sats(1000000);
        let tiers = Tiered::gen_denominations(2, max_amount);
        let tiered =
            TieredSummary::represent_amount::<()>(max_amount, &Default::default(), &tiers, 3);

        let mut total_notes = 0;
        for multiplier in 1..100 {
            let stream = reverse_sorted_note_stream(tiered.iter().collect());
            let select =
                select_notes_from_stream(stream, Amount::from_sats(multiplier * 1000)).await;
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
            select_notes_from_stream(f(), Amount::from_sats(7))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(1), 2), (Amount::from_sats(5), 1)])
        );
        assert_eq!(
            select_notes_from_stream(f(), Amount::from_sats(20))
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
            select_notes_from_stream(stream, Amount::from_sats(7))
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
            select_notes_from_stream(stream, Amount::from_sats(39))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(20), 2)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_error_if_amount_is_too_large() {
        let stream = reverse_sorted_note_stream(vec![(Amount::from_sats(10), 1)]);
        let error = select_notes_from_stream(stream, Amount::from_sats(100))
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
        let empty_oob_notes = OOBNotes::new(FederationId::dummy().to_prefix(), Default::default());
        let oob_notes_string = empty_oob_notes.to_string();

        let res = oob_notes_string.parse::<OOBNotes>();

        assert!(res.is_err(), "An empty OOB notes string should not parse");
    }
}
