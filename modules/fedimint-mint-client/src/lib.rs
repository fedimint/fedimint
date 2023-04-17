mod db;
mod issuance;
mod redemption;

use std::iter::once;

use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::{ClientModule, StateGenerator};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, OperationId, State, StateTransition};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{Database, ModuleDatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, Tiered, TieredSummary};
use fedimint_derive_secret::{ChildId, DerivableSecret};
pub use fedimint_mint_common as common;
use fedimint_mint_common::config::MintClientConfig;
pub use fedimint_mint_common::*;
use futures::StreamExt;
use secp256k1::{All, KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};
use tbs::AggregatePublicKey;
use tracing::debug;

use crate::db::{NextECashNoteIndexKey, NoteKeyPrefix};
use crate::issuance::{
    MintIssuanceCommon, MintIssuanceStateMachine, MintIssuanceStates, MintIssuanceStatesCreated,
    NoteIssuanceRequest, NoteIssuanceRequests,
};
use crate::redemption::MintRedemptionStateMachine;

const MINT_E_CASH_TYPE_CHILD_ID: ChildId = ChildId(0);

#[derive(Debug, Clone)]
pub struct MintClientGen;

impl ExtendsCommonModuleGen for MintClientGen {
    type Common = MintCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for MintClientGen {
    type Module = MintClientModule;
    type Config = MintClientConfig;

    async fn init(
        &self,
        _cfg: Self::Config,
        _db: Database,
        _instance_id: ModuleInstanceId,
    ) -> anyhow::Result<Self::Module> {
        unimplemented!()
        /*
        // FIXME: give module secret to module on init
        Ok(MintClientModule {
            instance_id,
            cfg,
            secret: ,
            secp: Secp256k1::new(),
        })
         */
    }
}

#[derive(Debug)]
pub struct MintClientModule {
    instance_id: ModuleInstanceId,
    cfg: MintClientConfig,
    secret: DerivableSecret,
    secp: Secp256k1<All>,
}

// TODO: wrap in Arc
#[derive(Debug, Clone)]
pub struct MintClientContext {
    /// Decoders for this module's types
    pub decoders: ModuleDecoderRegistry,
    pub mint_keys: Tiered<AggregatePublicKey>,
    pub instance_id: ModuleInstanceId,
}

impl Context for MintClientContext {}

impl ClientModule for MintClientModule {
    type Common = MintModuleTypes;
    type ModuleStateMachineContext = MintClientContext;
    type States = MintClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        let decoders = ModuleDecoderRegistry::new(once((self.instance_id, Self::decoder())));
        MintClientContext {
            decoders,
            mint_keys: self.cfg.tbs_pks.clone(),
            instance_id: self.instance_id,
        }
    }

    fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.0.total_amount(),
            // FIXME: prevent overflows
            fee: self.cfg.fee_consensus.note_spend_abs * (input.0.count_items() as u64),
        }
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.0.total_amount(),
            fee: self.cfg.fee_consensus.note_issuance_abs * (output.0.count_items() as u64),
        }
    }
}

impl MintClientModule {
    // TODO: put "notes per denomination" default into cfg
    pub async fn create_issuance(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        operation_id: OperationId,
        notes_per_denomination: u16,
        amount: Amount,
    ) -> (MintOutput, StateGenerator<MintClientStateMachines>) {
        let mut amount_requests: Vec<((Amount, NoteIssuanceRequest), (Amount, BlindNonce))> =
            Vec::new();
        let denominations = TieredSummary::represent_amount(
            amount,
            &self.available_notes_summary(dbtx).await,
            &self.cfg.tbs_pks,
            notes_per_denomination,
        );
        for (amt, num) in denominations.iter() {
            for _ in 0..num {
                let (request, blind_nonce) = self.new_ecash_note(amt, dbtx).await;
                amount_requests.push(((amt, request), (amt, blind_nonce)));
            }
        }
        let (note_issuance, sig_req): (NoteIssuanceRequests, MintOutput) =
            amount_requests.into_iter().unzip();

        let state_generator = Box::new(move |txid, out_idx| {
            vec![MintClientStateMachines::Issuance(
                MintIssuanceStateMachine {
                    common: MintIssuanceCommon {
                        operation_id,
                        out_point: OutPoint { txid, out_idx },
                    },
                    state: MintIssuanceStates::Created(MintIssuanceStatesCreated {
                        note_issuance: note_issuance.clone(),
                    }),
                },
            )]
        });

        debug!(
            %amount,
            notes = %sig_req.0.count_items(),
            tiers = ?sig_req.0.iter_tiers().collect::<Vec<_>>(),
            "Generated issuance request"
        );

        (sig_req, state_generator)
    }

    async fn available_notes_summary(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> TieredSummary {
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

    pub async fn get_next_note_index(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
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
    pub fn new_note_secret_static(
        secret: &DerivableSecret,
        amount: Amount,
        note_idx: NoteIndex,
    ) -> DerivableSecret {
        assert_eq!(secret.level(), 1);
        debug!(?secret, %amount, %note_idx, "Deriving new mint note");
        secret
            .child_key(MINT_E_CASH_TYPE_CHILD_ID) // TODO: cache
            .child_key(ChildId(amount.msats))
            .child_key(ChildId(note_idx.as_u64()))
            .child_key(ChildId(amount.msats))
    }

    async fn new_note_secret(
        &self,
        amount: Amount,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> DerivableSecret {
        let new_idx = self.get_next_note_index(dbtx, amount).await;
        dbtx.insert_entry(&NextECashNoteIndexKey(amount), &new_idx.next().as_u64())
            .await;
        Self::new_note_secret_static(&self.secret, amount, new_idx)
    }

    pub async fn new_ecash_note(
        &self,
        amount: Amount,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> (NoteIssuanceRequest, BlindNonce) {
        let secret = self.new_note_secret(amount, dbtx).await;
        NoteIssuanceRequest::new(&self.secp, secret)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum MintClientStateMachines {
    Issuance(MintIssuanceStateMachine),
    Redemption(MintRedemptionStateMachine),
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
            MintClientStateMachines::Issuance(issuance_state) => {
                sm_enum_variant_translation!(
                    issuance_state.transitions(context, global_context),
                    MintClientStateMachines::Issuance
                )
            }
            MintClientStateMachines::Redemption(redemption_state) => {
                sm_enum_variant_translation!(
                    redemption_state.transitions(context, global_context),
                    MintClientStateMachines::Redemption
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            MintClientStateMachines::Issuance(issuance_state) => issuance_state.operation_id(),
            MintClientStateMachines::Redemption(redemption_state) => {
                redemption_state.operation_id()
            }
        }
    }
}

/// A [`Note`] with associated secret key that allows to proof ownership (spend
/// it)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SpendableNote {
    pub note: Note,
    pub spend_key: KeyPair,
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
