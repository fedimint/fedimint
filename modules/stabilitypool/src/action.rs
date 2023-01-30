use std::{collections::BTreeMap, fmt::Debug, ops::Deref, sync::Mutex};

use fedimint_api::{
    db::DatabaseTransaction,
    encoding::{Decodable, Encodable},
    BitcoinHash,
};
use secp256k1_zkp::Secp256k1;
use serde::{Deserialize, Serialize};

use crate::{
    db,
    epoch::{self, EpochState},
    ConsensusItemOutcome, PoolConsensusItem,
};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum ActionProposed {
    Seeker(SignedAction<SeekerAction>),
    Provider(SignedAction<ProviderBid>),
}

impl ActionProposed {
    pub fn account_id(&self) -> secp256k1_zkp::XOnlyPublicKey {
        match self {
            ActionProposed::Seeker(sa) => sa.account_id,
            ActionProposed::Provider(sa) => sa.account_id,
        }
    }

    pub fn epoch_id(&self) -> u64 {
        match self {
            ActionProposed::Seeker(sa) => sa.epoch_id,
            ActionProposed::Provider(sa) => sa.epoch_id,
        }
    }

    pub fn sequence(&self) -> u64 {
        match self {
            ActionProposed::Seeker(sa) => sa.sequence,
            ActionProposed::Provider(sa) => sa.sequence,
        }
    }

    pub fn verify_signature(&self) -> Result<(), secp256k1_zkp::UpstreamError> {
        match self {
            ActionProposed::Seeker(sa) => sa.verify_signature(),
            ActionProposed::Provider(sa) => sa.verify_signature(),
        }
    }
}

impl From<SignedAction<SeekerAction>> for ActionProposed {
    fn from(value: SignedAction<SeekerAction>) -> Self {
        Self::Seeker(value)
    }
}

impl From<SignedAction<ProviderBid>> for ActionProposed {
    fn from(value: SignedAction<ProviderBid>) -> Self {
        Self::Provider(value)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum ActionStaged {
    #[serde(rename = "seeker")]
    Seeker(Action<SeekerAction>),
    #[serde(rename = "provider")]
    Provider(Action<ProviderBid>),
}

impl From<ActionProposed> for ActionStaged {
    fn from(value: ActionProposed) -> Self {
        match value {
            ActionProposed::Seeker(signed) => ActionStaged::Seeker(signed.action),
            ActionProposed::Provider(signed) => ActionStaged::Provider(signed.action),
        }
    }
}

impl ActionStaged {
    pub fn epoch_id(&self) -> u64 {
        match self {
            ActionStaged::Seeker(a) => a.epoch_id,
            ActionStaged::Provider(a) => a.epoch_id,
        }
    }

    pub fn sequence(&self) -> u64 {
        match self {
            ActionStaged::Seeker(a) => a.sequence,
            ActionStaged::Provider(a) => a.sequence,
        }
    }

    pub fn account_id(&self) -> secp256k1_zkp::XOnlyPublicKey {
        match self {
            ActionStaged::Seeker(a) => a.account_id,
            ActionStaged::Provider(a) => a.account_id,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Action<T> {
    pub epoch_id: u64,
    pub sequence: u64,
    pub account_id: secp256k1_zkp::XOnlyPublicKey,
    pub body: T,
}

impl<T: Encodable> Encodable for Action<T> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.epoch_id.consensus_encode(writer)?;
        len += self.sequence.consensus_encode(writer)?;
        len += self.account_id.consensus_encode(writer)?;
        len += self.body.consensus_encode(writer)?;
        Ok(len)
    }
}

impl<T: Decodable> Decodable for Action<T> {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_api::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_api::encoding::DecodeError> {
        Ok(Self {
            epoch_id: u64::consensus_decode(r, modules)?,
            sequence: u64::consensus_decode(r, modules)?,
            account_id: secp256k1_zkp::XOnlyPublicKey::consensus_decode(r, modules)?,
            body: T::consensus_decode(r, modules)?,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignedAction<T> {
    pub action: Action<T>,
    pub signature: secp256k1_zkp::schnorr::Signature,
}

impl<T: Encodable> Encodable for SignedAction<T> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.action.consensus_encode(writer)?;
        len += self.signature.consensus_encode(writer)?;
        Ok(len)
    }
}

impl<T: Decodable> Decodable for SignedAction<T> {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_api::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_api::encoding::DecodeError> {
        Ok(Self {
            action: Action::<T>::consensus_decode(r, modules)?,
            signature: secp256k1_zkp::schnorr::Signature::consensus_decode(r, modules)?,
        })
    }
}

impl<T> Deref for SignedAction<T> {
    type Target = Action<T>;

    fn deref(&self) -> &Self::Target {
        &self.action
    }
}

impl<T: Encodable> SignedAction<T> {
    #[must_use]
    pub fn verify_signature(&self) -> Result<(), secp256k1_zkp::UpstreamError> {
        let b = self
            .action
            .consensus_encode_to_vec()
            .expect("encode should not pukking fail");
        let hash = bitcoin::hashes::sha256::Hash::hash(&b);
        let secp = Secp256k1::verification_only();
        secp.verify_schnorr(&self.signature, &hash.into(), &self.action.account_id)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum SeekerAction {
    Lock { amount: fedimint_api::Amount },
    Unlock { amount: fedimint_api::Amount },
}

// Continually reentering according to bid -> unlock by setting max amount 0.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ProviderBid {
    pub min_feerate: u64,
    pub max_amount: fedimint_api::Amount,
}

#[derive(Debug, Default)]
pub struct ActionProposedDb {
    actions: Mutex<BTreeMap<secp256k1_zkp::XOnlyPublicKey, ActionProposed>>,
}

impl ActionProposedDb {
    pub fn is_empty(&self) -> bool {
        self.actions.lock().unwrap().is_empty()
    }

    pub fn get(&self, account_id: secp256k1_zkp::XOnlyPublicKey) -> Option<ActionProposed> {
        self.actions.lock().unwrap().get(&account_id).cloned()
    }

    pub fn insert(&self, action: ActionProposed) {
        self.actions
            .lock()
            .unwrap()
            .insert(action.account_id(), action);
    }

    pub fn remove_expired(&self, next_epoch_id: u64) {
        let actions = &mut *self.actions.lock().unwrap();
        actions.retain(|_, a| a.epoch_id() >= next_epoch_id)
    }

    pub fn has_epoch_items(&self, epoch_id: u64) -> bool {
        // TODO: filter out items that have sequences lower than entry in consensus item db!
        let actions = &*self.actions.lock().unwrap();
        actions.values().any(|a| a.epoch_id() == epoch_id)
    }

    pub fn epoch_items(&self, epoch_id: u64) -> Vec<PoolConsensusItem> {
        // TODO: filter out items that have sequences lower than entry in consensus item db!
        let actions = &*self.actions.lock().unwrap();
        actions
            .values()
            .filter(move |&a| a.epoch_id() == epoch_id)
            .cloned()
            .map(Into::into)
            .collect()
    }

    pub fn pop_entry(&self, action: &ActionProposed) {
        let actions = &mut *self.actions.lock().unwrap();
        if matches!(actions.get(&action.account_id()), Some(db_action) if db_action == action) {
            actions.remove(&action.account_id());
        }
    }
}

/// Determine whether we have at least one action that is to be proposed.
pub async fn can_propose(
    dbtx: &mut DatabaseTransaction<'_>,
    proposal_db: &ActionProposedDb,
) -> bool {
    let epoch_state = epoch::EpochState::from_db(dbtx).await;

    epoch_state.is_settled() && proposal_db.has_epoch_items(epoch_state.staging_epoch_id())
}

/// Provide consensus proposals.
pub async fn consensus_proposal(
    dbtx: &mut DatabaseTransaction<'_>,
    proposal_db: &ActionProposedDb,
) -> Vec<PoolConsensusItem> {
    let state = epoch::EpochState::from_db(dbtx).await;
    proposal_db.epoch_items(state.staging_epoch_id())
}

pub async fn process_consensus_item(
    dbtx: &mut DatabaseTransaction<'_>,
    proposal_db: &ActionProposedDb,
    incoming_action: ActionProposed,
) -> ConsensusItemOutcome {
    if incoming_action.verify_signature().is_err() {
        proposal_db.pop_entry(&incoming_action);
        return ConsensusItemOutcome::Banned(format!("proposed user action has invalid signature"));
    }

    let epoch_state = EpochState::from_db(dbtx).await;
    if !epoch_state.is_settled() {
        return ConsensusItemOutcome::Ignored(format!(
            "epoch is in an unsettled state, cannot stage user action"
        ));
    }

    let next_epoch_id = epoch_state.staging_epoch_id();
    if next_epoch_id != incoming_action.epoch_id() {
        proposal_db.pop_entry(&incoming_action);
        return ConsensusItemOutcome::Ignored(format!(
            "proposed action's epoch ({}) is not the next epoch ({})",
            incoming_action.epoch_id(),
            next_epoch_id
        ));
    }

    let db_key = db::ActionStagedKey(incoming_action.account_id());

    // existing staged action
    let existing_action = db::get(dbtx, &db_key).await;

    let min_sequence = existing_action.map_or(0_u64, |a| {
        if a.epoch_id() < next_epoch_id {
            0_u64
        } else {
            a.sequence() + 1
        }
    });
    if incoming_action.sequence() < min_sequence {
        proposal_db.pop_entry(&incoming_action);
        return ConsensusItemOutcome::Ignored(format!(
            "action: invalid sequence ({}), min_sequence ({})",
            incoming_action.sequence(),
            min_sequence,
        ));
    }

    proposal_db.pop_entry(&incoming_action);
    db::set(dbtx, &db_key, &incoming_action.into()).await;
    return ConsensusItemOutcome::Applied;
}
