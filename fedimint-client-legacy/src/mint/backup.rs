//! Backup and recovery of ecash notes
//!
//! Ecash backup is implemented by periodically taking a snapshot,
//! self-encrypting it and uploading it to federation.
//!
//! Recovery is done by deriving deterministic ecash nonces and checking,
//! them with federation. A successfully recovered snapshot can be used
//! to avoid having to scan the whole history.

use std::cmp::{max, Reverse};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;

use anyhow::Result;
use fedimint_core::api::{FederationError, GlobalFederationApi};
use fedimint_core::cancellable::{Cancellable, Cancelled};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_MINT;
use fedimint_core::epoch::{ConsensusItem, SignedEpochOutcome};
use fedimint_core::task::TaskGroup;
use fedimint_core::{NumPeers, PeerId};
use fedimint_logging::LOG_ECASH_RECOVERY;
use fedimint_mint_client::{BackupRequest, SignedBackupRequest};
use tbs::{combine_valid_shares, verify_blind_share, BlindedMessage, PublicKeyShare};
use tracing::{error, info};

use super::db::NextECashNoteIndexKeyPrefix;
use super::*;
use crate::api::MintFederationApi;
use crate::modules::mint::{MintConsensusItem, MintInput, MintOutput};

impl MintClient {
    /// Prepare an encrypted backup and send it to federation for storing
    pub async fn back_up_ecash_to_federation(&self, metadata: Metadata) -> Result<()> {
        let backup = self.prepare_ecash_backup(metadata).await?;

        self.upload_ecash_backup(backup).await?;

        Ok(())
    }

    pub async fn restore_ecash_from_federation(
        &self,
        gap_limit: usize,
        task_group: &mut TaskGroup,
    ) -> Result<Cancellable<Metadata>> {
        let backup = if let Some(backup) = self.download_ecash_backup_from_federation().await? {
            backup
        } else {
            warn!(
                target: LOG_ECASH_RECOVERY,
                id=%self.get_backup_id(),
                "Could not find any valid existing backup. Will attempt to restore from scratch. This might take a long time."
            );
            PlaintextEcashBackup::new_empty()
        };

        let mut task_group = task_group.make_subgroup().await;
        let metadata = backup.metadata.clone();

        // TODO: If the client attempts any operations between while the recovery is
        // working, the recovery code will most probably miss them, which might
        // lead to incorrect state. We should probably lock everything in some
        // way during recovery for corectness.
        let snapshot = match self
            .restore_current_state_from_backup(&mut task_group, backup, gap_limit)
            .await?
        {
            Ok(o) => o,
            Err(Cancelled) => return Ok(Err(Cancelled)),
        };

        task_group.join_all(None).await?;

        info!("Writing out the recovered state to the database");

        let mut dbtx = self.start_dbtx().await;

        Self::wipe_notes_static(&mut dbtx).await?;

        for (amount, note) in snapshot.spendable_notes {
            let key = NoteKey {
                amount,
                nonce: note.note.0,
            };
            dbtx.insert_entry(&key, &note).await;
        }

        for (txid, issuance_requests) in snapshot.unconfirmed_notes {
            dbtx.insert_entry(&OutputFinalizationKey(txid), &issuance_requests)
                .await;
        }

        for (amount, note_idx) in snapshot.next_note_idx.iter() {
            dbtx.insert_entry(&NextECashNoteIndexKey(amount), &note_idx.as_u64())
                .await;
        }
        dbtx.commit_tx_result().await?;

        Ok(Ok(metadata))
    }

    pub async fn wipe_notes(&self) -> Result<()> {
        let mut dbtx = self.start_dbtx().await;
        Self::wipe_notes_static(&mut dbtx).await?;
        dbtx.commit_tx_result().await?;
        Ok(())
    }

    /// Delete all the note-related data from the database
    ///
    /// Useful for cleaning previous data before restoring data recovered from
    /// backup.
    async fn wipe_notes_static(dbtx: &mut DatabaseTransaction<'_>) -> Result<()> {
        dbtx.remove_by_prefix(&NoteKeyPrefix).await;
        dbtx.remove_by_prefix(&OutputFinalizationKeyPrefix).await;
        dbtx.remove_by_prefix(&NextECashNoteIndexKeyPrefix).await;
        Ok(())
    }

    pub async fn download_ecash_backup_from_federation(
        &self,
    ) -> Result<Option<PlaintextEcashBackup>> {
        let mut responses: Vec<_> = self
            .context
            .api
            .download_ecash_backup(&self.get_backup_id())
            .await?
            .into_iter()
            .filter_map(|backup| {
                match EcashBackup(backup.data)
                    .decrypt_with(&self.get_derived_backup_encryption_key())
                {
                    Ok(valid) => Some(valid),
                    Err(e) => {
                        warn!(
                            target: LOG_ECASH_RECOVERY,
                            "Invalid backup returned by one of the peers: {e}"
                        );
                        None
                    }
                }
            })
            .collect();

        debug!(
            target: LOG_ECASH_RECOVERY,
            "Received {} valid responses",
            responses.len()
        );
        // Use the newest (highest epoch)
        responses.sort_by_key(|backup| Reverse(backup.epoch_count));

        Ok(responses.into_iter().next())
    }

    fn get_backup_id(&self) -> bitcoin::XOnlyPublicKey {
        self.get_derived_backup_signing_key().x_only_public_key().0
    }

    /// Static version of [`Self::get_derived_backup_encryption_key`] for
    /// testing without creating whole `MintClient`
    fn get_derived_backup_encryption_key_static(
        secret: &DerivableSecret,
    ) -> fedimint_aead::LessSafeKey {
        fedimint_aead::LessSafeKey::new(
            secret
                .child_key(MINT_E_CASH_BACKUP_SNAPSHOT_TYPE_CHILD_ID)
                .to_chacha20_poly1305_key(),
        )
    }

    /// Static version of [`Self::get_derived_backup_signing_key`] for testing
    /// without creating whole `MintClient`
    fn get_derived_backup_signing_key_static(secret: &DerivableSecret) -> secp256k1_zkp::KeyPair {
        // TODO: Do we need that one derivation level? This key is already derived for
        // the mint itself, and internally another kdf will be done with key type tag.
        secret
            .child_key(MINT_E_CASH_BACKUP_SNAPSHOT_TYPE_CHILD_ID)
            .to_secp_key(&Secp256k1::<secp256k1::SignOnly>::gen_new())
    }

    fn get_derived_backup_encryption_key(&self) -> fedimint_aead::LessSafeKey {
        Self::get_derived_backup_encryption_key_static(&self.secret)
    }

    fn get_derived_backup_signing_key(&self) -> secp256k1::KeyPair {
        Self::get_derived_backup_signing_key_static(&self.secret)
    }

    async fn prepare_plaintext_ecash_backup(
        &self,
        metadata: Metadata,
    ) -> Result<PlaintextEcashBackup> {
        // fetch consensus height first - so we dont miss anything when scanning
        let epoch_count = self.context.api.fetch_epoch_count().await?;

        let mut dbtx = self.start_dbtx().await;
        let notes = self.get_available_notes(&mut dbtx).await;

        let pending_notes: Vec<_> = dbtx
            .find_by_prefix(&OutputFinalizationKeyPrefix)
            .await
            .collect()
            .await;

        let mut idxes = vec![];
        for &amount in self.config.tbs_pks.tiers() {
            idxes.push((amount, self.get_next_note_index(&mut dbtx, amount).await));
        }
        let next_note_idx = Tiered::from_iter(idxes);

        Ok(PlaintextEcashBackup {
            notes,
            pending_notes,
            next_note_idx,
            epoch_count,
            metadata,
        })
    }

    async fn prepare_ecash_backup(&self, metadata: Metadata) -> Result<EcashBackup> {
        let plaintext = self.prepare_plaintext_ecash_backup(metadata).await?;
        plaintext.encrypt_to(&self.get_derived_backup_encryption_key())
    }

    async fn upload_ecash_backup(&self, backup: EcashBackup) -> Result<()> {
        let backup_request = backup.into_backup_request(&self.get_derived_backup_signing_key())?;
        self.context
            .api
            .upload_ecash_backup(&backup_request)
            .await?;
        Ok(())
    }

    /// Fetch epochs in a given range and send them over `sender`
    ///
    /// Since WASM's `spawn` does not support join handles, we indicate
    /// errors via `sender` itself.
    ///
    /// TODO: could be internal to recovery_loop?
    fn fetch_epochs_stream(
        &self,
        epoch_range: Range<u64>,
    ) -> impl futures::Stream<
        Item = (
            u64,
            std::result::Result<SignedEpochOutcome, FederationError>,
        ),
    > + '_ {
        futures::stream::iter(epoch_range)
            .map(move |epoch| {
                Box::pin(async move {
                    info!(epoch, "Fetching epoch");
                    (
                        epoch,
                        self.context
                            .api
                            .fetch_epoch_history(epoch, self.epoch_pk, &self.context.decoders)
                            .await,
                    )
                })
            })
            .buffered(8)
    }

    pub async fn restore_current_state_from_backup(
        &self,
        task_group: &mut TaskGroup,
        backup: PlaintextEcashBackup,
        gap_limit: usize,
    ) -> Result<Cancellable<EcashRecoveryFinalState>> {
        let current_epoch_count = match self.context.api.fetch_epoch_count().await {
            Ok(v) => v,
            Err(e) => {
                return Err(e.into());
            }
        };
        // TODO: This -1 is probably not necessary, as it should be enough to start from
        // the exact epoch the snapshot was taken, but it is harmless to start from any
        // epoch in the past, and starting a bit earlier makes it more robust in face of
        // some inconsistency that we've missed.
        let start_epoch = backup.epoch_count.saturating_sub(1);
        let epoch_range = start_epoch..current_epoch_count;

        info!(
            target: LOG_ECASH_RECOVERY,
            start_epoch, current_epoch_count, "Recovering from snapshot"
        );

        let mut tracker = EcashRecoveryTracker::from_backup(
            backup,
            self.secret.clone(),
            gap_limit,
            self.config.tbs_pks.clone(),
            self.config.peer_tbs_pks.clone(),
        );
        let task_handle = task_group.make_handle();

        let mut epoch_stream = self.fetch_epochs_stream(epoch_range);
        while let Some((epoch, epoch_res)) = epoch_stream.next().await {
            if task_handle.is_shutting_down() {
                return Ok(Err(Cancelled));
            }
            // if `recv` returned `None` that means fetch_epoch finished prematurely,
            // without sending an `Err` which is supposed to mean `is_shutting_down() ==
            // true`
            info!(target: LOG_ECASH_RECOVERY, epoch, "Awaiting epoch");
            let epoch_history = epoch_res?;
            assert_eq!(epoch_history.outcome.epoch, epoch);

            info!(target: LOG_ECASH_RECOVERY, epoch, "Processing epoch");
            let mut processed_txs = Default::default();
            for (peer_id, items) in &epoch_history.outcome.items {
                for item in items {
                    tracker.handle_consensus_item(
                        *peer_id,
                        item,
                        &mut processed_txs,
                        &epoch_history.outcome.rejected_txs,
                    );
                }
            }
        }

        Ok(Ok(tracker.finalize()))
    }
}

/// Backup metadata
///
/// A backup can have a blob of extra data encoded in it.
/// We provide methods to use json encoding, but clients
/// are free to use their own encoding.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable, Clone)]
pub struct Metadata(Vec<u8>);

impl Metadata {
    /// Create empty metadata
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn from_raw(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_raw(self) -> Vec<u8> {
        self.0
    }

    /// Is metadata empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Create metadata as json from typed `val`
    pub fn from_json_serialized<T: Serialize>(val: T) -> Self {
        Self(serde_json::to_vec(&val).expect("serializing to vec can't fail"))
    }

    /// Attempt to deserialize metadata as typed json
    pub fn to_json_deserialized<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.0)?)
    }

    /// Attempt to deserialize metadata as untyped json (`serde_json::Value`)
    pub fn to_json_value<T: serde::de::DeserializeOwned>(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.0)?)
    }
}

/// Snapshot of a ecash state (notes)
///
/// Used to speed up and improve privacy of ecash recovery,
/// by avoiding scanning the whole history.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct PlaintextEcashBackup {
    notes: TieredMulti<SpendableNote>,
    pending_notes: Vec<(OutputFinalizationKey, NoteIssuanceRequests)>,
    epoch_count: u64,
    next_note_idx: Tiered<NoteIndex>,
    metadata: Metadata,
}

impl PlaintextEcashBackup {
    /// An empty backup with, like a one created by a newly created client.
    fn new_empty() -> Self {
        Self {
            notes: TieredMulti::default(),
            pending_notes: vec![],
            epoch_count: 0,
            next_note_idx: Tiered::default(),
            metadata: Metadata::empty(),
        }
    }

    /// Align an ecoded message size up for better privacy
    fn get_alignment_size(len: usize) -> usize {
        // TODO: should we align to power of 2 instead?
        let padding_alignment = 16 * 1024;
        ((len.saturating_sub(1) / padding_alignment) + 1) * padding_alignment
    }

    /// Encode `self` to a padded (but still plaintext) message
    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.consensus_encode_to_vec()?;

        let padding_size = Self::get_alignment_size(bytes.len()) - bytes.len();

        bytes.extend(std::iter::repeat(0u8).take(padding_size));

        Ok(bytes)
    }

    /// Decode from a plaintexet (possibly aligned) message
    fn decode(msg: &[u8]) -> Result<Self> {
        Ok(Decodable::consensus_decode(
            &mut &msg[..],
            &ModuleDecoderRegistry::default(),
        )?)
    }

    /// Encrypt with a key and turn into [`EcashBackup`]
    pub fn encrypt_to(&self, key: &fedimint_aead::LessSafeKey) -> Result<EcashBackup> {
        let encoded = self.encode()?;

        let encrypted = fedimint_aead::encrypt(encoded, key)?;
        Ok(EcashBackup(encrypted))
    }
}

/// Encrypted version of [`PlaintextEcashBackup`].
pub struct EcashBackup(Vec<u8>);

impl EcashBackup {
    pub fn decrypt_with(
        mut self,
        key: &fedimint_aead::LessSafeKey,
    ) -> Result<PlaintextEcashBackup> {
        let decrypted = fedimint_aead::decrypt(&mut self.0, key)?;
        PlaintextEcashBackup::decode(decrypted)
    }

    pub fn into_backup_request(self, keypair: &KeyPair) -> Result<SignedBackupRequest> {
        let request = BackupRequest {
            id: keypair.x_only_public_key().0,
            timestamp: fedimint_core::time::now(),
            payload: self.0,
        };

        request.sign(keypair)
    }
}

#[derive(Debug)]
pub struct EcashRecoveryFinalState {
    /// Nonces that we track that are currently spendable.
    spendable_notes: Vec<(Amount, SpendableNote)>,

    /// Unsigned notes
    unconfirmed_notes: Vec<(OutPoint, NoteIssuanceRequests)>,

    /// Note index to derive next note in a given amount tier
    next_note_idx: Tiered<NoteIndex>,
}

/// The state machine used for fast-forwarding backup from point when it was
/// taken to the present time by following epoch history items from the time the
/// snapshot was taken.
///
/// The caller is responsible for creating it, and then feeding it in order all
/// valid consensus items from the epoch history between time taken (or even
/// somewhat before it) and present time.
#[derive(Debug)]
struct EcashRecoveryTracker {
    /// Nonces that we track that are currently spendable.
    spendable_note_by_nonce: HashMap<Nonce, (Amount, SpendableNote)>,

    /// Outputs (by `OutPoint`) we track federation member confirmations for
    /// blind nonces.
    ///
    /// Once we get enough confirmation (valid shares), these become new
    /// spendable notes.
    ///
    /// Note that `NoteIssuanceRequest` is optional, as sometimes we might need
    /// to handle a tx where only some of the blind nonces were in the pool.
    /// A `None` means that this blind nonce/message is there only for
    /// validation purposes, and will actually not create a
    /// `spendable_note_by_nonce`
    #[allow(clippy::type_complexity)]
    pending_outputs: HashMap<
        OutPoint,
        (
            TieredMulti<(BlindedMessage, Option<NoteIssuanceRequest>)>,
            HashMap<PeerId, Vec<tbs::BlindedSignatureShare>>,
        ),
    >,

    /// Next nonces that we expect might soon get used.
    /// Once we see them, we move the tracking to `pending_outputs`
    ///
    /// Note: since looking up nonces is going to be the most common operation
    /// the pool is kept shared (so only one lookup is enough), and
    /// replenishment is done each time a note is consumed.
    pending_nonces: HashMap<BlindedMessage, (NoteIssuanceRequest, NoteIndex, Amount)>,

    /// Tail of `pending`. `pending_notes` is filled by generating note with
    /// this index and incrementing it.
    next_pending_note_idx: Tiered<NoteIndex>,

    /// `LastECashNoteIndex` but tracked in flight. Basically max index of any
    /// note that got a partial sig from the federation (initialled from the
    /// backup value). TODO: One could imagine a case where the note was
    /// issued but not get any partial sigs yet. Very unlikely in real life
    /// scenario, but worth considering.
    last_mined_nonce_idx: Tiered<NoteIndex>,

    /// Threshold
    threshold: usize,

    /// The **mint** (not root) derived secret used to derive notes
    secret: DerivableSecret,

    /// Public key shares for each peer
    ///
    /// Used to validate contributed consensus items
    pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,

    /// Aggregate public key for each amount tier
    tbs_pks: Tiered<AggregatePublicKey>,

    /// The number of nonces we look-ahead when looking for mints (per each
    /// amount).
    gap_limit: usize,
}

impl EcashRecoveryTracker {
    pub fn from_backup(
        backup: PlaintextEcashBackup,
        mint_secret: DerivableSecret,
        gap_limit: usize,
        tbs_pks: Tiered<AggregatePublicKey>,
        pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    ) -> Self {
        assert_eq!(mint_secret.level(), 1);
        let amount_tiers: Vec<_> = tbs_pks.tiers().copied().collect();
        let mut s = Self {
            spendable_note_by_nonce: backup
                .notes
                .into_iter()
                .map(|(amount, note)| (note.note.0, (amount, note)))
                .collect(),
            pending_outputs: backup
                .pending_notes
                .into_iter()
                .map(|(finalization_key, issuance_requests)| {
                    (
                        finalization_key.0,
                        (
                            issuance_requests
                                .notes
                                .iter_items()
                                .map(|(amount, iss_req)| {
                                    (amount, (iss_req.recover_blind_nonce().0, Some(*iss_req)))
                                })
                                .collect(),
                            HashMap::default(),
                        ),
                    )
                })
                .collect(),
            pending_nonces: HashMap::default(),
            next_pending_note_idx: backup.next_note_idx.clone(),
            last_mined_nonce_idx: backup.next_note_idx,
            secret: mint_secret,
            threshold: pub_key_shares.threshold(),
            gap_limit,
            tbs_pks,
            pub_key_shares,
        };

        for amount in amount_tiers {
            s.fill_initial_pending_nonces(amount);
        }

        s
    }

    /// Fill each tier pool to the gap limit
    fn fill_initial_pending_nonces(&mut self, amount: Amount) {
        info!(%amount, count=self.gap_limit, "Generating initial set of nonces for amount tier");
        for _ in 0..self.gap_limit {
            self.add_next_pending_nonce_in_pending_pool(amount);
        }
    }

    /// Add next nonce from `amount` tier to the `next_pending_note_idx`
    fn add_next_pending_nonce_in_pending_pool(&mut self, amount: Amount) {
        let note_idx_ref = self.next_pending_note_idx.get_mut_or_default(amount);

        let (note_issuance_request, blind_nonce) = NoteIssuanceRequest::new(
            secp256k1::SECP256K1,
            MintClient::new_note_secret_static(&self.secret, amount, *note_idx_ref),
        );
        assert!(self
            .pending_nonces
            .insert(
                blind_nonce.0,
                (note_issuance_request, *note_idx_ref, amount)
            )
            .is_none());

        note_idx_ref.advance();
    }

    pub fn handle_input(&mut self, input: &MintInput) {
        // We attempt to delete any nonce we see as spent, simple
        for (_amt, note) in input.0.iter_items() {
            self.spendable_note_by_nonce.remove(&note.0);
        }
    }

    pub fn handle_output(&mut self, out_point: OutPoint, output: &MintOutput) {
        // There is nothing preventing other users from creating valid transactions
        // mining notes to our own blind nonce, possibly even racing with us.
        // Including amount in blind nonce derivation helps us avoid accidentally using
        // a nonce mined for as smaller amount, but it doesn't eliminate completely
        // the possibility that we might use a note mined in a different transaction,
        // that our original one.
        // While it is harmless to us, as such duplicated blind nonces are effective as
        // good the as the original ones (same amount), it breaks the assumption
        // that all our blind nonces in an our output need to be in the pending
        // pool. It forces us to be greedy no matter what and take what we can,
        // and just report anything suspicious.
        //
        // found - all nonces that we found in the pool with the correct amount
        // missing - all the nonces we have not found in the pool, either because they
        // are not ours           or were consumed by a previous transaction
        // using this nonce, or possibly gap           buffer was too small
        // wrong - nonces that were ours but were mined to a wrong
        let (found, missing, wrong) = output.0.iter_items().fold(
            (vec![], vec![], vec![]),
            |(mut found, mut missing, mut wrong), (amount_from_output, nonce)| {
                match self.pending_nonces.get(&nonce.0).cloned() {
                    Some((issuance_request, note_idx, pending_amount)) => {
                        // the moment we see our blind nonce in the epoch history, correctly or
                        // incorrectly used, we know that we must have used
                        // already
                        self.observe_nonce_idx_being_used(pending_amount, note_idx);

                        if pending_amount == amount_from_output {
                            found.push((amount_from_output, (nonce.0, Some(issuance_request))));
                            (found, missing, wrong)
                        } else {
                            // put it back, incorrect amount
                            self.pending_nonces
                                .insert(nonce.0, (issuance_request, note_idx, pending_amount));
                            // report problem
                            wrong.push((
                                out_point,
                                nonce.0,
                                pending_amount,
                                amount_from_output,
                                note_idx,
                            ));
                            (found, missing, wrong)
                        }
                    }
                    None => {
                        missing.push((amount_from_output, (nonce.0, None)));
                        (found, missing, wrong)
                    }
                }
            },
        );

        for wrong in &wrong {
            warn!(output = ?out_point,
                 blind_nonce = ?wrong.1,
                 expected_amount = %wrong.2,
                 found_amount = %wrong.3,
                 "Transaction output contains blind nonce that looks like ours but is of the wrong amount. Ignoring.");
            // Any blind nonce mined with a wrong amount means that this
            // transaction can't be ours
        }

        if !wrong.is_empty() {
            return;
        }

        if found.is_empty() {
            // If we found nothing, this is not our output
            return;
        }

        for &(_amount, (nonce, _)) in &missing {
            warn!(output = ?out_point,
                 nonce = ?nonce,
                 "Missing nonce in pending pool for a transaction with other valid nonces that belong to us. This indicate an issue.");
        }

        // ok, now that we know we track this output as ours and use the nonces we've
        // found delete them from the pool and replace them
        for &(_amount, (nonce, _)) in &found {
            assert!(self.pending_nonces.remove(&nonce).is_some());
        }

        self.pending_outputs.insert(
            out_point,
            (
                TieredMulti::from_iter(found.into_iter().chain(missing.into_iter())),
                HashMap::new(),
            ),
        );
    }

    /// React to a valid pending nonce being tracked being used in the epoch
    /// history
    ///
    /// (Possibly) increment the `self.last_mined_nonce_idx`, then replenish the
    /// pending pool to always maintain at least `gap_limit` of pending
    /// nonces in each amount tier.
    fn observe_nonce_idx_being_used(&mut self, amount: Amount, note_idx: NoteIndex) {
        *self.last_mined_nonce_idx.entry(amount).or_default() = max(
            self.last_mined_nonce_idx
                .get(amount)
                .copied()
                .unwrap_or_default(),
            note_idx,
        );

        while self.next_pending_note_idx.get_mut_or_default(amount).0
            < self.gap_limit as u64
                + self
                    .last_mined_nonce_idx
                    .get(amount)
                    .expect("must be there already")
                    .0
        {
            self.add_next_pending_nonce_in_pending_pool(amount);
        }
    }

    pub fn handle_output_confirmation(&mut self, peer_id: PeerId, sigs: &MintConsensusItem) {
        let enough_shares = if let Some((output_data, peer_shares)) =
            self.pending_outputs.get_mut(&sigs.out_point)
        {
            if !sigs.signatures.0.structural_eq(output_data) {
                warn!(
                    peer = %peer_id,
                    "Peer proposed a sig share of wrong structure (different than out_point)",
                );
                return;
            }

            for ((share_amt, share_sig), (output_item_amt, output_data_item)) in
                sigs.signatures.0.iter_items().zip(output_data.iter_items())
            {
                // Guaranteed by the structural_eq check above
                assert_eq!(share_amt, output_item_amt);

                let amount_key = match self.pub_key_shares[&peer_id].tier(&share_amt) {
                    Ok(key) => key,
                    Err(_) => {
                        error!(
                            ?peer_id,
                            amount = ?share_amt,
                            "Missing public key for the amount. This should not happen."
                        );
                        return;
                    }
                };

                if !verify_blind_share(output_data_item.0, share_sig.1, *amount_key) {
                    warn!(?peer_id, "Ignoring invalid contribution share from peer");
                    return;
                }
            }

            if let Some(_prev) = peer_shares.insert(
                peer_id,
                // We compact the shares to a `Vec<BlindedSignatureShare>` like
                // we eventually want in the consensus itself: https://github.com/fedimint/fedimint/issues/1053#issue-1477111966
                sigs.signatures
                    .0
                    .iter_items()
                    .map(|(_, (_, sig_share))| *sig_share)
                    .collect(),
            ) {
                warn!(
                    out_point = %sigs.out_point,
                    ?peer_id,
                    "Duplicate signature share for out_point",
                );
            }

            self.threshold <= peer_shares.len()
        } else {
            false
        };

        if enough_shares {
            let (output_data, sig_shares) = self
                .pending_outputs
                .remove(&sigs.out_point)
                .expect("must be in the map already");

            for (item_i, (item_amt, item)) in output_data.iter_items().enumerate() {
                let iss_request = if let Some(iss_request) = item.1 {
                    iss_request
                } else {
                    // Items without issuance request are ones we don't consider ours
                    // for some reason, so there's no point combining sigs for them.
                    continue;
                };

                let sig = combine_valid_shares(
                    sig_shares
                        .iter()
                        .map(|(peer, shares)| (peer.to_usize(), shares[item_i])),
                    self.threshold,
                );

                let note = iss_request
                    .finalize(
                        sig,
                        *self
                            .tbs_pks
                            .tier(&item_amt)
                            .expect("must have keys for all amounts here"),
                    )
                    .expect("We can assume all data valid at this point");

                self.spendable_note_by_nonce
                    .insert(iss_request.nonce(), (item_amt, note));
            }
        }
    }

    pub(crate) fn handle_consensus_item(
        &mut self,
        peer_id: PeerId,
        item: &ConsensusItem,
        processed_txs: &mut HashSet<TransactionId>,
        rejected_txs: &BTreeSet<TransactionId>,
    ) {
        debug!(target: LOG_ECASH_RECOVERY, ?item, "handling consensus item");
        match item {
            ConsensusItem::Transaction(tx) => {
                let txid = tx.tx_hash();

                if !processed_txs.insert(txid) {
                    // Just like server side consensus, do not attempt to process the same
                    // transaction twice.
                    debug!(target: LOG_ECASH_RECOVERY, ?item, "was already processed");
                    return;
                }

                if rejected_txs.contains(&txid) {
                    debug!(target: LOG_ECASH_RECOVERY, ?item, "was rejected");
                    // Do not process invalid transactions.
                    // Consensus history contains all data proposed by each peer, even invalid (e.g.
                    // due to double spent) transactions. Precisely to save
                    // downstream users from having to run the consensus themselves,
                    // each epoch contains a list of transactions  that turned out to be invalid.
                    return;
                }

                for input in &tx.inputs {
                    if input.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_MINT {
                        let input = input
                            .as_any()
                            .downcast_ref::<MintInput>()
                            .expect("mint key just checked");

                        self.handle_input(input);
                    }
                }

                for (out_idx, output) in tx.outputs.iter().enumerate() {
                    if output.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_MINT {
                        let output = output
                            .as_any()
                            .downcast_ref::<MintOutput>()
                            .expect("mint key just checked");

                        self.handle_output(
                            OutPoint {
                                txid,
                                out_idx: out_idx as u64,
                            },
                            output,
                        );
                    }
                }
            }
            ConsensusItem::Module(module_item) => {
                if module_item.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_MINT {
                    let mint_item = module_item
                        .as_any()
                        .downcast_ref::<MintConsensusItem>()
                        .expect("mint key just checked");

                    self.handle_output_confirmation(peer_id, mint_item);
                }
            }
            _ => {}
        }
    }

    fn finalize(self) -> EcashRecoveryFinalState {
        EcashRecoveryFinalState {
            spendable_notes: self
                .spendable_note_by_nonce
                .into_iter()
                .map(|(_nonce, (amount, snote))| (amount, snote))
                .collect(),
            unconfirmed_notes: self
                .pending_outputs
                .into_iter()
                .map(|(out_point, data)| {
                    (
                        out_point,
                        NoteIssuanceRequests {
                            notes: TieredMulti::from_iter(data.0.into_iter_items().filter_map(
                                |(amount, (_bn, opt_note_iss_req))| {
                                    opt_note_iss_req.map(|iss_req| (amount, iss_req))
                                },
                            )),
                        },
                    )
                })
                .collect(),
            // next note idx is the last one detected as used + 1
            next_note_idx: Tiered::from_iter(
                self.last_mined_nonce_idx
                    .iter()
                    .map(|(amount, value)| (amount, value.next())),
            ),
        }
    }
}

#[cfg(test)]
mod tests;
