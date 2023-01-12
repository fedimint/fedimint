use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use fedimint_api::{
    core::{self, Output, LEGACY_HARDCODED_INSTANCE_ID_MINT},
    msats, Amount, OutPoint, PeerId, Tiered, TieredMulti,
};
use fedimint_core::{
    epoch::ConsensusItem,
    modules::mint::{
        BlindNonce, MintInput, MintOutput, MintOutputConfirmation, OutputConfirmationSignatures,
    },
    transaction::Transaction,
};
use fedimint_derive_secret::DerivableSecret;
use tbs::{AggregatePublicKey, BlindedSignatureShare, PublicKeyShare, SecretKeyShare};

use super::{EcashRecoveryTracker, PlaintextEcashBackup};
use crate::{
    mint::{
        db::OutputFinalizationKey, MintClient, NoteIndex, NoteIssuanceRequest,
        NoteIssuanceRequests, SpendableNote,
    },
    Client,
};

/// Simplest in-memory mint client for the purpose of writting tests
/// (at least e-cash recovery ones).
///
/// It only tracks state of deterministic e-cash notes creation,
/// and provide couple of functions to help manipulate them.
///
/// State management is left for the user (which in tests is usually
/// bunch of variables tracking things).
struct MicroMintClient {
    next_note_idx: Tiered<NoteIndex>,
    secret: DerivableSecret,
}

impl MicroMintClient {
    fn from_short_seed(id: u8) -> Self {
        let root_secret = DerivableSecret::new_root(&[id; 32], &[0; 32]);
        Self::new(Client::<()>::mint_secret_static(&root_secret))
    }

    fn new(secret: DerivableSecret) -> Self {
        Self {
            next_note_idx: Tiered::default(),
            secret,
        }
    }

    fn make_backup<PendingInner>(
        &self,
        spendable_notes: impl IntoIterator<Item = (Amount, SpendableNote)>,
        // pending_notes: impl IntoIterator<Item = (OutPoint, NoteIssuanceRequests)>,
        pending_notes: impl IntoIterator<Item = (OutPoint, PendingInner)>,
    ) -> PlaintextEcashBackup
    where
        PendingInner: IntoIterator<Item = (Amount, NoteIssuanceRequest)>,
    {
        PlaintextEcashBackup {
            notes: TieredMulti::from_iter(spendable_notes.into_iter()),
            pending_notes: pending_notes
                .into_iter()
                .map(|(out_point, iss_reqs)| {
                    (
                        OutputFinalizationKey(out_point),
                        NoteIssuanceRequests {
                            coins: TieredMulti::from_iter(iss_reqs),
                        },
                    )
                })
                .collect(),
            epoch: 0,
            next_note_idx: self.next_note_idx.clone(),
        }
    }

    fn generate_pending_note(&mut self, amount: Amount) -> (NoteIssuanceRequest, BlindNonce) {
        let note_idx_ref = self.next_note_idx.get_mut_or_default(amount);
        let note_idx = *note_idx_ref;
        note_idx_ref.advance();

        NoteIssuanceRequest::new(
            secp256k1::SECP256K1,
            MintClient::new_note_secret_static(&self.secret, amount, note_idx),
        )
    }

    fn generate_output(
        &mut self,
        note_amounts: impl IntoIterator<Item = u64>,
    ) -> (MintOutput, Vec<(Amount, BlindNonce, NoteIssuanceRequest)>) {
        let tiered = TieredMulti::from_iter(note_amounts.into_iter().map(|amount| {
            let amount = Amount::from_msats(amount);
            let (iss_req, bn) = self.generate_pending_note(amount);

            (amount, (bn, iss_req))
        }));

        (
            MintOutput(TieredMulti::from_iter(
                tiered
                    .iter_items()
                    .map(|(amount, (bn, _iss_req))| (amount, *bn)),
            )),
            tiered
                .iter_items()
                .map(|(amount, (bn, iss_req))| (amount, *bn, *iss_req))
                .collect(),
        )
    }

    fn generate_input(
        &self,
        spendable_notes: impl IntoIterator<Item = (Amount, SpendableNote)>,
    ) -> MintInput {
        MintInput(TieredMulti::from_iter(
            spendable_notes
                .into_iter()
                .map(|(amount, snote)| (amount, snote.note)),
        ))
    }
}

/// Minimal mint-only federation
///
/// This is just bunch of functions to make it more convenient to
/// simulate what a w real federation would do w.r.t. handling
/// mint notes.
struct MicroMintFed {
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    pub sec_key_shares: BTreeMap<PeerId, Tiered<SecretKeyShare>>,
    pub threshold: usize,
}

impl MicroMintFed {
    fn new(threshold: usize, peers_num: usize, amount_tiers: &[Amount]) -> Self {
        let mut tbs_pks: Tiered<AggregatePublicKey> = Tiered::default();
        let mut pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>> = BTreeMap::default();
        let mut sec_key_shares: BTreeMap<PeerId, Tiered<SecretKeyShare>> = BTreeMap::default();
        for &amount in amount_tiers {
            let (agg_pk, pub_keys, sec_keys) = tbs::dealer_keygen(threshold, peers_num);
            tbs_pks.insert(amount, agg_pk);
            for peer_i in 0..peers_num {
                let peer_id = PeerId::from(peer_i as u16);
                pub_key_shares
                    .entry(peer_id)
                    .or_default()
                    .insert(amount, pub_keys[peer_i]);
                sec_key_shares
                    .entry(peer_id)
                    .or_default()
                    .insert(amount, sec_keys[peer_i]);
            }
        }
        Self {
            tbs_pks,
            pub_key_shares,
            sec_key_shares,
            threshold,
        }
    }

    /// Generate [`MintOutputconfirmation`]s for each peer in the federation
    fn confirm_mint_output(
        &self,
        out_point: OutPoint,
        output: &MintOutput,
    ) -> Vec<(PeerId, MintOutputConfirmation)> {
        self.sec_key_shares
            .iter()
            .map(|(peer_id, sec_keys)| {
                (
                    *peer_id,
                    MintOutputConfirmation {
                        out_point,
                        signatures: OutputConfirmationSignatures(TieredMulti::from_iter(
                            output.0.iter_items().map(|(amount, blind_nonce)| {
                                let blind_message = blind_nonce.0;

                                (
                                    amount,
                                    (
                                        blind_message,
                                        tbs::sign_blinded_msg(
                                            blind_message,
                                            *sec_keys
                                                .get(amount)
                                                .expect("key for amount must be there"),
                                        ),
                                    ),
                                )
                            }),
                        )),
                    },
                )
            })
            .collect()
    }

    /// Combine multiple mint consensus item output confirmations into
    /// actual spendable notes.
    ///
    /// This is actually client-side operation, but given that it uses
    /// keys and other data the `self` has already, it makes sense to
    /// just do it here.
    fn combine_output_confirmations(
        &self,
        note_iss_requests: &[(Amount, BlindNonce, NoteIssuanceRequest)],
        confirmations: &[(PeerId, MintOutputConfirmation)],
    ) -> Vec<(Amount, SpendableNote)> {
        let mut confs_by_order: Vec<HashMap<PeerId, BlindedSignatureShare>> = vec![];

        for (peer_id, mint_output_conf) in confirmations {
            for (i, (_amount, (_bn, sig_share))) in
                mint_output_conf.signatures.0.iter_items().enumerate()
            {
                if confs_by_order.len() <= i {
                    assert_eq!(i, confs_by_order.len());
                    confs_by_order.push(HashMap::new());
                }
                confs_by_order[i].insert(*peer_id, *sig_share);
            }
        }

        assert_eq!(confs_by_order.len(), note_iss_requests.len());

        note_iss_requests
            .iter()
            .zip(confs_by_order.into_iter())
            .map(|((amount, _bn, iss_req), sigs_by_peer)| {
                let bsig = tbs::combine_valid_shares(
                    sigs_by_peer
                        .iter()
                        .map(|(peer_id, bsig)| (peer_id.to_usize(), *bsig)),
                    self.threshold,
                );
                (
                    *amount,
                    iss_req
                        .finalize(bsig, *self.tbs_pks.tier(amount).expect("Must have it"))
                        .expect("all sigshares must be valid"),
                )
            })
            .collect()
    }
}

#[test]
fn sanity_ecash_backup_align() {
    assert_eq!(PlaintextEcashBackup::get_alignment_size(1), 16 * 1024);
    assert_eq!(
        PlaintextEcashBackup::get_alignment_size(16 * 1024),
        16 * 1024
    );
    assert_eq!(
        PlaintextEcashBackup::get_alignment_size(16 * 1024 + 1),
        16 * 1024 * 2
    );
}

#[test]
fn sanity_ecash_backup_decode_encode() -> Result<()> {
    let orig = PlaintextEcashBackup {
        notes: TieredMulti::from_iter([]),
        pending_notes: vec![],
        next_note_idx: Tiered::from_iter(
            [(Amount::from_msats(1), NoteIndex::from_u64(3))].into_iter(),
        ),
        epoch: 0,
    };

    let encoded = orig.encode()?;
    assert_eq!(encoded.len(), 16 * 1024);
    assert_eq!(orig, PlaintextEcashBackup::decode(&encoded)?);

    Ok(())
}

#[test]
fn sanity_ecash_backup_encrypt_decrypt() -> Result<()> {
    let orig = PlaintextEcashBackup {
        notes: TieredMulti::from_iter([]),
        pending_notes: vec![],
        next_note_idx: Tiered::from_iter(
            [(Amount::from_msats(1), NoteIndex::from_u64(3))].into_iter(),
        ),
        epoch: 1,
    };

    let secret = DerivableSecret::new_root(&[1; 32], &[1, 32]);
    let key = MintClient::get_derived_backup_encryption_key_static(&secret);

    let encrypted = orig.encrypt_to(&key)?;

    let decrypted = encrypted.decrypt_with(&key)?;

    assert_eq!(orig, decrypted);

    Ok(())
}

// A sanity test that simulates a simplest mint note lifecycle,
// and confirms that backup recovery is tracking it correctly.
//
// It very much uses the knowledge of how recovery is implemented,
// but given that recovery code is inherently complex, it makes
// sense to validate things this way.
//
// In addition, opportunistically multiple checks are being done
// here in sequnce. Ideally a test would exercise just one thing,
// but given the amount of boilerplate and sequential nature of
// the process, it really does pay off to check multiple things.
#[test]
fn sanity_check_recovery_fresh_backup() {
    let peers_num = 3;
    let threshold = 2;
    let gap_limit = 10;
    let amount_tiers = [msats(1), msats(2), msats(4)];

    let fed = MicroMintFed::new(threshold, peers_num, &amount_tiers);

    // Client 1
    let mut c1 = MicroMintClient::from_short_seed(0);

    // Make an empty backup of client1
    let empty_backup_c1 = c1.make_backup::<Vec<_>>(vec![], vec![]);

    // Start a recovery nonce tracker from the backup.
    // This simulates the simplest (yet corner) case, where we start from
    // nothing.
    let mut tracker = EcashRecoveryTracker::from_backup(
        empty_backup_c1,
        c1.secret.clone(),
        gap_limit,
        fed.tbs_pks.clone(),
        fed.pub_key_shares.clone(),
    );

    let (output_c1_a, iss_reqs_c1_a) = c1.generate_output([1, 2, 4]);

    let tx_a = Transaction {
        inputs: vec![],
        outputs: vec![Output::from_typed(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            output_c1_a.clone(),
        )],
        signature: None,
    };

    let output_c1_a_out_point = OutPoint {
        txid: tx_a.tx_hash(),
        out_idx: 0,
    };

    tracker.handle_consensus_item(
        PeerId::from(0),
        &ConsensusItem::Transaction(tx_a),
        &mut Default::default(),
        &Default::default(),
    );

    // At this point tracker should recognize c1's blind nonces are mined and move them
    // into `pending_outputs` to start matching against consensus items.
    assert_eq!(tracker.pending_outputs.len(), 1);
    assert!(tracker.pending_outputs.contains_key(&output_c1_a_out_point));

    // Generate mint consensus items to confirm
    let confirmations_c1_a = fed.confirm_mint_output(output_c1_a_out_point, &output_c1_a);

    // The tracker will deduplicate/ignore redundant confirmations
    for _ in 0..3 {
        tracker.handle_consensus_item(
            confirmations_c1_a[0].0,
            &ConsensusItem::Module(core::ConsensusItem::from_typed(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                confirmations_c1_a[0].1.clone(),
            )),
            &mut Default::default(),
            &Default::default(),
        );

        assert_eq!(
            tracker
                .pending_outputs
                .get(&output_c1_a_out_point)
                .unwrap()
                .1
                .len(),
            1
        );
    }

    // The tracker will reject incorrect confirmations (here: mismatch between peer and confirmation data)
    for wrong_peer_i in 1..2 {
        tracker.handle_consensus_item(
            confirmations_c1_a[wrong_peer_i].0,
            &ConsensusItem::Module(core::ConsensusItem::from_typed(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                confirmations_c1_a[0].1.clone(),
            )),
            &mut Default::default(),
            &Default::default(),
        );

        assert_eq!(
            tracker
                .pending_outputs
                .get(&output_c1_a_out_point)
                .unwrap()
                .1
                .len(),
            1
        );
    }

    // After enough correct confirmations, the tracker convert tracked output into spendable notes
    for (peer_id, mint_output_confirmation) in &confirmations_c1_a {
        tracker.handle_consensus_item(
            *peer_id,
            &ConsensusItem::Module(core::ConsensusItem::from_typed(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                mint_output_confirmation.clone(),
            )),
            &mut Default::default(),
            &Default::default(),
        );
    }

    let notes_c1_a = fed.combine_output_confirmations(&iss_reqs_c1_a, &confirmations_c1_a);

    assert_eq!(
        tracker.spendable_note_by_nonce,
        notes_c1_a
            .iter()
            .map(|(amount, spendable_note)| (spendable_note.note.0, (*amount, *spendable_note)))
            .collect()
    );

    // Spend the notes, which should remove them from the tracker
    let tx_b = Transaction {
        inputs: vec![core::DynInput::from_typed(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            c1.generate_input(notes_c1_a),
        )],
        outputs: vec![core::Output::from_typed(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            output_c1_a,
        )],
        signature: None,
    };

    tracker.handle_consensus_item(
        PeerId::from(0),
        &ConsensusItem::Transaction(tx_b),
        &mut Default::default(),
        &Default::default(),
    );
    assert!(tracker.spendable_note_by_nonce.is_empty());
}

/// Exercise restoring from backup that contains existing notes (spendable & unsigned)
///
/// Refer to [`sanity_check_recovery_fresh_backup`] for introduction and more comments
#[test]
fn sanity_check_recovery_non_empty_backup() {
    let peers_num = 3;
    let threshold = 2;
    let gap_limit = 10;
    let amount_tiers = [msats(1), msats(2), msats(4)];

    let fed = MicroMintFed::new(threshold, peers_num, &amount_tiers);

    // Client 1
    let mut c1 = MicroMintClient::from_short_seed(0);

    let (output_c1_a0, iss_reqs_c1_a0) = c1.generate_output([1, 2, 4]);
    let (output_c1_a1, iss_reqs_c1_a1) = c1.generate_output([1, 4]);

    let tx_a = Transaction {
        inputs: vec![],
        outputs: vec![
            core::Output::from_typed(LEGACY_HARDCODED_INSTANCE_ID_MINT, output_c1_a0.clone()),
            core::Output::from_typed(LEGACY_HARDCODED_INSTANCE_ID_MINT, output_c1_a1.clone()),
        ],
        signature: None,
    };

    let output_c1_a0_out_point = OutPoint {
        txid: tx_a.tx_hash(),
        out_idx: 0,
    };
    let output_c1_a1_out_point = OutPoint {
        txid: tx_a.tx_hash(),
        out_idx: 1,
    };

    let confirmations_c1_a0 = fed.confirm_mint_output(output_c1_a0_out_point, &output_c1_a0);

    let notes_c1_a0 = fed.combine_output_confirmations(&iss_reqs_c1_a0, &confirmations_c1_a0);

    // Make a backup of client1 with both some unsigned and spendable notes
    let backup_c1 = c1.make_backup(
        notes_c1_a0.clone(),
        vec![(
            output_c1_a1_out_point,
            iss_reqs_c1_a1
                .iter()
                .map(|(amount, _bn, iss_req)| (*amount, *iss_req)),
        )],
    );

    // Start a recovery nonce tracker from the backup.
    let mut tracker = EcashRecoveryTracker::from_backup(
        backup_c1,
        c1.secret.clone(),
        gap_limit,
        fed.tbs_pks.clone(),
        fed.pub_key_shares.clone(),
    );

    // Spend the notes, which should remove them from the tracker
    let tx_b = Transaction {
        inputs: vec![core::DynInput::from_typed(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            c1.generate_input(notes_c1_a0),
        )],
        outputs: vec![],
        signature: None,
    };
    let confirmations_c1_a1 = fed.confirm_mint_output(output_c1_a1_out_point, &output_c1_a1);

    tracker.handle_consensus_item(
        PeerId::from(0),
        &ConsensusItem::Transaction(tx_b),
        &mut Default::default(),
        &Default::default(),
    );

    for (peer_id, mint_output_confirmation) in &confirmations_c1_a1 {
        tracker.handle_consensus_item(
            *peer_id,
            &ConsensusItem::Module(core::ConsensusItem::from_typed(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                mint_output_confirmation.clone(),
            )),
            &mut Default::default(),
            &Default::default(),
        );
    }

    let notes_c1_a1 = fed.combine_output_confirmations(&iss_reqs_c1_a1, &confirmations_c1_a1);

    assert_eq!(tracker.spendable_note_by_nonce.len(), notes_c1_a1.len());
    for snote in notes_c1_a1 {
        assert!(tracker
            .spendable_note_by_nonce
            .contains_key(&snote.1.note.0));
    }
}

/// Exercise restoring from backup where another client tries to race to re-use blind nonce (with different amount)
///
/// Refer to [`sanity_check_recovery_fresh_backup`] for introduction and more comments
#[test]
fn sanity_check_recovery_bn_reuse_with_invalid_amount() {
    let peers_num = 3;
    let threshold = 2;
    let gap_limit = 10;
    let amount_tiers = [msats(1), msats(2), msats(4)];

    let fed = MicroMintFed::new(threshold, peers_num, &amount_tiers);

    // Client 1
    let mut c1 = MicroMintClient::from_short_seed(0);
    // Client 2
    let mut c2 = MicroMintClient::from_short_seed(1);

    let backup_c1 = c1.make_backup::<Vec<_>>(vec![], vec![]);

    let mut tracker = EcashRecoveryTracker::from_backup(
        backup_c1,
        c1.secret.clone(),
        gap_limit,
        fed.tbs_pks.clone(),
        fed.pub_key_shares,
    );

    let (output_c1_b, _iss_reqs_c1_b) = c1.generate_output([1, 2, 4]);
    let (mut output_c2_a, _iss_reqs_c2_a) = c2.generate_output([1, 2, 4]);

    // Client2 uses blind nonce of client1, with a smaller value, trying to confuse them!!!
    output_c2_a.0.get_mut(msats(1)).unwrap()[0] = output_c1_b.0.get(msats(4)).unwrap()[0];

    let tx_a = Transaction {
        inputs: vec![],
        outputs: vec![core::Output::from_typed(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            output_c2_a.clone(),
        )],
        signature: None,
    };
    let output_c1_a_out_point = OutPoint {
        txid: tx_a.tx_hash(),
        out_idx: 0,
    };

    let tx_b = Transaction {
        inputs: vec![],
        outputs: vec![core::Output::from_typed(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            output_c1_b,
        )],
        signature: None,
    };
    let output_c1_b_out_point = OutPoint {
        txid: tx_b.tx_hash(),
        out_idx: 0,
    };

    // The transaction with fake outputs gets included in consensus earlier, so tracker
    // processes it first.
    tracker.handle_consensus_item(
        PeerId::from(0),
        &ConsensusItem::Transaction(tx_a),
        &mut Default::default(),
        &Default::default(),
    );
    tracker.handle_consensus_item(
        PeerId::from(0),
        &ConsensusItem::Transaction(tx_b),
        &mut Default::default(),
        &Default::default(),
    );

    // Tracker ignored the tx with incorrect values, because the amount associated with
    // this blind nonce was incorrect.
    // It did start tracking the correct output.
    assert_eq!(tracker.pending_outputs.len(), 1);
    assert!(!tracker.pending_outputs.contains_key(&output_c1_a_out_point));
    assert!(tracker.pending_outputs.contains_key(&output_c1_b_out_point));
}

/// Exercise restoring from backup where another client tries to race to re-use blind nonce (with valid amount)
///
/// Refer to [`sanity_check_recovery_fresh_backup`] for introduction and more comments
#[test]
fn sanity_check_recovery_bn_reuse_with_valid_amount() {
    let peers_num = 3;
    let threshold = 2;
    let gap_limit = 10;
    let amount_tiers = [msats(1), msats(2), msats(4)];

    let fed = MicroMintFed::new(threshold, peers_num, &amount_tiers);

    // Client 1
    let mut c1 = MicroMintClient::from_short_seed(0);
    // Client 2
    let mut c2 = MicroMintClient::from_short_seed(1);

    let backup_c1 = c1.make_backup::<Vec<_>>(vec![], vec![]);

    let mut tracker = EcashRecoveryTracker::from_backup(
        backup_c1,
        c1.secret.clone(),
        gap_limit,
        fed.tbs_pks.clone(),
        fed.pub_key_shares.clone(),
    );

    let (output_c1_b, iss_reqs_c1_b) = c1.generate_output([1, 2, 4]);
    let (mut output_c2_a, _iss_reqs_c2_a) = c2.generate_output([1, 2, 4]);

    // Client2 uses blind nonce of client1, with a same value, trying to confuse them!!!
    output_c2_a.0.get_mut(msats(1)).unwrap()[0] = output_c1_b.0.get(msats(1)).unwrap()[0];

    let tx_a = Transaction {
        inputs: vec![],
        outputs: vec![core::Output::from_typed(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            output_c2_a.clone(),
        )],
        signature: None,
    };
    let output_c2_a_out_point = OutPoint {
        txid: tx_a.tx_hash(),
        out_idx: 0,
    };

    let tx_b = Transaction {
        inputs: vec![],
        outputs: vec![core::Output::from_typed(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            output_c1_b.clone(),
        )],
        signature: None,
    };
    let output_c1_b_out_point = OutPoint {
        txid: tx_b.tx_hash(),
        out_idx: 0,
    };

    // The transaction with fake outputs gets included in consensus earlier, so tracker
    // processes it first.
    tracker.handle_consensus_item(
        PeerId::from(0),
        &ConsensusItem::Transaction(tx_a),
        &mut Default::default(),
        &Default::default(),
    );
    tracker.handle_consensus_item(
        PeerId::from(0),
        &ConsensusItem::Transaction(tx_b),
        &mut Default::default(),
        &Default::default(),
    );

    // Tracker tracks both outputs now
    assert_eq!(tracker.pending_outputs.len(), 2);
    assert!(tracker.pending_outputs.contains_key(&output_c2_a_out_point));
    assert!(tracker.pending_outputs.contains_key(&output_c1_b_out_point));

    let confirmations_c2_a = fed.confirm_mint_output(output_c2_a_out_point, &output_c2_a);

    for (peer_id, mint_output_confirmation) in &confirmations_c2_a {
        tracker.handle_consensus_item(
            *peer_id,
            &ConsensusItem::Module(core::ConsensusItem::from_typed(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                mint_output_confirmation.clone(),
            )),
            &mut Default::default(),
            &Default::default(),
        );
    }

    // Tracker was happy to accept the note of the correct value produced by client2, however...
    assert_eq!(tracker.spendable_note_by_nonce.len(), 1);

    let confirmations_c1_b = fed.confirm_mint_output(output_c1_b_out_point, &output_c1_b);
    for (peer_id, mint_output_confirmation) in &confirmations_c1_b {
        tracker.handle_consensus_item(
            *peer_id,
            &ConsensusItem::Module(core::ConsensusItem::from_typed(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                mint_output_confirmation.clone(),
            )),
            &mut Default::default(),
            &Default::default(),
        );
    }

    let notes_c1_b = fed.combine_output_confirmations(&iss_reqs_c1_b, &confirmations_c1_b);

    assert_eq!(tracker.spendable_note_by_nonce.len(), notes_c1_b.len());
    // ... irrespective of that it still recovered other notes of client1.
    for snote in notes_c1_b {
        assert!(tracker
            .spendable_note_by_nonce
            .contains_key(&snote.1.note.0));
    }
}
