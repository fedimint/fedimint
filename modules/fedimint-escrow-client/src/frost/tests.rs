use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::runtime::{JoinHandle, sleep, spawn, timeout};
use fedimint_core::secp256k1::{self, Keypair, Message, Parity, PublicKey, Secp256k1, schnorr};
use fedimint_core::time::duration_since_epoch;
use fedimint_escrow_common::rules::{Settlement, check_resolution};
use fedimint_escrow_common::{
    ContractHash, EscrowContract, EscrowId, EscrowInputError, EscrowMessage, EscrowStatus,
    EscrowTransition, FallbackPolicy, Outcome, Resolution, compute_escrow_message,
};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::round1::commit as Round1Commit;
use frost_secp256k1_tr::round2::sign as Round2Sign;
use frost_secp256k1_tr::{Identifier, Signature, SigningPackage, aggregate};
use iroh::{Endpoint, NodeAddr, RelayMode, SecretKey};
use rand::rngs::OsRng;

use crate::client_db::FrostDkgSessionKey;
use crate::frost::dkg::{DkgError, DkgResult, DkgRound1, DkgRunner};
use crate::frost::frost_sign::{
    SignerOutcome, SigningError, SigningMux, coordinator_for_slot, finished_frame, pick_outcome,
    sign_as_coordinator, sign_as_signer, sign_with_failover,
};
use crate::frost::secret::StateKey;
use crate::frost::session::{FrostDkgSessionRecord, FrostParticipant, SessionId};
use crate::frost::transport::file::FileTransport;
use crate::frost::transport::iroh::{DKG_ALPN, IrohDkgTransport};
use crate::frost::transport::{DkgTransport, SigningTransport, TransportError};

const DKG_STATE_KEY: [u8; 32] = [7u8; 32];
fn dummy_federation_id() -> FederationId {
    FederationId::dummy()
}

fn create_frost_participant(count: usize) -> Vec<FrostParticipant> {
    let secp = Secp256k1::new();
    (0..count)
        .map(|_| {
            let keypair = Keypair::new(&secp, &mut OsRng);
            FrostParticipant::from_pubkey(keypair.public_key()).expect("invalid identifier")
        })
        .collect()
}

async fn has_saved_state(db: &Database, session_id: SessionId) -> bool {
    let mut dbtx = db.begin_transaction_nc().await;
    dbtx.get_value(&FrostDkgSessionKey(session_id))
        .await
        .is_some()
}

struct IrohNet {
    ids: Vec<Identifier>,
    endpoints: Vec<Endpoint>,
    peers: BTreeMap<Identifier, NodeAddr>,
}

impl IrohNet {
    fn transport(&self, index: usize, session_id: SessionId) -> IrohDkgTransport {
        IrohDkgTransport::from_endpoint(
            self.endpoints[index].clone(),
            session_id,
            self.peers.clone(),
        )
    }

    /// A transport that only knows the listed members
    fn transport_knowing(
        &self,
        index: usize,
        session_id: SessionId,
        known: &[usize],
    ) -> IrohDkgTransport {
        let peers = known
            .iter()
            .map(|position| {
                let id = self.ids[*position];
                (id, self.peers[&id].clone())
            })
            .collect();
        IrohDkgTransport::from_endpoint(self.endpoints[index].clone(), session_id, peers)
    }
}

async fn bind_iroh_net(ids: &[Identifier]) -> IrohNet {
    let mut endpoints = Vec::new();
    let mut peers = BTreeMap::new();

    for id in ids {
        let endpoint = Endpoint::builder()
            .secret_key(SecretKey::from_bytes(&rand::random::<[u8; 32]>()))
            .alpns(vec![DKG_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind endpoint");

        peers.insert(*id, endpoint.node_addr().await.expect("node addr"));
        endpoints.push(endpoint);
    }

    IrohNet {
        ids: ids.to_vec(),
        endpoints,
        peers,
    }
}

struct Consortium {
    participants: Vec<FrostParticipant>,
    session_id: SessionId,
    sessions: Vec<(Database, FrostDkgSessionRecord)>,
}

impl Consortium {
    async fn new(size: usize) -> anyhow::Result<Self> {
        let federation_id = dummy_federation_id();

        let participants: Vec<FrostParticipant> = create_frost_participant(size);

        let mut sessions = Vec::with_capacity(size);

        for participant in &participants {
            let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

            let record = FrostDkgSessionRecord::new(
                participant.clone(),
                participants.clone(),
                federation_id,
                &db,
            )
            .await?;

            sessions.push((db, record));
        }

        let session_id = sessions[0].1.session_id;

        Ok(Self {
            participants,
            session_id,
            sessions,
        })
    }

    async fn run(self) -> Vec<DkgResult> {
        let mut handles = Vec::with_capacity(self.sessions.len());
        for (db, record) in self.sessions {
            let session_id = self.session_id;
            handles.push(spawn("file_transport_dkg", async move {
                let transport = FileTransport::new(&session_id)
                    .await
                    .expect("transport init");

                record
                    .run(&db, transport, &StateKey::new(&DKG_STATE_KEY))
                    .await
                    .expect("dkg failed")
            }));
        }

        let mut results = Vec::with_capacity(handles.len());

        for handle in handles {
            results.push(handle.await.expect("task panicked"));
        }

        results
    }

    async fn iroh_net(&self) -> IrohNet {
        let ids: Vec<Identifier> = self
            .participants
            .iter()
            .map(|participant| participant.identifier)
            .collect();
        bind_iroh_net(&ids).await
    }

    async fn run_iroh(self) -> Vec<DkgResult> {
        let net = self.iroh_net().await;
        let mut handles = Vec::with_capacity(self.sessions.len());

        for (index, (db, record)) in self.sessions.into_iter().enumerate() {
            let transport = net.transport(index, self.session_id);

            handles.push(spawn("iroh_transport_dkg", async move {
                sleep(Duration::from_millis(200 * index as u64)).await;
                record
                    .run(&db, transport, &StateKey::new(&DKG_STATE_KEY))
                    .await
                    .expect("dkg failed")
            }));
        }

        let mut results = Vec::with_capacity(handles.len());

        for handle in handles {
            results.push(handle.await.expect("task panicked"));
        }

        results
    }
}

/// Plain FROST signing with the key packages of a finished DKG
fn sign(signers: &[&DkgResult], message: &[u8]) -> Result<Signature, frost_secp256k1_tr::Error> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for signer in signers {
        let id = *signer.key_package.identifier();
        let (signer_nonces, signer_commitments) =
            Round1Commit(signer.key_package.signing_share(), &mut OsRng);
        nonces.insert(id, signer_nonces);
        commitments.insert(id, signer_commitments);
    }

    let signing_package = SigningPackage::new(commitments, message);

    let mut shares = BTreeMap::new();
    for signer in signers {
        let id = *signer.key_package.identifier();
        let share = Round2Sign(&signing_package, &nonces[&id], &signer.key_package)?;
        shares.insert(id, share);
    }

    aggregate(&signing_package, &shares, &signers[0].pubkey_package)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_converges_to_same_aggregate_key() {
    let consortium = Consortium::new(3).await.expect("consortium failed");
    let results = consortium.run().await;
    let first = results[0].pubkey_package.verifying_key().serialize();

    for result in &results[1..] {
        assert_eq!(
            result.pubkey_package.verifying_key().serialize(),
            first,
            "all participants must converge on the same aggregate public key"
        );
    }
    for result in &results {
        let id = *result.key_package.identifier();
        assert_eq!(
            result.key_package.verifying_share(),
            result.pubkey_package.verifying_shares().get(&id).unwrap()
        );
    }

    for (position, first_member) in results.iter().enumerate() {
        for second_member in &results[position + 1..] {
            assert_ne!(
                first_member.key_package.verifying_share(),
                second_member.key_package.verifying_share()
            );
        }
    }
}

#[tokio::test]
async fn test_participants_have_unique_identifiers() {
    let consortium = Consortium::new(5).await.expect("consortium failed");

    let mut identifiers = std::collections::HashSet::new();

    for participant in &consortium.participants {
        assert!(
            identifiers.insert(participant.identifier),
            "participants must have unique identifiers"
        );
    }
}

#[tokio::test]
async fn test_all_participants_have_same_session_id() {
    let consortium = Consortium::new(5).await.expect("consortium failed");

    for (_, session) in &consortium.sessions {
        assert_eq!(
            session.session_id, consortium.session_id,
            "all participants must use the same DKG session ID"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_for_multiple_sizes() {
    for size in [2, 3, 4, 5, 7] {
        let consortium = Consortium::new(size).await;

        if size == 2 {
            assert!(
                consortium.is_err(),
                "DKG setup should fail for {size} participants"
            );
            continue;
        }

        let consortium = consortium.expect("valid consortium");
        let results = consortium.run().await;

        assert_eq!(results.len(), size);

        let aggregate_key = results[0].pubkey_package.verifying_key().serialize();

        for result in &results[1..] {
            assert_eq!(
                result.pubkey_package.verifying_key().serialize(),
                aggregate_key,
                "DKG did not converge for size {size}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_signing_with_dkg_key() {
    for size in [4, 5, 7] {
        let consortium = Consortium::new(size).await.expect("consortium failed");
        let min_signers = consortium.sessions[0].1.min_signers as usize;
        let results = consortium.run().await;
        let group_key = results[0].pubkey_package.verifying_key();
        let message = b"release the funds";

        let enough: Vec<&DkgResult> = results.iter().take(min_signers).collect();
        let signature = sign(&enough, message).expect("signing failed");
        assert!(group_key.verify(message, &signature).is_ok());
        assert!(group_key.verify(b"refund", &signature).is_err());

        let too_few: Vec<&DkgResult> = results.iter().take(min_signers - 1).collect();
        if let Ok(signature) = sign(&too_few, message) {
            assert!(group_key.verify(message, &signature).is_err());
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_any_threshold_sized_group_can_sign() {
    let consortium = Consortium::new(5).await.expect("consortium failed");
    let min_signers = consortium.sessions[0].1.min_signers as usize;
    let results = consortium.run().await;
    let group_key = results[0].pubkey_package.verifying_key();
    let message = b"release the funds";

    // whoever is offline, the others can sign
    for offline in 0..results.len() {
        let online: Vec<&DkgResult> = results
            .iter()
            .enumerate()
            .filter(|(position, _)| *position != offline)
            .map(|(_, result)| result)
            .collect();
        assert_eq!(online.len(), min_signers);

        let signature = sign(&online, message).expect("signing failed");
        assert!(group_key.verify(message, &signature).is_ok());
    }
}

#[tokio::test]
async fn test_invalid_participant_lists_rejected() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let federation_id = dummy_federation_id();

    for size in [1, 2] {
        let participants = create_frost_participant(size);
        let result =
            FrostDkgSessionRecord::new(participants[0].clone(), participants, federation_id, &db)
                .await;
        assert!(result.is_err(), "size {size} must be rejected");
    }

    // duplicate participant
    let mut participants = create_frost_participant(3);
    participants.push(participants[0].clone());
    let result =
        FrostDkgSessionRecord::new(participants[0].clone(), participants, federation_id, &db).await;
    assert!(result.is_err(), "duplicates must be rejected");

    // local participant is not in the list
    let participants = create_frost_participant(3);
    let outsider = create_frost_participant(1).remove(0);
    let result = FrostDkgSessionRecord::new(outsider, participants, federation_id, &db).await;
    assert!(result.is_err(), "outsider must be rejected");
}

#[tokio::test]
async fn test_consortium_size_limits() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let federation_id = dummy_federation_id();

    // a contract has room for 32 fee keys
    for (size, allowed) in [(2, false), (3, true), (32, true), (33, false)] {
        let participants = create_frost_participant(size);
        let result =
            FrostDkgSessionRecord::new(participants[0].clone(), participants, federation_id, &db)
                .await;
        assert_eq!(result.is_ok(), allowed, "size {size}");
    }
}

#[tokio::test]
async fn test_session_id_ignores_participant_order() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let participants = create_frost_participant(4);
    let mut reversed = participants.clone();
    reversed.reverse();

    let original_order = FrostDkgSessionRecord::new(
        participants[0].clone(),
        participants.clone(),
        dummy_federation_id(),
        &db,
    )
    .await
    .unwrap();

    let second_db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let reversed_order = FrostDkgSessionRecord::new(
        participants[0].clone(),
        reversed,
        dummy_federation_id(),
        &second_db,
    )
    .await
    .unwrap();

    assert_eq!(original_order.session_id, reversed_order.session_id);
}

#[tokio::test]
async fn test_threshold_values() {
    for (size, expected_min) in [(3, 3), (4, 3), (5, 4), (7, 5), (10, 7)] {
        let consortium = Consortium::new(size).await.unwrap();
        assert_eq!(
            consortium.sessions[0].1.min_signers, expected_min,
            "size {size}"
        );
    }
}

#[test]
fn test_participant_identity_ignores_key_parity() {
    let public_key = Keypair::new(&Secp256k1::new(), &mut OsRng).public_key();
    let (x_only, _) = public_key.x_only_public_key();
    let even = PublicKey::from_x_only_public_key(x_only, Parity::Even);
    let odd = PublicKey::from_x_only_public_key(x_only, Parity::Odd);
    assert_ne!(even, odd);

    assert_eq!(
        FrostParticipant::from_pubkey(even).unwrap(),
        FrostParticipant::from_pubkey(odd).unwrap()
    );
}

#[test]
fn test_participant_and_session_id_survive_serialization() {
    let participant = create_frost_participant(1).remove(0);
    let json = serde_json::to_string(&participant).unwrap();
    assert_eq!(
        serde_json::from_str::<FrostParticipant>(&json).unwrap(),
        participant
    );

    let session_id = SessionId(rand::random());
    let json = serde_json::to_string(&session_id).unwrap();
    assert_eq!(
        serde_json::from_str::<SessionId>(&json).unwrap(),
        session_id
    );

    assert!(serde_json::from_str::<SessionId>("\"abcd\"").is_err());
    assert!(serde_json::from_str::<SessionId>("\"not hex\"").is_err());
    assert!(serde_json::from_str::<FrostParticipant>("\"zz\"").is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_run_after_finish_returns_same_key() {
    let consortium = Consortium::new(3).await.unwrap();
    let (db, record) = consortium.sessions[0].clone();
    let session_id = consortium.session_id;
    let results = consortium.run().await;

    let transport = FileTransport::new(&session_id).await.unwrap();
    let again = record
        .run(&db, transport, &StateKey::new(&DKG_STATE_KEY))
        .await
        .expect("second run failed");

    assert_eq!(
        again.pubkey_package.verifying_key().serialize(),
        results[0].pubkey_package.verifying_key().serialize()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_completes_when_a_member_joins_late() {
    let consortium = Consortium::new(4).await.expect("consortium failed");
    let session_id = consortium.session_id;
    let late_position = 3;

    let mut handles = Vec::new();
    for (position, (db, record)) in consortium.sessions.into_iter().enumerate() {
        handles.push(spawn("member", async move {
            if position == late_position {
                sleep(Duration::from_secs(4)).await;
            }
            let transport = FileTransport::new(&session_id)
                .await
                .expect("transport init");
            record
                .run(&db, transport, &StateKey::new(&DKG_STATE_KEY))
                .await
                .expect("dkg failed")
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.expect("task panicked"));
    }

    let group_key = results[0].pubkey_package.verifying_key().serialize();
    for result in &results {
        assert_eq!(result.pubkey_package.verifying_key().serialize(), group_key);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_interrupted_run_keeps_its_state_and_reset_clears_it() {
    let consortium = Consortium::new(3).await.expect("consortium failed");
    let session_id = consortium.session_id;
    let (db, record) = consortium.sessions[0].clone();

    // nobody else is running, so this run is cut off while it waits for round 1
    let transport = FileTransport::new(&session_id)
        .await
        .expect("transport init");
    let interrupted = timeout(
        Duration::from_secs(2),
        record.run(&db, transport, &StateKey::new(&DKG_STATE_KEY)),
    )
    .await;
    assert!(interrupted.is_err(), "run must not finish alone");
    assert!(has_saved_state(&db, session_id).await);

    record
        .reset(&db)
        .await
        .expect("an unfinished attempt can be reset");
    assert!(!has_saved_state(&db, session_id).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_reset_never_destroys_a_finished_key() {
    let consortium = Consortium::new(3).await.expect("consortium failed");
    let session_id = consortium.session_id;
    let (db, record) = consortium.sessions[0].clone();
    let results = consortium.run().await;

    assert!(
        record.reset(&db).await.is_err(),
        "resetting would destroy the key share"
    );

    let kept =
        FrostDkgSessionRecord::load_dkg_result(&db, session_id, &StateKey::new(&DKG_STATE_KEY))
            .await
            .expect("the key must still be there");
    assert_eq!(
        kept.pubkey_package.verifying_key().serialize(),
        results[0].pubkey_package.verifying_key().serialize()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_member_resumes_after_a_restart() {
    let consortium = Consortium::new(3).await.expect("consortium failed");
    let session_id = consortium.session_id;
    let (db, record) = consortium.sessions[0].clone();

    // the first process is killed while it waits for the others
    let first_transport = FileTransport::new(&session_id)
        .await
        .expect("transport init");
    let interrupted = timeout(
        Duration::from_secs(2),
        record.run(&db, first_transport, &StateKey::new(&DKG_STATE_KEY)),
    )
    .await;

    assert!(interrupted.is_err());
    assert!(has_saved_state(&db, session_id).await);

    // the others come online
    let other_sessions = consortium.sessions[1..].to_vec();
    let others = spawn("other_members", async move {
        run_honest_members(&other_sessions, session_id).await
    });

    // the restarted process has a new transport and continues from the saved step
    let second_transport = FileTransport::new(&session_id)
        .await
        .expect("transport init");
    let restarted = record
        .run(&db, second_transport, &StateKey::new(&DKG_STATE_KEY))
        .await
        .expect("resumed run failed");

    let group_key = restarted.pubkey_package.verifying_key().serialize();
    for (_, result) in others.await.expect("task panicked") {
        let other = result.expect("dkg failed");
        assert_eq!(other.pubkey_package.verifying_key().serialize(), group_key);
    }
}

type MemberOutcome = (Database, Result<DkgResult, DkgError>);

/// Runs the members over the file transport and gives back how each one ended
async fn run_honest_members(
    sessions: &[(Database, FrostDkgSessionRecord)],
    session_id: SessionId,
) -> Vec<MemberOutcome> {
    let tasks: Vec<_> = sessions
        .iter()
        .map(|(db, record)| {
            let db = db.clone();
            let record = record.clone();

            spawn("honest_member", async move {
                let transport = FileTransport::new(&session_id)
                    .await
                    .expect("transport init");
                let result = record
                    .run(&db, transport, &StateKey::new(&DKG_STATE_KEY))
                    .await;
                (db, result)
            })
        })
        .collect();

    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(task.await.expect("task panicked"));
    }
    outcomes
}

/// Checks that every member gave up without keeping anything and returns the
/// errors
async fn aborted_errors(outcomes: Vec<MemberOutcome>, session_id: SessionId) -> Vec<DkgError> {
    let mut errors = Vec::new();
    for (db, result) in outcomes {
        let error = match result {
            Ok(_) => panic!("the dkg must not finish"),
            Err(error) => error,
        };
        assert!(
            !error.is_transient(),
            "bad data must not be retried: {error}"
        );
        assert!(
            FrostDkgSessionRecord::load_dkg_result(&db, session_id, &StateKey::new(&DKG_STATE_KEY))
                .await
                .is_err()
        );
        assert!(!has_saved_state(&db, session_id).await);
        errors.push(error);
    }
    errors
}

#[tokio::test(flavor = "multi_thread")]
async fn test_corrupted_round1_package_aborts_the_dkg() {
    let consortium = Consortium::new(4).await.expect("consortium failed");
    let session_id = consortium.session_id;
    let faulty = consortium.participants[3].identifier;

    // the fourth member left garbage where its round 1 package should be
    let round1_dir = FileTransport::file_transport_root(&session_id).join("round1");
    tokio::fs::create_dir_all(&round1_dir)
        .await
        .expect("create dir");
    let path = round1_dir.join(format!("{}.json", hex::encode(faulty.serialize())));

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .expect("create garbage file");

    use tokio::io::AsyncWriteExt;
    file.write_all(b"not a package")
        .await
        .expect("write garbage");

    let outcomes = run_honest_members(&consortium.sessions[..3], session_id).await;

    for error in aborted_errors(outcomes, session_id).await {
        assert!(
            matches!(
                error,
                DkgError::TransportError(TransportError::Serialization(_))
            ),
            "unexpected error: {error}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_round1_package_of_another_identity_aborts_the_dkg() {
    let consortium = Consortium::new(4).await.expect("consortium failed");
    let session_id = consortium.session_id;
    let max_signers = consortium.sessions[0].1.max_signers;
    let min_signers = consortium.sessions[0].1.min_signers;
    let faulty = consortium.participants[3].clone();
    let outsider = create_frost_participant(1).remove(0);

    // the fourth member publishes a package that was made for somebody else
    let (_secret, borrowed_package) =
        frost_secp256k1_tr::keys::dkg::part1(outsider.identifier, max_signers, min_signers, OsRng)
            .expect("round 1");
    let transport = FileTransport::new(&session_id)
        .await
        .expect("transport init");
    transport
        .broadcast_round1(&session_id, &faulty.identifier, borrowed_package)
        .await
        .expect("publish");

    let outcomes = run_honest_members(&consortium.sessions[..3], session_id).await;

    for error in aborted_errors(outcomes, session_id).await {
        assert!(
            matches!(error, DkgError::FrostError(_)),
            "unexpected error: {error}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bad_round2_share_aborts_the_dkg() {
    let consortium = Consortium::new(4).await.expect("consortium failed");
    let session_id = consortium.session_id;
    let participants = consortium.participants.clone();
    let record = consortium.sessions[0].1.clone();
    let faulty = participants[3].clone();

    // the fourth member plays round 1 honestly and then gives every member a
    // share that wasn't there
    let faulty_task = spawn("faulty_member", async move {
        let runner = DkgRunner::new(
            FileTransport::new(&session_id)
                .await
                .expect("transport init"),
        );
        let (secret, package) = runner
            .start_round1(&faulty, record.max_signers, record.min_signers)
            .expect("round 1");
        let round1_packages = runner
            .exchange_round1(&session_id, &faulty, &participants, package)
            .await
            .expect("round 1 exchange");
        let (_secret, round2_packages) =
            frost_secp256k1_tr::keys::dkg::part2(secret, &round1_packages).expect("round 2");

        let receivers: Vec<Identifier> = round2_packages.keys().copied().collect();
        let mut shares: Vec<_> = round2_packages.into_values().collect();
        shares.rotate_left(1);

        let transport = FileTransport::new(&session_id)
            .await
            .expect("transport init");
        for (receiver, share) in receivers.iter().zip(shares) {
            transport
                .send_round2(&session_id, &faulty.identifier, receiver, share)
                .await
                .expect("send share");
        }
    });

    let outcomes = run_honest_members(&consortium.sessions[..3], session_id).await;
    faulty_task.await.expect("task panicked");

    for error in aborted_errors(outcomes, session_id).await {
        assert!(
            matches!(error, DkgError::FrostError(_)),
            "unexpected error: {error}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_over_iroh() {
    for size in [3, 4] {
        let consortium = Consortium::new(size).await.expect("consortium failed");
        let min_signers = consortium.sessions[0].1.min_signers as usize;
        let results = consortium.run_iroh().await;

        let first = results[0].pubkey_package.verifying_key().serialize();
        for result in &results {
            assert_eq!(result.pubkey_package.verifying_key().serialize(), first);
        }

        let signers: Vec<&DkgResult> = results.iter().take(min_signers).collect();
        let signature = sign(&signers, b"msg").expect("signing failed");
        assert!(
            results[0]
                .pubkey_package
                .verifying_key()
                .verify(b"msg", &signature)
                .is_ok()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_runner_steps_over_iroh() {
    let consortium = Consortium::new(4).await.expect("consortium failed");
    let net = consortium.iroh_net().await;
    let member_count = consortium.participants.len();
    let min_signers = consortium.sessions[0].1.min_signers;
    let session_id = consortium.session_id;

    let mut handles = Vec::new();
    for (index, member) in consortium.participants.iter().cloned().enumerate() {
        let participants = consortium.participants.clone();
        let transport = net.transport(index, session_id);

        handles.push(spawn("iroh_dkg_transport", async move {
            let runner = DkgRunner::new(transport);

            let (round1_secret_package, package) = runner
                .start_round1(&member, member_count as u16, min_signers)
                .expect("start round1 failed");
            let round1_packages = runner
                .exchange_round1(&session_id, &member, &participants, package)
                .await
                .expect("round1 failed");
            let round1 = DkgRound1 {
                round1_packages,
                round1_secret_package,
            };
            // a package from every other participant, not from the member itself
            assert_eq!(round1.round1_packages.len(), member_count - 1);
            assert!(!round1.round1_packages.contains_key(&member.identifier));

            let round2 = runner
                .run_round2(
                    &session_id,
                    &participants,
                    &member,
                    round1.round1_secret_package,
                    &round1.round1_packages,
                )
                .await
                .expect("round2 failed");
            assert_eq!(round2.round2_received.len(), member_count - 1);
            assert!(!round2.round2_received.contains_key(&member.identifier));

            runner
                .finalize(
                    &round1.round1_packages,
                    &round2.round2_secret_package,
                    &round2.round2_received,
                )
                .expect("finalize failed")
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.expect("task panicked"));
    }

    let group_key = results[0].pubkey_package.verifying_key();
    for result in &results {
        assert_eq!(
            result.pubkey_package.verifying_key().serialize(),
            group_key.serialize()
        );
    }

    let signers: Vec<&DkgResult> = results.iter().take(min_signers as usize).collect();
    let signature = sign(&signers, b"msg").expect("signing failed");
    assert!(group_key.verify(b"msg", &signature).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_early_round2_package_survives_timed_out_attempt() {
    let consortium = Consortium::new(3).await.expect("consortium failed");
    let net = consortium.iroh_net().await;
    let session_id = consortium.session_id;
    let participants = consortium.participants.clone();
    let local_member = participants[0].clone();

    let expected: Vec<Identifier> = participants
        .iter()
        .map(|participant| participant.identifier)
        .collect();
    let (_, record) = consortium.sessions[0].clone();

    let transport = Arc::new(net.transport(0, session_id));
    let other_transports: Vec<IrohDkgTransport> = (1..3)
        .map(|index| net.transport(index, session_id))
        .collect();
    let other_sessions = consortium.sessions[1..].to_vec();

    let runner = DkgRunner::new(transport.clone());
    let (secret, package) = runner
        .start_round1(&local_member, record.max_signers, record.min_signers)
        .expect("start round1 failed");

    transport
        .broadcast_round1(&session_id, &local_member.identifier, package.clone())
        .await
        .expect("broadcast failed");
    let first = transport
        .recv_round1_all(
            &session_id,
            &local_member.identifier,
            &expected,
            Duration::from_millis(100),
        )
        .await;
    assert!(matches!(first, Err(TransportError::TimeoutError)));

    // the others run the whole dkg and send their round 2 packages while the
    // local member is still not done with round 1
    let mut handles = Vec::new();
    for ((db, record), transport) in other_sessions.into_iter().zip(other_transports) {
        handles.push(spawn("iroh_transport_dkg", async move {
            record
                .run(&db, transport, &StateKey::new(&DKG_STATE_KEY))
                .await
                .expect("dkg failed")
        }));
    }
    sleep(Duration::from_secs(1)).await;

    // second attempt with the same transport: the early round 2 packages must
    // still be there
    let round1_packages = runner
        .exchange_round1(&session_id, &local_member, &participants, package)
        .await
        .expect("round1 retry failed");
    let round2 = runner
        .run_round2(
            &session_id,
            &participants,
            &local_member,
            secret,
            &round1_packages,
        )
        .await
        .expect("round2 failed");
    let local_result = runner
        .finalize(
            &round1_packages,
            &round2.round2_secret_package,
            &round2.round2_received,
        )
        .expect("finalize failed");

    let group_key = local_result.pubkey_package.verifying_key().serialize();
    for handle in handles {
        let result = handle.await.expect("task panicked");
        assert_eq!(result.pubkey_package.verifying_key().serialize(), group_key);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_session_restarts_after_failed_run() {
    let consortium = Consortium::new(3).await.expect("consortium failed");
    let net = consortium.iroh_net().await;
    let session_id = consortium.session_id;

    let (db, record) = consortium.sessions[0].clone();
    let transport = Arc::new(net.transport(0, session_id));
    let other_transports: Vec<IrohDkgTransport> = (1..3)
        .map(|index| net.transport(index, session_id))
        .collect();
    let other_sessions = consortium.sessions[1..].to_vec();

    // nobody else is running, so this run cannot finish and gets cut off
    let first = timeout(
        Duration::from_secs(1),
        record.run(&db, transport.clone(), &StateKey::new(&DKG_STATE_KEY)),
    )
    .await;
    assert!(first.is_err(), "run must not finish alone");
    assert!(
        FrostDkgSessionRecord::load_dkg_result(&db, session_id, &StateKey::new(&DKG_STATE_KEY))
            .await
            .is_err()
    );

    // the others start, and the first member runs again from the saved state
    // with the same transport
    let mut handles = Vec::new();
    for ((db, record), transport) in other_sessions.into_iter().zip(other_transports) {
        handles.push(spawn("iroh_transport_dkg", async move {
            record
                .run(&db, transport, &StateKey::new(&DKG_STATE_KEY))
                .await
                .expect("dkg failed")
        }));
    }

    let first_member = record
        .run(&db, transport, &StateKey::new(&DKG_STATE_KEY))
        .await
        .expect("second run failed");

    let group_key = first_member.pubkey_package.verifying_key().serialize();
    for handle in handles {
        let result = handle.await.expect("task panicked");
        assert_eq!(result.pubkey_package.verifying_key().serialize(), group_key);
    }

    // the finished key is stored
    let loaded =
        FrostDkgSessionRecord::load_dkg_result(&db, session_id, &StateKey::new(&DKG_STATE_KEY))
            .await
            .expect("key must be saved");
    assert_eq!(loaded.pubkey_package.verifying_key().serialize(), group_key);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_iroh_frames_carry_the_authenticated_sender() {
    let session_id = SessionId([5; 32]);
    let ids: Vec<Identifier> = create_frost_participant(2)
        .iter()
        .map(|member| member.identifier)
        .collect();
    let net = bind_iroh_net(&ids).await;
    let sender = net.transport(0, session_id);
    let receiver = net.transport(1, session_id);

    // the sender lies about who it is, the receiver goes by the connection
    let claimed = Identifier::derive(b"somebody else").expect("identifier");
    sender
        .send(&claimed, &ids[1], b"hello".to_vec())
        .await
        .expect("send");

    let (from, payload) = receiver
        .recv(&ids[1], Duration::from_secs(5))
        .await
        .expect("the frame must arrive");
    assert_eq!(from, ids[0]);
    assert_eq!(payload, b"hello".to_vec());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_iroh_ignores_frames_from_unknown_nodes() {
    let session_id = SessionId([6; 32]);
    let ids: Vec<Identifier> = create_frost_participant(3)
        .iter()
        .map(|member| member.identifier)
        .collect();
    let net = bind_iroh_net(&ids).await;

    let receiver = net.transport_knowing(0, session_id, &[0, 1]);
    let member = net.transport_knowing(1, session_id, &[0, 1]);
    let outsider = net.transport_knowing(2, session_id, &[0]);

    let _ = outsider.send(&ids[2], &ids[0], b"let me in".to_vec()).await;
    member
        .send(&ids[1], &ids[0], b"known member".to_vec())
        .await
        .expect("send");

    let (from, payload) = receiver
        .recv(&ids[0], Duration::from_secs(5))
        .await
        .expect("the frame of the member must arrive");
    assert_eq!(from, ids[1]);
    assert_eq!(payload, b"known member".to_vec());

    // nothing from the outsider is waiting behind it
    let nothing_else = receiver.recv(&ids[0], Duration::from_secs(1)).await;
    assert!(matches!(nothing_else, Err(TransportError::TimeoutError)));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_iroh_ignores_frames_of_another_session() {
    let session_id = SessionId([7; 32]);
    let ids: Vec<Identifier> = create_frost_participant(3)
        .iter()
        .map(|member| member.identifier)
        .collect();
    let net = bind_iroh_net(&ids).await;

    let receiver = net.transport(0, session_id);
    let other_session = net.transport(1, SessionId([8; 32]));
    let same_session = net.transport(2, session_id);

    let _ = other_session
        .send(&ids[1], &ids[0], b"other session".to_vec())
        .await;
    same_session
        .send(&ids[2], &ids[0], b"same session".to_vec())
        .await
        .expect("send");

    let (from, payload) = receiver
        .recv(&ids[0], Duration::from_secs(5))
        .await
        .expect("the frame of the same session must arrive");
    assert_eq!(from, ids[2]);
    assert_eq!(payload, b"same session".to_vec());

    let nothing_else = receiver.recv(&ids[0], Duration::from_secs(1)).await;
    assert!(matches!(nothing_else, Err(TransportError::TimeoutError)));
}

#[tokio::test]
async fn test_file_transport_delivers_frames_in_the_order_they_were_sent() {
    let session_id = SessionId(rand::random());
    let ids: Vec<Identifier> = create_frost_participant(2)
        .iter()
        .map(|member| member.identifier)
        .collect();
    let (sender, receiver) = (ids[0], ids[1]);
    let transport = FileTransport::new(&session_id)
        .await
        .expect("transport init");

    for number in 0..5u8 {
        transport
            .send(&sender, &receiver, vec![number])
            .await
            .expect("send");
    }
    for number in 0..5u8 {
        let (from, payload) = transport
            .recv(&receiver, Duration::from_secs(2))
            .await
            .expect("recv");
        assert_eq!(from, sender);
        assert_eq!(payload, vec![number]);
    }

    let nothing_left = transport.recv(&receiver, Duration::from_millis(300)).await;
    assert!(matches!(nothing_left, Err(TransportError::TimeoutError)));

    transport.remove_data().await.expect("cleanup");
}

#[tokio::test]
async fn test_file_transport_refuses_another_session() {
    let session_id = SessionId(rand::random());
    let other_session_id = SessionId(rand::random());
    let transport = FileTransport::new(&session_id)
        .await
        .expect("transport init");

    let member = create_frost_participant(1).remove(0);
    let (_secret, package) =
        frost_secp256k1_tr::keys::dkg::part1(member.identifier, 3, 3, OsRng).expect("round 1");

    let result = transport
        .broadcast_round1(&other_session_id, &member.identifier, package)
        .await;
    assert!(matches!(
        result,
        Err(TransportError::SessionMismatch { .. })
    ));

    transport.remove_data().await.expect("cleanup");
}

#[tokio::test]
async fn test_file_transport_removes_all_its_data() {
    let session_id = SessionId(rand::random());
    let ids: Vec<Identifier> = create_frost_participant(2)
        .iter()
        .map(|member| member.identifier)
        .collect();
    let transport = FileTransport::new(&session_id)
        .await
        .expect("transport init");

    transport
        .send(&ids[0], &ids[1], b"hello".to_vec())
        .await
        .expect("send");
    transport.remove_data().await.expect("cleanup");

    assert!(!FileTransport::file_transport_root(&session_id).exists());
    let nothing_left = transport.recv(&ids[1], Duration::from_millis(300)).await;
    assert!(matches!(nothing_left, Err(TransportError::TimeoutError)));

    // removing what is already gone is fine
    transport.remove_data().await.expect("second cleanup");
}

// frost_signing tests

type Frame = (Identifier, Vec<u8>);

/// In-memory transport: every arbiter has an inbox, send puts a message in the
/// inbox of the receiver.
struct Loopback {
    peers: Arc<HashMap<Identifier, tokio::sync::mpsc::UnboundedSender<Frame>>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Frame>>,
}

#[async_trait::async_trait]
impl SigningTransport for Loopback {
    async fn send(
        &self,
        sender: &Identifier,
        receiver: &Identifier,
        payload: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.peers
            .get(receiver)
            .ok_or(TransportError::InvalidReceiver)?
            .send((*sender, payload))
            .map_err(|_| TransportError::InvalidReceiver)
    }
    async fn recv(&self, _: &Identifier, limit: Duration) -> Result<Frame, TransportError> {
        match timeout(limit, self.rx.lock().await.recv()).await {
            Ok(Some(frame)) => Ok(frame),
            _ => Err(TransportError::TimeoutError),
        }
    }
}

fn loopback_transports(ids: &[Identifier]) -> Vec<Loopback> {
    let mut senders = HashMap::new();
    let mut receivers = Vec::new();
    for id in ids {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        senders.insert(*id, sender);
        receivers.push(receiver);
    }
    let peers = Arc::new(senders);

    receivers
        .into_iter()
        .map(|receiver| Loopback {
            peers: peers.clone(),
            rx: tokio::sync::Mutex::new(receiver),
        })
        .collect()
}

/// Every transport that carries signing frames
trait TestTransport: SigningTransport + Send + Sync + 'static {}
impl<T: SigningTransport + Send + Sync + 'static> TestTransport for T {}

/// The keys of a consortium that finished a real DKG
struct ConsortiumKeys {
    session_id: SessionId,
    ids: Vec<Identifier>,
    key_packages: Vec<KeyPackage>,
    pubkey_package: PublicKeyPackage,
}

impl ConsortiumKeys {
    async fn generate(size: usize) -> Self {
        let consortium = Consortium::new(size).await.expect("consortium failed");
        let session_id = consortium.session_id;
        let results = consortium.run().await;

        // the dkg leaves the round 2 secret shares in the scratch directory
        FileTransport::new(&session_id)
            .await
            .expect("transport init")
            .remove_data()
            .await
            .expect("cleanup");

        let ids = results
            .iter()
            .map(|result| *result.key_package.identifier())
            .collect();
        let pubkey_package = results[0].pubkey_package.clone();
        let key_packages = results
            .into_iter()
            .map(|result| result.key_package)
            .collect();

        Self {
            session_id,
            ids,
            key_packages,
            pubkey_package,
        }
    }
}

struct Arbiter<T: TestTransport> {
    id: Identifier,
    key_package: KeyPackage,
    transport: Arc<T>,
    mux: Arc<SigningMux<T>>,
}

impl<T: TestTransport> Clone for Arbiter<T> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            key_package: self.key_package.clone(),
            transport: self.transport.clone(),
            mux: self.mux.clone(),
        }
    }
}

struct Cluster<T: TestTransport> {
    pubkey_package: PublicKeyPackage,
    arbiters: Vec<Arbiter<T>>,
}

impl<T: TestTransport> Cluster<T> {
    fn new(keys: ConsortiumKeys, transports: Vec<T>) -> Self {
        let ConsortiumKeys {
            ids,
            key_packages,
            pubkey_package,
            ..
        } = keys;
        let participants: Vec<FrostParticipant> = ids
            .iter()
            .map(|id| FrostParticipant { identifier: *id })
            .collect();

        let arbiters = participants
            .iter()
            .zip(key_packages)
            .zip(transports)
            .map(|((participant, key_package), transport)| {
                let transport = Arc::new(transport);
                Arbiter {
                    id: participant.identifier,
                    key_package,
                    mux: SigningMux::start(transport.clone(), participant, &participants),
                    transport,
                }
            })
            .collect();

        Self {
            pubkey_package,
            arbiters,
        }
    }
}

impl Cluster<Loopback> {
    async fn loopback(size: usize) -> Self {
        let keys = ConsortiumKeys::generate(size).await;
        let transports = loopback_transports(&keys.ids);
        Self::new(keys, transports)
    }
}

impl Cluster<IrohDkgTransport> {
    async fn iroh(size: usize) -> Self {
        let keys = ConsortiumKeys::generate(size).await;
        let net = bind_iroh_net(&keys.ids).await;
        let transports: Vec<IrohDkgTransport> = (0..size)
            .map(|index| net.transport(index, keys.session_id))
            .collect();
        Self::new(keys, transports)
    }
}

impl Cluster<FileTransport> {
    async fn files(size: usize) -> Self {
        let keys = ConsortiumKeys::generate(size).await;
        let mut transports = Vec::new();
        for _ in 0..size {
            transports.push(
                FileTransport::new(&keys.session_id)
                    .await
                    .expect("transport init"),
            );
        }
        Self::new(keys, transports)
    }
}

const SIZE: usize = 4;
const TIMEOUT: Duration = Duration::from_secs(15);
const ESCROW: EscrowId = EscrowId([7; 32]);
const CONTRACT_HASH: ContractHash = ContractHash([9; 32]);

/// The message the federation checks for a ruling on `escrow_id`
fn decision_hash(escrow_id: EscrowId, outcome: Outcome) -> [u8; 32] {
    compute_escrow_message(&EscrowMessage::Resolution {
        escrow_id,
        federation_id: dummy_federation_id(),
        outcome,
        contract_hash: CONTRACT_HASH,
    })
}

fn hash_for(escrow_id: EscrowId) -> impl Fn(Outcome) -> [u8; 32] + Send + 'static {
    move |outcome| decision_hash(escrow_id, outcome)
}

/// What the federation does with a signature: a BIP340 check against the
/// consortium key
fn is_valid_decision(
    pubkey_package: &PublicKeyPackage,
    escrow_id: EscrowId,
    outcome: Outcome,
    signature: &schnorr::Signature,
) -> bool {
    let consortium_key =
        FrostDkgSessionRecord::consortium_pubkey(pubkey_package).expect("consortium key");
    let digest = Message::from_digest(decision_hash(escrow_id, outcome));
    secp256k1::global::SECP256K1
        .verify_schnorr(signature, &digest, &consortium_key.x_only_public_key().0)
        .is_ok()
}

/// Starts the listed arbiters as signers behind the coordinator
fn start_signers<T: TestTransport>(
    cluster: &Cluster<T>,
    coordinator: usize,
    votes: &[(usize, Outcome)],
    escrow_id: EscrowId,
    time_limit: Duration,
) -> Vec<JoinHandle<Result<SignerOutcome, SigningError>>> {
    let coordinator_id = cluster.arbiters[coordinator].id;

    votes
        .iter()
        .map(|(position, outcome)| {
            let arbiter = cluster.arbiters[*position].clone();
            let outcome = *outcome;
            spawn("arbiter_signer", async move {
                sign_as_signer(
                    &arbiter.mux,
                    &coordinator_id,
                    &arbiter.key_package,
                    escrow_id,
                    outcome,
                    hash_for(escrow_id),
                    time_limit,
                )
                .await
            })
        })
        .collect()
}

async fn coordinate<T: TestTransport>(
    cluster: &Cluster<T>,
    position: usize,
    escrow_id: EscrowId,
    outcome: Outcome,
    time_limit: Duration,
) -> Result<(Outcome, schnorr::Signature), SigningError> {
    let arbiter = &cluster.arbiters[position];
    sign_as_coordinator(
        &arbiter.mux,
        &arbiter.key_package,
        &cluster.pubkey_package,
        escrow_id,
        outcome,
        hash_for(escrow_id),
        time_limit,
    )
    .await
}

/// The decision a signer ended with, which must be a final one
fn finished(result: Result<SignerOutcome, SigningError>) -> (Outcome, schnorr::Signature) {
    match result.expect("signer failed") {
        SignerOutcome::Final { outcome, signature } => (outcome, signature),
        SignerOutcome::ShareSent => panic!("expected the final result"),
    }
}

/// Waits for the start of the next slot and returns its number
async fn wait_for_next_slot(slot: Duration) -> u64 {
    let slot_secs = slot.as_secs();
    let now_secs = duration_since_epoch().as_secs();
    let next_slot = now_secs / slot_secs + 1;
    sleep(Duration::from_secs(next_slot * slot_secs - now_secs)).await;
    next_slot
}

async fn majority_outcome_is_signed_and_shared<T: TestTransport>(cluster: Cluster<T>) {
    // arbiter 0 coordinates, 1 and 2 agree with it, 3 disagrees
    let votes = [
        (1, Outcome::Release),
        (2, Outcome::Release),
        (3, Outcome::Refund),
    ];
    let signers = start_signers(&cluster, 0, &votes, ESCROW, TIMEOUT);

    let (outcome, signature) = coordinate(&cluster, 0, ESCROW, Outcome::Release, TIMEOUT)
        .await
        .expect("signing failed");
    assert_eq!(outcome, Outcome::Release);

    // the signature is a plain BIP340 signature of the consortium key
    assert!(is_valid_decision(
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Release,
        &signature
    ));
    assert!(!is_valid_decision(
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Refund,
        &signature
    ));

    // every arbiter ends with the same result, also the one that disagreed
    for signer in signers {
        let (received_outcome, received_signature) = finished(signer.await.expect("task panicked"));
        assert_eq!(received_outcome, Outcome::Release);
        assert_eq!(received_signature, signature);
    }
}

async fn junk_frames_do_not_stop_signing<T: TestTransport>(cluster: Cluster<T>) {
    let coordinator = &cluster.arbiters[0];
    let outsider = Identifier::derive(b"outsider").expect("identifier");
    let oversized = vec![0xAB; 100 * 1024];

    let junk_frames = [
        b"not json at all".to_vec(),
        br#"{"escrow_id": 7}"#.to_vec(),
        oversized,
    ];
    for junk in junk_frames {
        // junk from a member, and junk from somebody who is not in the consortium
        cluster.arbiters[1]
            .transport
            .send(&cluster.arbiters[1].id, &coordinator.id, junk.clone())
            .await
            .expect("send");
        cluster.arbiters[2]
            .transport
            .send(&outsider, &coordinator.id, junk)
            .await
            .expect("send");
    }

    majority_outcome_is_signed_and_shared(cluster).await;
}

/// The arbiter that would coordinate the first slot never answers
async fn signing_continues_past_an_unresponsive_coordinator<T: TestTransport>(cluster: Cluster<T>) {
    let slot = Duration::from_secs(6);
    let participants: BTreeSet<Identifier> =
        cluster.arbiters.iter().map(|arbiter| arbiter.id).collect();

    // start at the beginning of a slot so the first slot is used in full
    let slot_number = wait_for_next_slot(slot).await;
    let silent = coordinator_for_slot(&participants, &ESCROW, slot_number);

    let tasks: Vec<_> = cluster
        .arbiters
        .iter()
        .filter(|arbiter| arbiter.id != silent)
        .map(|arbiter| {
            let arbiter = arbiter.clone();
            let pubkey_package = cluster.pubkey_package.clone();

            spawn("arbiter", async move {
                sign_with_failover(
                    &arbiter.mux,
                    &arbiter.key_package,
                    &pubkey_package,
                    ESCROW,
                    Outcome::Release,
                    hash_for(ESCROW),
                    slot,
                    Duration::from_secs(60),
                )
                .await
            })
        })
        .collect();
    assert_eq!(tasks.len(), SIZE - 1);

    let mut signatures = Vec::new();
    for task in tasks {
        let (outcome, signature) = task.await.expect("task panicked").expect("signing failed");
        assert_eq!(outcome, Outcome::Release);
        assert!(is_valid_decision(
            &cluster.pubkey_package,
            ESCROW,
            Outcome::Release,
            &signature
        ));
        signatures.push(signature);
    }
    assert!(signatures.windows(2).all(|pair| pair[0] == pair[1]));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_majority_is_signed_over_loopback() {
    majority_outcome_is_signed_and_shared(Cluster::loopback(SIZE).await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_majority_is_signed_over_iroh() {
    majority_outcome_is_signed_and_shared(Cluster::iroh(SIZE).await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_majority_is_signed_over_files() {
    majority_outcome_is_signed_and_shared(Cluster::files(SIZE).await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_junk_frames_are_ignored_over_loopback() {
    junk_frames_do_not_stop_signing(Cluster::loopback(SIZE).await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_junk_frames_are_ignored_over_iroh() {
    junk_frames_do_not_stop_signing(Cluster::iroh(SIZE).await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_junk_frames_are_ignored_over_files() {
    junk_frames_do_not_stop_signing(Cluster::files(SIZE).await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_failover_over_loopback() {
    signing_continues_past_an_unresponsive_coordinator(Cluster::loopback(SIZE).await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_failover_over_iroh() {
    signing_continues_past_an_unresponsive_coordinator(Cluster::iroh(SIZE).await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_no_outcome_with_enough_votes() {
    let cluster = Cluster::loopback(SIZE).await;
    let short = Duration::from_secs(2);

    // 2 votes for Release (with the coordinator) and 2 for Refund
    let votes = [
        (1, Outcome::Release),
        (2, Outcome::Refund),
        (3, Outcome::Refund),
    ];
    start_signers(&cluster, 0, &votes, ESCROW, short);

    let result = coordinate(&cluster, 0, ESCROW, Outcome::Release, short).await;
    assert!(matches!(result, Err(SigningError::NoQuorum)));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signing_can_be_retried_after_no_quorum() {
    let cluster = Cluster::loopback(SIZE).await;
    let short = Duration::from_secs(2);

    // first attempt: the arbiters are split 2 against 2
    let split_votes = [
        (1, Outcome::Release),
        (2, Outcome::Refund),
        (3, Outcome::Refund),
    ];
    let first_signers = start_signers(&cluster, 0, &split_votes, ESCROW, short);
    let first = coordinate(&cluster, 0, ESCROW, Outcome::Release, short).await;
    assert!(matches!(first, Err(SigningError::NoQuorum)));
    for signer in first_signers {
        let _ = signer.await;
    }

    // after talking it over everybody agrees
    let agreed_votes = [
        (1, Outcome::Release),
        (2, Outcome::Release),
        (3, Outcome::Release),
    ];
    let second_signers = start_signers(&cluster, 0, &agreed_votes, ESCROW, TIMEOUT);
    let (outcome, signature) = coordinate(&cluster, 0, ESCROW, Outcome::Release, TIMEOUT)
        .await
        .expect("second attempt failed");

    assert_eq!(outcome, Outcome::Release);
    assert!(is_valid_decision(
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Release,
        &signature
    ));
    for signer in second_signers {
        finished(signer.await.expect("task panicked"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_old_votes_are_ignored() {
    let cluster = Cluster::loopback(SIZE).await;

    // three arbiters vote, but their vote is only good for a second
    let votes = [
        (1, Outcome::Release),
        (2, Outcome::Release),
        (3, Outcome::Release),
    ];
    let signers = start_signers(&cluster, 0, &votes, ESCROW, Duration::from_secs(1));
    for signer in signers {
        let _ = signer.await;
    }
    sleep(Duration::from_secs(1)).await;

    // the coordinator only looks at the votes after they expired
    let result = coordinate(
        &cluster,
        0,
        ESCROW,
        Outcome::Release,
        Duration::from_secs(2),
    )
    .await;
    assert!(matches!(result, Err(SigningError::NoQuorum)));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiters_acting_at_different_times_still_reach_a_decision() {
    let cluster = Cluster::loopback(SIZE).await;
    let coordinator_id = cluster.arbiters[0].id;

    // every arbiter acts a little later than the one before
    let mut signers = Vec::new();
    for position in 1..SIZE {
        let arbiter = cluster.arbiters[position].clone();
        signers.push(spawn("late_signer", async move {
            sleep(Duration::from_secs(position as u64)).await;
            sign_as_signer(
                &arbiter.mux,
                &coordinator_id,
                &arbiter.key_package,
                ESCROW,
                Outcome::Release,
                hash_for(ESCROW),
                TIMEOUT,
            )
            .await
        }));
    }

    let (outcome, signature) = coordinate(&cluster, 0, ESCROW, Outcome::Release, TIMEOUT)
        .await
        .expect("signing failed");
    assert_eq!(outcome, Outcome::Release);
    assert!(is_valid_decision(
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Release,
        &signature
    ));

    // the last arbiter votes after the decision is already made and still gets it
    for signer in signers {
        let (received_outcome, received_signature) = finished(signer.await.expect("task panicked"));
        assert_eq!(received_outcome, Outcome::Release);
        assert_eq!(received_signature, signature);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_one_offline_arbiter_is_tolerated() {
    let cluster = Cluster::loopback(SIZE).await;

    // arbiter 3 never shows up, the other three are enough
    let votes = [(1, Outcome::Release), (2, Outcome::Release)];
    let signers = start_signers(&cluster, 0, &votes, ESCROW, TIMEOUT);

    let (outcome, signature) = coordinate(&cluster, 0, ESCROW, Outcome::Release, TIMEOUT)
        .await
        .expect("signing failed");

    assert_eq!(outcome, Outcome::Release);
    assert!(is_valid_decision(
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Release,
        &signature
    ));
    for signer in signers {
        finished(signer.await.expect("task panicked"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_too_many_offline_arbiters_stop_the_consortium() {
    let cluster = Cluster::loopback(SIZE).await;
    let short = Duration::from_secs(2);

    // only the coordinator and one more arbiter are there, 3 are needed
    start_signers(&cluster, 0, &[(1, Outcome::Release)], ESCROW, short);

    let result = coordinate(&cluster, 0, ESCROW, Outcome::Release, short).await;
    assert!(matches!(result, Err(SigningError::NoQuorum)));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_large_consortium_signs_with_two_arbiters_offline() {
    // 7 arbiters need 5 signers, arbiters 5 and 6 are offline
    let cluster = Cluster::loopback(7).await;
    let votes: Vec<(usize, Outcome)> = (1..5).map(|position| (position, Outcome::Refund)).collect();
    let signers = start_signers(&cluster, 0, &votes, ESCROW, TIMEOUT);

    let (outcome, signature) = coordinate(&cluster, 0, ESCROW, Outcome::Refund, TIMEOUT)
        .await
        .expect("signing failed");

    assert_eq!(outcome, Outcome::Refund);
    assert!(is_valid_decision(
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Refund,
        &signature
    ));
    for signer in signers {
        finished(signer.await.expect("task panicked"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signer_that_vanishes_after_voting_is_named_and_a_retry_works() {
    let cluster = Cluster::loopback(SIZE).await;
    let vanishing = 1;
    let short = Duration::from_secs(3);

    // arbiter 1 votes first and then its process dies
    let dying = start_signers(
        &cluster,
        0,
        &[(vanishing, Outcome::Release)],
        ESCROW,
        TIMEOUT,
    )
    .remove(0);
    sleep(Duration::from_millis(500)).await;
    dying.abort();

    let others = start_signers(
        &cluster,
        0,
        &[(2, Outcome::Release), (3, Outcome::Release)],
        ESCROW,
        short,
    );
    let result = coordinate(&cluster, 0, ESCROW, Outcome::Release, short).await;
    match result {
        Err(SigningError::MissingShares(missing)) => {
            assert_eq!(missing, vec![cluster.arbiters[vanishing].id]);
        }
        other => panic!("expected MissingShares, got {other:?}"),
    }
    for signer in others {
        let _ = signer.await;
    }

    // the three arbiters that are left sign it in a new attempt
    let retry_signers = start_signers(
        &cluster,
        0,
        &[(2, Outcome::Release), (3, Outcome::Release)],
        ESCROW,
        TIMEOUT,
    );
    let (outcome, signature) = coordinate(&cluster, 0, ESCROW, Outcome::Release, TIMEOUT)
        .await
        .expect("retry failed");

    assert_eq!(outcome, Outcome::Release);
    assert!(is_valid_decision(
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Release,
        &signature
    ));
    for signer in retry_signers {
        finished(signer.await.expect("task panicked"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signer_does_not_sign_what_it_did_not_vote_for() {
    let cluster = Cluster::loopback(SIZE).await;
    let votes = [
        (1, Outcome::Release),
        (2, Outcome::Release),
        (3, Outcome::Release),
    ];
    let signers = start_signers(&cluster, 0, &votes, ESCROW, Duration::from_secs(3));

    // a coordinator with another view of the contract
    let coordinator = &cluster.arbiters[0];
    let result = sign_as_coordinator(
        &coordinator.mux,
        &coordinator.key_package,
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Release,
        |_| [0xEE; 32],
        Duration::from_secs(3),
    )
    .await;
    assert!(matches!(result, Err(SigningError::MissingShares(_))));

    // the two arbiters picked to sign refuse
    let mut mismatches = 0;
    for signer in signers {
        if matches!(
            signer.await.expect("task panicked"),
            Err(SigningError::MessageMismatch)
        ) {
            mismatches += 1;
        }
    }
    assert!(mismatches >= 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_split_that_does_not_add_up_is_refused() {
    let cluster = Cluster::loopback(SIZE).await;
    let bad_split = Outcome::Split {
        funder_split_bps: 9_000,
        recipient_split_bps: 2_000,
    };

    let as_signer = start_signers(&cluster, 0, &[(1, bad_split)], ESCROW, TIMEOUT)
        .remove(0)
        .await
        .expect("task panicked");
    assert!(matches!(as_signer, Err(SigningError::InvalidOutcome)));

    let as_coordinator = coordinate(&cluster, 0, ESCROW, bad_split, TIMEOUT).await;
    assert!(matches!(as_coordinator, Err(SigningError::InvalidOutcome)));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_forged_result_is_ignored() {
    let cluster = Cluster::loopback(SIZE).await;
    let votes = [
        (1, Outcome::Release),
        (2, Outcome::Release),
        (3, Outcome::Release),
    ];
    let signers = start_signers(&cluster, 0, &votes, ESCROW, TIMEOUT);

    // a member tells the other signers that the decision is Refund, with a
    // signature that is not one
    let forged = finished_frame(ESCROW, Outcome::Refund, vec![0x11; 64]);
    for target in [2, 3] {
        cluster.arbiters[1]
            .transport
            .send(
                &cluster.arbiters[1].id,
                &cluster.arbiters[target].id,
                forged.clone(),
            )
            .await
            .expect("send");
    }
    sleep(Duration::from_millis(300)).await;

    let (outcome, signature) = coordinate(&cluster, 0, ESCROW, Outcome::Release, TIMEOUT)
        .await
        .expect("signing failed");
    assert_eq!(outcome, Outcome::Release);

    // every signer ended with the real decision, not the forged one
    for signer in signers {
        let (received_outcome, received_signature) = finished(signer.await.expect("task panicked"));
        assert_eq!(received_outcome, Outcome::Release);
        assert_eq!(received_signature, signature);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_two_escrows_signed_at_once_stay_separate() {
    let cluster = Cluster::loopback(SIZE).await;
    let other_escrow = EscrowId([8; 32]);
    let votes = [
        (1, Outcome::Release),
        (2, Outcome::Release),
        (3, Outcome::Release),
    ];

    let mut signers = Vec::new();
    for escrow_id in [ESCROW, other_escrow] {
        signers.extend(start_signers(&cluster, 0, &votes, escrow_id, TIMEOUT));
    }
    let (first, second) = tokio::join!(
        coordinate(&cluster, 0, ESCROW, Outcome::Release, TIMEOUT),
        coordinate(&cluster, 0, other_escrow, Outcome::Release, TIMEOUT),
    );
    let (_, first_signature) = first.expect("first escrow failed");
    let (_, second_signature) = second.expect("second escrow failed");

    // each signature is good for its own escrow only
    let package = &cluster.pubkey_package;
    assert!(is_valid_decision(
        package,
        ESCROW,
        Outcome::Release,
        &first_signature
    ));
    assert!(!is_valid_decision(
        package,
        other_escrow,
        Outcome::Release,
        &first_signature
    ));
    assert!(is_valid_decision(
        package,
        other_escrow,
        Outcome::Release,
        &second_signature
    ));
    assert!(!is_valid_decision(
        package,
        ESCROW,
        Outcome::Release,
        &second_signature
    ));

    for signer in signers {
        finished(signer.await.expect("task panicked"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_every_arbiter_makes_the_same_call() {
    let cluster = Cluster::loopback(SIZE).await;

    let tasks: Vec<_> = cluster
        .arbiters
        .iter()
        .map(|arbiter| {
            let arbiter = arbiter.clone();
            let pubkey_package = cluster.pubkey_package.clone();

            spawn("arbiter", async move {
                sign_with_failover(
                    &arbiter.mux,
                    &arbiter.key_package,
                    &pubkey_package,
                    ESCROW,
                    Outcome::Release,
                    hash_for(ESCROW),
                    Duration::from_secs(8),
                    Duration::from_secs(40),
                )
                .await
            })
        })
        .collect();

    let mut signatures = Vec::new();
    for task in tasks {
        let (outcome, signature) = task.await.expect("task panicked").expect("signing failed");
        assert_eq!(outcome, Outcome::Release);
        signatures.push(signature);
    }
    assert!(signatures.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(is_valid_decision(
        &cluster.pubkey_package,
        ESCROW,
        Outcome::Release,
        &signatures[0]
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_the_same_escrow_is_not_signed_twice_on_one_node() {
    let cluster = Cluster::loopback(SIZE).await;
    let arbiter = cluster.arbiters[1].clone();
    let pubkey_package = cluster.pubkey_package.clone();

    // nobody else takes part, so this keeps trying until it is cancelled
    let first = spawn("first_signing", {
        let arbiter = arbiter.clone();
        let pubkey_package = pubkey_package.clone();
        async move {
            sign_with_failover(
                &arbiter.mux,
                &arbiter.key_package,
                &pubkey_package,
                ESCROW,
                Outcome::Release,
                hash_for(ESCROW),
                Duration::from_secs(6),
                Duration::from_secs(20),
            )
            .await
        }
    });
    sleep(Duration::from_millis(200)).await;
    assert!(arbiter.mux.has_active_escrows());

    let second = sign_with_failover(
        &arbiter.mux,
        &arbiter.key_package,
        &pubkey_package,
        ESCROW,
        Outcome::Release,
        hash_for(ESCROW),
        Duration::from_secs(6),
        Duration::from_secs(20),
    )
    .await;
    assert!(matches!(second, Err(SigningError::AlreadyInProgress)));

    // cancelling the first signing frees the escrow again
    first.abort();
    let _ = first.await;
    assert!(!arbiter.mux.has_active_escrows());
}

#[test]
fn test_coordinator_rotation_visits_every_arbiter() {
    let ids: BTreeSet<Identifier> = create_frost_participant(4)
        .iter()
        .map(|member| member.identifier)
        .collect();
    let escrow_id = EscrowId([3; 32]);

    // everybody gets a turn within one cycle
    let one_cycle: BTreeSet<Identifier> = (0..4)
        .map(|slot| coordinator_for_slot(&ids, &escrow_id, slot))
        .collect();
    assert_eq!(one_cycle, ids);

    // the cycle repeats and every arbiter computes the same answer
    assert_eq!(
        coordinator_for_slot(&ids, &escrow_id, 1),
        coordinator_for_slot(&ids, &escrow_id, 5)
    );
    assert_eq!(
        coordinator_for_slot(&ids, &escrow_id, 9),
        coordinator_for_slot(&ids, &escrow_id, 9)
    );

    // different escrows do not all start with the same arbiter
    let first_coordinators: BTreeSet<Identifier> = (0..64u8)
        .map(|byte| coordinator_for_slot(&ids, &EscrowId([byte; 32]), 0))
        .collect();
    assert!(first_coordinators.len() > 1);
}

#[test]
fn test_pick_outcome_needs_min_signers_votes() {
    let split = Outcome::Split {
        funder_split_bps: 5_000,
        recipient_split_bps: 5_000,
    };

    assert_eq!(pick_outcome(&[], 3), None);
    assert_eq!(
        pick_outcome(&[Outcome::Release, Outcome::Release, Outcome::Refund], 3),
        None
    );
    assert_eq!(
        pick_outcome(
            &[
                Outcome::Release,
                Outcome::Refund,
                Outcome::Release,
                Outcome::Release
            ],
            3
        ),
        Some(Outcome::Release)
    );
    assert_eq!(
        pick_outcome(&[split, split, split, Outcome::Refund], 3),
        Some(split)
    );
}

#[test]
fn test_pick_outcome_counts_different_splits_separately() {
    let even = Outcome::Split {
        funder_split_bps: 5_000,
        recipient_split_bps: 5_000,
    };
    let uneven = Outcome::Split {
        funder_split_bps: 4_000,
        recipient_split_bps: 6_000,
    };

    assert_eq!(pick_outcome(&[even, uneven, even], 3), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_consortium_decision_is_accepted_by_the_escrow_rules() {
    let cluster = Cluster::loopback(SIZE).await;

    // the key the funder puts in the contract as the arbiter key
    let consortium_key =
        FrostDkgSessionRecord::consortium_pubkey(&cluster.pubkey_package).expect("consortium key");

    let secp = Secp256k1::new();
    let funder_key = Keypair::new(&secp, &mut OsRng).public_key();
    let recipient_key = Keypair::new(&secp, &mut OsRng).public_key();
    let fee_key = Keypair::new(&secp, &mut OsRng).public_key();
    // same escrow id, federation id and contract hash as `decision_hash`
    let contract = EscrowContract {
        escrow_id: ESCROW,
        funder_key,
        recipient_key,
        arbiter_key: consortium_key,
        arbiter_fee_key: vec![fee_key],
        amount: Amount::from_sats(1000),
        arbiter_fee: Amount::from_sats(20),
        contract_hash: CONTRACT_HASH,
        timeout: 1_000,
        federation_id: dummy_federation_id(),
        status: EscrowStatus::Disputed {
            resolve_by: 5_000,
            swapped: false,
        },
        resolution_period: 3_600,
        default_fallback: FallbackPolicy::Refund,
    };

    // the arbiters agree on a split
    let split = Outcome::Split {
        funder_split_bps: 2_500,
        recipient_split_bps: 7_500,
    };
    let votes = [(1, split), (2, split), (3, split)];
    let signers = start_signers(&cluster, 0, &votes, ESCROW, TIMEOUT);
    let (outcome, signature) = coordinate(&cluster, 0, ESCROW, split, TIMEOUT)
        .await
        .expect("signing failed");
    assert_eq!(outcome, split);
    for signer in signers {
        finished(signer.await.expect("task panicked"));
    }

    // the funder submits the signature
    let ruling = Resolution::ArbiterOutcome {
        arbiter_signature: signature,
        outcome: split,
        submitter_pubkey: funder_key,
    };
    let accepted = check_resolution(&contract, &ruling, 2_000).expect("ruling must be accepted");

    assert_eq!(accepted.transition, EscrowTransition::ArbiterOutcome(split));
    // 980 sats are left after the fee: 25% to the funder, the rest to the recipient
    assert_eq!(
        accepted.settlement,
        Settlement::WriteClaims(vec![
            (funder_key, Amount::from_sats(245)),
            (recipient_key, Amount::from_sats(735)),
            (fee_key, Amount::from_sats(20)),
        ])
    );

    // the same signature does not work for another outcome
    let tampered = Resolution::ArbiterOutcome {
        arbiter_signature: signature,
        outcome: Outcome::Release,
        submitter_pubkey: funder_key,
    };
    assert_eq!(
        check_resolution(&contract, &tampered, 2_000),
        Err(EscrowInputError::InvalidSignature)
    );
}
