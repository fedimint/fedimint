use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::runtime::{sleep, spawn, timeout};
use fedimint_core::secp256k1::{self, Keypair, Message, Secp256k1};
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

use crate::frost::dkg::{DkgResult, DkgRound1, DkgRunner};
use crate::frost::frost_sign::{
    SignerOutcome, SigningError, SigningMux, pick_outcome, sign_as_coordinator, sign_as_signer,
    sign_with_failover,
};
use crate::frost::session::{FrostDkgSessionRecord, FrostParticipant, SessionId};
use crate::frost::transport::file::FileTransport;
use crate::frost::transport::iroh::{DKG_ALPN, IrohDkgTransport};
use crate::frost::transport::{DkgTransport, SigningTransport, TransportError};

fn dummy_federation_id() -> FederationId {
    FederationId::dummy()
}

fn create_frost_participant(n: usize) -> Vec<FrostParticipant> {
    let secp = Secp256k1::new();
    (0..n)
        .map(|_| {
            let kp = Keypair::new(&secp, &mut OsRng);
            FrostParticipant::from_pubkey(kp.public_key()).expect("invalid identifier")
        })
        .collect()
}

struct IrohNet {
    endpoints: Vec<Endpoint>,
    peers: BTreeMap<Identifier, NodeAddr>,
}

impl IrohNet {
    fn transport(&self, i: usize, session_id: SessionId) -> IrohDkgTransport {
        IrohDkgTransport::from_endpoint(self.endpoints[i].clone(), session_id, self.peers.clone())
    }
}

struct Consortium {
    participants: Vec<FrostParticipant>,
    session_id: SessionId,
    sessions: Vec<(Database, FrostDkgSessionRecord)>,
}

impl Consortium {
    async fn new(n: usize) -> anyhow::Result<Self> {
        let federation_id = dummy_federation_id();

        let participants: Vec<FrostParticipant> = create_frost_participant(n);

        let mut sessions = Vec::with_capacity(n);

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

                record.run(&db, transport).await.expect("dkg failed")
            }));
        }

        let mut results = Vec::with_capacity(handles.len());

        for handle in handles {
            results.push(handle.await.expect("task panicked"));
        }

        results
    }

    async fn iroh_net(&self) -> IrohNet {
        let mut endpoints = Vec::new();
        let mut peers = BTreeMap::new();

        for participant in &self.participants {
            let endpoint = Endpoint::builder()
                .secret_key(SecretKey::from_bytes(&rand::random::<[u8; 32]>()))
                .alpns(vec![DKG_ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind()
                .await
                .expect("bind endpoint");

            peers.insert(
                participant.identifier,
                endpoint.node_addr().await.expect("node addr"),
            );
            endpoints.push(endpoint);
        }

        IrohNet { endpoints, peers }
    }

    async fn run_iroh(self) -> Vec<DkgResult> {
        let net = self.iroh_net().await;
        let mut handles = Vec::with_capacity(self.sessions.len());

        for (i, (db, record)) in self.sessions.into_iter().enumerate() {
            let transport = net.transport(i, self.session_id);

            handles.push(spawn("iroh_transport_dkg", async move {
                sleep(Duration::from_millis(200 * i as u64)).await;
                record.run(&db, transport).await.expect("dkg failed")
            }));
        }

        let mut results = Vec::with_capacity(handles.len());

        for handle in handles {
            results.push(handle.await.expect("task panicked"));
        }

        results
    }
}

fn sign(signers: &[&DkgResult], msg: &[u8]) -> Result<Signature, frost_secp256k1_tr::Error> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for s in signers {
        let id = *s.key_package.identifier();
        let (n, c) = Round1Commit(s.key_package.signing_share(), &mut OsRng);
        nonces.insert(id, n);
        commitments.insert(id, c);
    }

    let signing_package = SigningPackage::new(commitments, msg);

    let mut shares = BTreeMap::new();
    for s in signers {
        let id = *s.key_package.identifier();
        let share = Round2Sign(&signing_package, &nonces[&id], &s.key_package)?;
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
    for r in &results {
        let id = *r.key_package.identifier();
        assert_eq!(
            r.key_package.verifying_share(),
            r.pubkey_package.verifying_shares().get(&id).unwrap()
        );
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
    for n in [2, 3, 4, 5, 7] {
        let consortium = Consortium::new(n).await;

        if n == 2 {
            assert!(
                consortium.is_err(),
                "DKG setup should fail for {n} participants"
            );
            continue;
        }

        let consortium = consortium.expect("valid consortium");
        let results = consortium.run().await;

        assert_eq!(results.len(), n);

        let aggregate_key = results[0].pubkey_package.verifying_key().serialize();

        for result in &results[1..] {
            assert_eq!(
                result.pubkey_package.verifying_key().serialize(),
                aggregate_key,
                "DKG did not converge for n={n}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_signing_with_dkg_key() {
    let consortium = Consortium::new(5).await.expect("consortium failed");
    let min_signers = consortium.sessions[0].1.min_signers as usize;
    let results = consortium.run().await;
    let group_key = results[0].pubkey_package.verifying_key();
    let msg = b"release the funds";

    let signers: Vec<&DkgResult> = results.iter().take(min_signers).collect();
    let sig = sign(&signers, msg).expect("signing failed");

    assert!(group_key.verify(msg, &sig).is_ok());
    assert!(group_key.verify(b"refund", &sig).is_err());

    let signers: Vec<&DkgResult> = results.iter().take(min_signers - 1).collect();
    if let Ok(sig) = sign(&signers, msg) {
        assert!(group_key.verify(msg, &sig).is_err());
    }
}

#[tokio::test]
async fn test_invalid_participant_lists_rejected() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let federation_id = dummy_federation_id();

    for n in [1, 2] {
        let participants = create_frost_participant(n);
        let result =
            FrostDkgSessionRecord::new(participants[0].clone(), participants, federation_id, &db)
                .await;
        assert!(result.is_err(), "n={n} must be rejected");
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
async fn test_session_id_ignores_participant_order() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let participants = create_frost_participant(4);
    let mut reversed = participants.clone();
    reversed.reverse();

    let a = FrostDkgSessionRecord::new(
        participants[0].clone(),
        participants.clone(),
        dummy_federation_id(),
        &db,
    )
    .await
    .unwrap();

    let db2 = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let b = FrostDkgSessionRecord::new(
        participants[0].clone(),
        reversed,
        dummy_federation_id(),
        &db2,
    )
    .await
    .unwrap();

    assert_eq!(a.session_id, b.session_id);
}

#[tokio::test]
async fn test_threshold_values() {
    for (n, expected) in [(3, 3), (4, 3), (5, 4), (7, 5), (10, 7)] {
        let consortium = Consortium::new(n).await.unwrap();
        assert_eq!(consortium.sessions[0].1.min_signers, expected, "n={n}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_run_after_finish_returns_same_key() {
    let consortium = Consortium::new(3).await.unwrap();
    let (db, record) = consortium.sessions[0].clone();
    let session_id = consortium.session_id;
    let results = consortium.run().await;

    let transport = FileTransport::new(&session_id).await.unwrap();
    let again = record.run(&db, transport).await.expect("second run failed");

    assert_eq!(
        again.pubkey_package.verifying_key().serialize(),
        results[0].pubkey_package.verifying_key().serialize()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_over_iroh() {
    for n in [3, 4] {
        let consortium = Consortium::new(n).await.expect("consortium failed");
        let min_signers = consortium.sessions[0].1.min_signers as usize;
        let results = consortium.run_iroh().await;

        let first = results[0].pubkey_package.verifying_key().serialize();
        for result in &results {
            assert_eq!(result.pubkey_package.verifying_key().serialize(), first);
        }

        let signers: Vec<&DkgResult> = results.iter().take(min_signers).collect();
        let sig = sign(&signers, b"msg").expect("signing failed");
        assert!(
            results[0]
                .pubkey_package
                .verifying_key()
                .verify(b"msg", &sig)
                .is_ok()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_runner_steps_over_iroh() {
    let consortium = Consortium::new(4).await.expect("consortium failed");
    let net = consortium.iroh_net().await;
    let n = consortium.participants.len();
    let min_signers = consortium.sessions[0].1.min_signers;
    let session_id = consortium.session_id;

    let mut handles = Vec::new();
    for (i, me) in consortium.participants.iter().cloned().enumerate() {
        let participants = consortium.participants.clone();
        let transport = net.transport(i, session_id);

        handles.push(spawn("iroh_dkg_transport", async move {
            let runner = DkgRunner::new(transport);

            let (round1_secret_package, package) = runner
                .start_round1(&me, n as u16, min_signers)
                .expect("start round1 failed");
            let round1_packages = runner
                .exchange_round1(&session_id, &me, &participants, package)
                .await
                .expect("round1 failed");
            let round1 = DkgRound1 {
                round1_packages,
                round1_secret_package,
            };
            // a package from every other participant, not from self runner
            assert_eq!(round1.round1_packages.len(), n - 1);
            assert!(!round1.round1_packages.contains_key(&me.identifier));

            let round2 = runner
                .run_round2(
                    &session_id,
                    &participants,
                    &me,
                    round1.round1_secret_package,
                    &round1.round1_packages,
                )
                .await
                .expect("round2 failed");
            assert_eq!(round2.round2_received.len(), n - 1);
            assert!(!round2.round2_received.contains_key(&me.identifier));

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
    for r in &results {
        assert_eq!(
            r.pubkey_package.verifying_key().serialize(),
            group_key.serialize()
        );
    }

    let signers: Vec<&DkgResult> = results.iter().take(min_signers as usize).collect();
    let sig = sign(&signers, b"msg").expect("signing failed");
    assert!(group_key.verify(b"msg", &sig).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_early_round2_package_survives_timed_out_attempt() {
    let consortium = Consortium::new(3).await.expect("consortium failed");
    let net = consortium.iroh_net().await;
    let session_id = consortium.session_id;
    let participants = consortium.participants.clone();
    let me = participants[0].clone();
    let expected: Vec<Identifier> = participants.iter().map(|p| p.identifier).collect();
    let (_, record) = consortium.sessions[0].clone();

    let transport = Arc::new(net.transport(0, session_id));
    let other_transports: Vec<IrohDkgTransport> =
        (1..3).map(|i| net.transport(i, session_id)).collect();
    let other_sessions = consortium.sessions[1..].to_vec();

    let runner = DkgRunner::new(transport.clone());
    let (secret, package) = runner
        .start_round1(&me, record.max_signers, record.min_signers)
        .expect("start round1 failed");

    // first attempt: nobody else has started, so waiting for round 1 times out
    transport
        .broadcast_round1(&session_id, &me.identifier, package.clone())
        .await
        .expect("broadcast failed");
    let first = transport
        .recv_round1_all(
            &session_id,
            &me.identifier,
            &expected,
            Duration::from_millis(100),
        )
        .await;
    assert!(matches!(first, Err(TransportError::TimeoutError)));

    let mut handles = Vec::new();
    for ((db, record), transport) in other_sessions.into_iter().zip(other_transports) {
        handles.push(spawn("iroh_transport_dkg", async move {
            record.run(&db, transport).await.expect("dkg failed")
        }));
    }
    sleep(Duration::from_secs(1)).await;

    let round1_packages = runner
        .exchange_round1(&session_id, &me, &participants, package)
        .await
        .expect("round1 retry failed");
    let round2 = runner
        .run_round2(&session_id, &participants, &me, secret, &round1_packages)
        .await
        .expect("round2 failed");
    let mine = runner
        .finalize(
            &round1_packages,
            &round2.round2_secret_package,
            &round2.round2_received,
        )
        .expect("finalize failed");

    let group_key = mine.pubkey_package.verifying_key().serialize();
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
    let other_transports: Vec<IrohDkgTransport> =
        (1..3).map(|i| net.transport(i, session_id)).collect();
    let other_sessions = consortium.sessions[1..].to_vec();

    // nobody else is running, so this run cannot finish and gets cut off
    let first = timeout(Duration::from_secs(1), record.run(&db, transport.clone())).await;
    assert!(first.is_err(), "run must not finish alone");
    assert!(
        FrostDkgSessionRecord::load_dkg_result(&db, session_id)
            .await
            .is_err()
    );

    // the others start, and I run again from the saved state with the same
    // transport
    let mut handles = Vec::new();
    for ((db, record), transport) in other_sessions.into_iter().zip(other_transports) {
        handles.push(spawn("iroh_transport_dkg", async move {
            record.run(&db, transport).await.expect("dkg failed")
        }));
    }
    let mine = record.run(&db, transport).await.expect("second run failed");

    let group_key = mine.pubkey_package.verifying_key().serialize();
    for handle in handles {
        let result = handle.await.expect("task panicked");
        assert_eq!(result.pubkey_package.verifying_key().serialize(), group_key);
    }

    // the finished key is stored
    let loaded = FrostDkgSessionRecord::load_dkg_result(&db, session_id)
        .await
        .expect("key must be saved");
    assert_eq!(loaded.pubkey_package.verifying_key().serialize(), group_key);
}

// frost signing tests

type Frame = (Identifier, Vec<u8>);

/// In-memory transport: every arbiter has an inbox, send puts a message in the
/// inbox of the receiver.
struct Loopback {
    peers: Arc<HashMap<Identifier, tokio::sync::mpsc::UnboundedSender<Frame>>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Frame>>,
}

#[async_trait::async_trait]
impl SigningTransport for Loopback {
    async fn send(&self, s: &Identifier, r: &Identifier, p: Vec<u8>) -> Result<(), TransportError> {
        self.peers
            .get(r)
            .ok_or(TransportError::InvalidReceiver)?
            .send((*s, p))
            .map_err(|_| TransportError::InvalidReceiver)
    }
    async fn recv(&self, _: &Identifier, d: Duration) -> Result<Frame, TransportError> {
        match timeout(d, self.rx.lock().await.recv()).await {
            Ok(Some(f)) => Ok(f),
            _ => Err(TransportError::TimeoutError),
        }
    }
}

struct Cluster {
    ids: Vec<Identifier>,
    key_packages: Vec<KeyPackage>,
    pubkey_package: PublicKeyPackage,
    muxes: Vec<Arc<SigningMux<Loopback>>>,
}

impl Cluster {
    async fn new() -> Self {
        let consortium = Consortium::new(4).await.expect("consortium failed");
        let results = consortium.run().await;

        let ids: Vec<Identifier> = results
            .iter()
            .map(|r| *r.key_package.identifier())
            .collect();
        let key_packages: Vec<KeyPackage> = results.iter().map(|r| r.key_package.clone()).collect();
        let pubkey_package = results[0].pubkey_package.clone();

        let (mut senders, mut receivers) = (HashMap::new(), HashMap::new());
        for id in &ids {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            senders.insert(*id, tx);
            receivers.insert(*id, rx);
        }
        let peers = Arc::new(senders);
        let participants: Vec<FrostParticipant> = ids
            .iter()
            .map(|id| FrostParticipant { identifier: *id })
            .collect();
        let muxes = participants
            .iter()
            .map(|participant| {
                let transport = Arc::new(Loopback {
                    peers: peers.clone(),
                    rx: tokio::sync::Mutex::new(receivers.remove(&participant.identifier).unwrap()),
                });
                SigningMux::start(transport, participant, &participants)
            })
            .collect();

        Self {
            ids,
            key_packages,
            pubkey_package,
            muxes,
        }
    }
}

const TIMEOUT: Duration = Duration::from_secs(5);
const ESCROW: EscrowId = EscrowId([7; 32]);
const CONTRACT_HASH: ContractHash = ContractHash([9; 32]);

/// The message the federation checks, for the escrow used in these tests
fn decision_hash_for(outcome: Outcome) -> [u8; 32] {
    compute_escrow_message(&EscrowMessage::Resolution {
        escrow_id: ESCROW,
        federation_id: dummy_federation_id(),
        outcome,
        contract_hash: CONTRACT_HASH,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn majority_outcome_is_signed_and_everyone_gets_the_result() {
    let c = Cluster::new().await;
    let mut signers = vec![];
    for i in 1..4 {
        let (mux, key_package, coordinator) =
            (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
        // the last arbiter disagrees
        let vote = if i == 3 {
            Outcome::Refund
        } else {
            Outcome::Release
        };
        signers.push(spawn("test", async move {
            sign_as_signer(
                &mux,
                &coordinator,
                &key_package,
                ESCROW,
                vote,
                decision_hash_for,
                TIMEOUT,
            )
            .await
        }));
    }
    let (outcome, signature) = sign_as_coordinator(
        &c.muxes[0],
        &c.key_packages[0],
        &c.pubkey_package,
        ESCROW,
        Outcome::Release,
        decision_hash_for,
        TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Release);

    let consortium_key = FrostDkgSessionRecord::consortium_pubkey(&c.pubkey_package).unwrap();
    let digest = Message::from_digest(decision_hash_for(Outcome::Release));
    let x_only = consortium_key.x_only_public_key().0;
    assert!(
        secp256k1::global::SECP256K1
            .verify_schnorr(&signature, &digest, &x_only)
            .is_ok()
    );
    let other = Message::from_digest(decision_hash_for(Outcome::Refund));
    assert!(
        secp256k1::global::SECP256K1
            .verify_schnorr(&signature, &other, &x_only)
            .is_err()
    );

    for signer in signers {
        match signer.await.unwrap().unwrap() {
            SignerOutcome::Final {
                outcome,
                signature: received,
            } => {
                assert_eq!(outcome, Outcome::Release);
                assert_eq!(received, signature);
            }
            SignerOutcome::ShareSent => panic!("expected the final result"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_outcome_with_enough_votes() {
    let c = Cluster::new().await;
    let short = Duration::from_secs(2);
    for i in 1..4 {
        let (mux, key_package, coordinator) =
            (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
        // 2 votes for Release (with the coordinator) and 2 for Refund
        let vote = if i == 1 {
            Outcome::Release
        } else {
            Outcome::Refund
        };
        spawn("test", async move {
            sign_as_signer(
                &mux,
                &coordinator,
                &key_package,
                ESCROW,
                vote,
                decision_hash_for,
                short,
            )
            .await
        });
    }
    let result = sign_as_coordinator(
        &c.muxes[0],
        &c.key_packages[0],
        &c.pubkey_package,
        ESCROW,
        Outcome::Release,
        decision_hash_for,
        short,
    )
    .await;
    assert!(matches!(result, Err(SigningError::NoQuorum)));
}

#[tokio::test(flavor = "multi_thread")]
async fn signer_does_not_sign_what_it_did_not_vote_for() {
    let c = Cluster::new().await;
    let mut signers = vec![];
    for i in 1..4 {
        let (mux, key_package, coordinator) =
            (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
        signers.push(spawn("test", async move {
            sign_as_signer(
                &mux,
                &coordinator,
                &key_package,
                ESCROW,
                Outcome::Release,
                decision_hash_for,
                Duration::from_secs(3),
            )
            .await
        }));
    }

    let result = sign_as_coordinator(
        &c.muxes[0],
        &c.key_packages[0],
        &c.pubkey_package,
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
        if matches!(signer.await.unwrap(), Err(SigningError::MessageMismatch)) {
            mismatches += 1;
        }
    }
    assert!(mismatches >= 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn split_that_does_not_add_up_is_refused() {
    let c = Cluster::new().await;
    let bad_split = Outcome::Split {
        funder_split_bps: 9_000,
        recipient_split_bps: 2_000,
    };

    let as_signer = sign_as_signer(
        &c.muxes[1],
        &c.ids[0],
        &c.key_packages[1],
        ESCROW,
        bad_split,
        decision_hash_for,
        TIMEOUT,
    )
    .await;
    assert!(matches!(as_signer, Err(SigningError::InvalidOutcome)));

    let as_coordinator = sign_as_coordinator(
        &c.muxes[0],
        &c.key_packages[0],
        &c.pubkey_package,
        ESCROW,
        bad_split,
        decision_hash_for,
        TIMEOUT,
    )
    .await;
    assert!(matches!(as_coordinator, Err(SigningError::InvalidOutcome)));
}

#[tokio::test(flavor = "multi_thread")]
async fn two_escrows_are_signed_at_the_same_time() {
    let c = Cluster::new().await;
    let other_escrow = EscrowId([8; 32]);
    for escrow_id in [ESCROW, other_escrow] {
        for i in 1..4 {
            let (mux, key_package, coordinator) =
                (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
            spawn("test", async move {
                sign_as_signer(
                    &mux,
                    &coordinator,
                    &key_package,
                    escrow_id,
                    Outcome::Release,
                    decision_hash_for,
                    TIMEOUT,
                )
                .await
            });
        }
    }
    let (first, second) = tokio::join!(
        sign_as_coordinator(
            &c.muxes[0],
            &c.key_packages[0],
            &c.pubkey_package,
            ESCROW,
            Outcome::Release,
            decision_hash_for,
            TIMEOUT
        ),
        sign_as_coordinator(
            &c.muxes[0],
            &c.key_packages[0],
            &c.pubkey_package,
            other_escrow,
            Outcome::Release,
            decision_hash_for,
            TIMEOUT
        ),
    );
    first.unwrap();
    second.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn every_arbiter_makes_the_same_call() {
    let c = Cluster::new().await;
    let mut arbiters = vec![];
    for i in 0..4 {
        let (mux, key_package, pubkey_package) = (
            c.muxes[i].clone(),
            c.key_packages[i].clone(),
            c.pubkey_package.clone(),
        );
        arbiters.push(spawn("test", async move {
            sign_with_failover(
                &mux,
                &key_package,
                &pubkey_package,
                ESCROW,
                Outcome::Release,
                decision_hash_for,
                Duration::from_secs(8),
                Duration::from_secs(40),
            )
            .await
        }));
    }
    let mut signatures = vec![];
    for arbiter in arbiters {
        let (outcome, signature) = arbiter.await.unwrap().unwrap();
        assert_eq!(outcome, Outcome::Release);
        signatures.push(signature);
    }
    assert!(signatures.windows(2).all(|pair| pair[0] == pair[1]));
}

/// An arbiter that never shows up costs at most one slot
#[tokio::test(flavor = "multi_thread")]
async fn one_arbiter_offline() {
    let c = Cluster::new().await;
    let mut arbiters = vec![];
    for i in 1..4 {
        let (mux, key_package, pubkey_package) = (
            c.muxes[i].clone(),
            c.key_packages[i].clone(),
            c.pubkey_package.clone(),
        );
        arbiters.push(spawn("test", async move {
            sign_with_failover(
                &mux,
                &key_package,
                &pubkey_package,
                ESCROW,
                Outcome::Release,
                decision_hash_for,
                Duration::from_secs(6),
                Duration::from_secs(60),
            )
            .await
        }));
    }
    for arbiter in arbiters {
        arbiter.await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_escrow_is_not_signed_twice_on_one_node() {
    let c = Cluster::new().await;
    let (mux, key_package, pubkey_package) = (
        c.muxes[1].clone(),
        c.key_packages[1].clone(),
        c.pubkey_package.clone(),
    );
    // nobody else takes part, so this keeps trying until it is cancelled
    let first = spawn("test", {
        let (mux, key_package, pubkey_package) =
            (mux.clone(), key_package.clone(), pubkey_package.clone());
        async move {
            sign_with_failover(
                &mux,
                &key_package,
                &pubkey_package,
                ESCROW,
                Outcome::Release,
                decision_hash_for,
                Duration::from_secs(6),
                Duration::from_secs(20),
            )
            .await
        }
    });
    sleep(Duration::from_millis(200)).await;
    assert!(mux.has_active_escrows());

    let second = sign_with_failover(
        &mux,
        &key_package,
        &pubkey_package,
        ESCROW,
        Outcome::Release,
        decision_hash_for,
        Duration::from_secs(6),
        Duration::from_secs(20),
    )
    .await;
    assert!(matches!(second, Err(SigningError::AlreadyInProgress)));

    // cancelling the first signing frees the escrow again
    first.abort();
    let _ = first.await;
    assert!(!mux.has_active_escrows());
}

#[test]
fn pick_outcome_needs_min_signers_votes() {
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
fn pick_outcome_counts_different_splits_separately() {
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
async fn consortium_decision_is_accepted_by_the_escrow_rules() {
    let c = Cluster::new().await;

    // the key the funder puts in the contract as the arbiter key
    let consortium_key = FrostDkgSessionRecord::consortium_pubkey(&c.pubkey_package).unwrap();

    let secp = Secp256k1::new();
    let funder_key = Keypair::new(&secp, &mut OsRng).public_key();
    let recipient_key = Keypair::new(&secp, &mut OsRng).public_key();
    let fee_key = Keypair::new(&secp, &mut OsRng).public_key();
    // same escrow id, federation id and contract hash as `decision_hash_for`
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
    for i in 1..4 {
        let (mux, key_package, coordinator) =
            (c.muxes[i].clone(), c.key_packages[i].clone(), c.ids[0]);
        spawn("test", async move {
            sign_as_signer(
                &mux,
                &coordinator,
                &key_package,
                ESCROW,
                split,
                decision_hash_for,
                TIMEOUT,
            )
            .await
        });
    }
    let (outcome, signature) = sign_as_coordinator(
        &c.muxes[0],
        &c.key_packages[0],
        &c.pubkey_package,
        ESCROW,
        split,
        decision_hash_for,
        TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(outcome, split);

    // the funder submits the signature
    let ruling = Resolution::ArbiterOutcome {
        arbiter_signature: signature,
        outcome: split,
        submitter_pubkey: funder_key,
    };
    let accepted = check_resolution(&contract, &ruling, 2_000).unwrap();

    assert_eq!(accepted.transition, EscrowTransition::ArbiterOutcome(split));
    assert_eq!(
        accepted.settlement,
        Settlement::WriteClaims(vec![
            (funder_key, Amount::from_sats(245)),
            (recipient_key, Amount::from_sats(735)),
            (fee_key, Amount::from_sats(20)),
        ])
    );

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
