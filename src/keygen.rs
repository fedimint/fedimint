use crate::config::Config;
use crate::peer::Peer;
use futures::future::try_join_all;
use hbbft::crypto::{PublicKey, PublicKeySet, SecretKey, SecretKeyShare};
use hbbft::sync_key_gen::{Ack, Part, PartOutcome, SyncKeyGen};
use hbbft::util::max_faulty;
use rand::Rng;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::iter::once;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub async fn generate_keys<R: Rng>(
    cfg: &Config,
    rng: &mut R,
    mut peers: HashMap<u16, TcpStream>,
) -> (
    Vec<(u16, TcpStream, PublicKey)>,
    PublicKeySet,
    SecretKey,
    SecretKeyShare,
) {
    info!("Beginning distributed key generation");
    let hbbft_sec_key: SecretKey = rng.gen();
    let hbbft_pub_key = hbbft_sec_key.public_key();

    // Exchange pub keys
    for (_, peer_socket) in peers.iter_mut() {
        peer_socket
            .write_all(&hbbft_pub_key.to_bytes())
            .await
            .expect("Failed to send hbbft pub key to peer");
    }

    let mut peers = try_join_all(peers.into_iter().map(|(id, peer_socket)| {
        (async move |id: u16,
                     mut peer_socket: TcpStream|
                    -> Result<(u16, TcpStream, PublicKey), std::io::Error> {
            let mut key_buffer = [0u8; 48];
            peer_socket.read_exact(&mut key_buffer).await?;
            let hbbft_pub_key = PublicKey::from_bytes(key_buffer).unwrap();
            Ok((id, peer_socket, hbbft_pub_key))
        })(id, peer_socket)
    }))
    .await
    .expect("Error collecting peer pub keys");

    let pub_keys = once((cfg.identity, hbbft_pub_key.clone()))
        .chain(peers.iter().map(|(id, _, key)| (*id, key.clone())))
        .collect::<BTreeMap<_, _>>();

    // Generate proposal
    let thresh = max_faulty(cfg.federation_size as usize);
    debug!("Max faulty nodes: {}", thresh);
    let (mut kg, proposal) = SyncKeyGen::new(
        cfg.identity,
        hbbft_sec_key.clone(),
        pub_keys.clone(),
        thresh,
        rng,
    )
    .expect("Failed to instantiate keygen algorithm");

    let ack = kg
        .handle_part(&cfg.identity, proposal.clone().unwrap(), rng)
        .expect("Failed to accept own proposal");
    let ack = match ack {
        PartOutcome::Valid(Some(ack)) => ack,
        _ => {
            panic!()
        }
    };
    kg.handle_ack(&cfg.identity, ack.clone())
        .expect("Failed to handle own ack");

    // Distribute proposal
    let proposal_bin = bincode::serialize(proposal.as_ref().expect("No proposal was generated"))
        .expect("Can't encode proposal");
    let proposal_len = proposal_bin.len();
    for (peer, peer_socket, _) in peers.iter_mut() {
        peer_socket
            .write_u64(proposal_len as u64)
            .await
            .expect("Failed to send proposal len");
        peer_socket
            .write_all(&proposal_bin)
            .await
            .expect("Failed to send proposal");
        debug!("Sent proposal to node {}", peer);
    }

    // Receive and ack proposals
    let mut acks = vec![ack];
    for (peer, peer_socket, _) in peers.iter_mut() {
        let len = peer_socket
            .read_u64()
            .await
            .expect("Failed to read proposal len");

        let mut proposal_bin = vec![0; len as usize];
        peer_socket
            .read_exact(&mut proposal_bin)
            .await
            .expect("Failed to read proposal");
        let proposal: Part =
            bincode::deserialize(&proposal_bin).expect("Could not decode proposal");

        debug!("Received proposal from {}", peer);
        let ack = match kg
            .handle_part(peer, proposal, rng)
            .expect("Could not process proposal")
        {
            PartOutcome::Valid(Some(ack)) => ack,
            PartOutcome::Valid(None) => panic!("No ACK produced"),
            PartOutcome::Invalid(e) => {
                panic!("Invalid proposal: {:?}", e)
            }
        };

        acks.push(ack);
    }

    let mut ack_sent = 0;
    let mut ack_received = 0;
    // sending all acks to all peers
    for (peer, peer_socket, _) in peers.iter_mut() {
        debug!("Sending acks to {}", peer);
        for ack in acks.iter() {
            let ack_bin = bincode::serialize(ack).expect("Could not serialize ACK");
            let ack_len = ack_bin.len();
            peer_socket
                .write_u64(ack_len as u64)
                .await
                .expect("Failed to send ack len");
            peer_socket
                .write_all(&ack_bin)
                .await
                .expect("Failed to send ack");
            ack_sent += 1;
        }
    }

    for (peer, peer_socket, _) in peers.iter_mut() {
        for _ in 0..cfg.federation_size {
            let len = peer_socket
                .read_u64()
                .await
                .expect("Failed to read ack len");

            let mut ack_bin = vec![0; len as usize];
            peer_socket
                .read_exact(&mut ack_bin)
                .await
                .expect("Failed to read ack");
            let ack: Ack = bincode::deserialize(&ack_bin).expect("Could not decode proposal");

            kg.handle_ack(peer, ack).expect("Could not process ACK");
            ack_received += 1;
        }
        debug!("Received all ACKs from {}", peer);
    }

    assert_eq!(ack_sent, ack_received);
    assert!(kg.is_ready());
    let (pub_key_set, secret_key_share) = kg.generate().expect("Could not generate keys");

    info!("Finished generating keys");

    (peers, pub_key_set, hbbft_sec_key, secret_key_share.unwrap())
}
