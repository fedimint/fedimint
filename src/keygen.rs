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

pub async fn generate_keys(
    cfg: &Config,
    mut peers: HashMap<u16, TcpStream>,
) -> (HashMap<u16, Peer>, PublicKeySet, SecretKey, SecretKeyShare) {
    let mut rng = rand::rngs::OsRng::new().expect("Failed to get RNG");

    info!("Beginning distributed key generation");
    let sec_key: SecretKey = rng.gen();
    let pub_key = sec_key.public_key();

    // Exchange pub keys
    for (_, peer_socket) in peers.iter_mut() {
        peer_socket
            .write_all(&pub_key.to_bytes())
            .await
            .expect("Failed to send pub key to peer");
    }

    let mut peers = try_join_all(peers.into_iter().map(|(id, peer_socket)| {
        (async move |id: u16,
                     mut peer_socket: TcpStream|
                    -> Result<(u16, TcpStream, PublicKey), std::io::Error> {
            let mut key_buffer = [0u8; 48];
            peer_socket.read_exact(&mut key_buffer).await?;
            Ok((id, peer_socket, PublicKey::from_bytes(key_buffer).unwrap()))
        })(id, peer_socket)
    }))
    .await
    .expect("Error collecting peer pub keys");

    let pub_keys = once((cfg.identity, pub_key.clone()))
        .chain(peers.iter().map(|(id, _, key)| (*id, key.clone())))
        .collect::<BTreeMap<_, _>>();

    // Generate proposal
    let (mut kg, proposal) = SyncKeyGen::new(
        cfg.identity,
        sec_key.clone(),
        pub_keys.clone(),
        max_faulty(cfg.federation_size as usize),
        &mut rng,
    )
    .expect("Failed to instantiate keygen algorithm");

    // Distribute proposal
    let proposal_bin = bincode::serialize(proposal.as_ref().expect("No proposal was generated"))
        .expect("Can't encode proposal");
    let proposal_len = proposal_bin.len();
    for (_, peer_socket, _) in peers.iter_mut() {
        peer_socket
            .write_u64(proposal_len as u64)
            .await
            .expect("Failed to send proposal len");
        peer_socket
            .write_all(&proposal_bin)
            .await
            .expect("Failed to send proposal");
    }

    // Receive and ack proposals
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

        let ack = match kg
            .handle_part(peer, proposal, &mut rng)
            .expect("Could not process proposal")
        {
            PartOutcome::Valid(Some(ack)) => ack,
            PartOutcome::Valid(None) => panic!("No ACK produced"),
            PartOutcome::Invalid(e) => {
                panic!("Invalid proposal: {:?}", e)
            }
        };

        let ack_bin = bincode::serialize(&ack).expect("Could not serialize ACK");
        let ack_len = ack_bin.len();
        peer_socket
            .write_u64(ack_len as u64)
            .await
            .expect("Failed to send ack len");
        peer_socket
            .write_all(&ack_bin)
            .await
            .expect("Failed to send ack");
    }

    for (peer, peer_socket, _) in peers.iter_mut() {
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
    }

    let (pub_key_set, secret_key_share) = kg.generate().expect("Could not generate keys");

    let peers = peers
        .into_iter()
        .map(|(id, conn, pubkey)| (id, Peer { id, conn, pubkey }))
        .collect::<HashMap<_, _>>();

    info!("Finished generating keys");

    (peers, pub_key_set, sec_key, secret_key_share.unwrap())
}
