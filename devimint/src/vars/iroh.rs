use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use fedimint_core::envs::FM_IROH_CONNECT_OVERRIDES_ENV;
use fedimint_core::{NumPeers, PeerId};
use iroh_base::NodeAddr;
use iroh_base::ticket::{NodeTicket, Ticket};

use super::ToEnvVar;
use crate::federation::{
    FEDIMINTD_API_PORT_OFFSET, FEDIMINTD_P2P_PORT_OFFSET, PORTS_PER_FEDIMINTD,
};

#[derive(Debug, Clone)]
pub struct FedimintdEndpoint {
    node_id: iroh_base::NodeId,
    secret_key: iroh_base::SecretKey,
    port: u16,
}

impl FedimintdEndpoint {
    fn new(port: u16) -> Self {
        let secret_key = iroh_base::SecretKey::generate(&mut rand::thread_rng());

        Self {
            node_id: secret_key.public(),
            secret_key,
            port,
        }
    }

    pub fn secret_key(&self) -> String {
        self.secret_key.to_string()
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    fn to_override(&self) -> String {
        let node_addr = NodeAddr {
            node_id: self.node_id,
            relay_url: None,
            direct_addresses: BTreeSet::from([SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                self.port,
            ))]),
        };
        format!(
            "{}={},",
            self.node_id,
            Ticket::serialize(&NodeTicket::from(node_addr))
        )
    }
}

#[derive(Debug, Clone)]
pub struct FedimintdPeerOverrides {
    pub p2p: FedimintdEndpoint,
    pub api: FedimintdEndpoint,
    pub base_port: u16,
}

impl FedimintdPeerOverrides {
    fn new(base_port: u16) -> Self {
        Self {
            p2p: FedimintdEndpoint::new(base_port + FEDIMINTD_P2P_PORT_OFFSET),
            api: FedimintdEndpoint::new(base_port + FEDIMINTD_API_PORT_OFFSET),
            base_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FedimintdOverrides {
    pub base_port: u16,
    pub num_peers: NumPeers,
    pub peers: BTreeMap<PeerId, FedimintdPeerOverrides>,
}

impl FedimintdOverrides {
    pub fn new(base_port: u16, num_peers: NumPeers) -> Self {
        let peers = num_peers
            .peer_ids()
            .map(|peer_id| {
                (peer_id, {
                    FedimintdPeerOverrides::new(
                        base_port
                            + u16::try_from(peer_id.to_usize()).expect("Can't fail")
                                * PORTS_PER_FEDIMINTD,
                    )
                })
            })
            .collect();
        Self {
            base_port,
            num_peers,
            peers,
        }
    }

    pub fn peer_expect(&self, peer_id: PeerId) -> &FedimintdPeerOverrides {
        self.peers.get(&peer_id).expect("Wrong peer_id?")
    }
}

impl ToEnvVar for FedimintdOverrides {
    fn to_env_values(&self, _base_env: &str) -> impl Iterator<Item = (String, String)> {
        vec![(
            FM_IROH_CONNECT_OVERRIDES_ENV.to_string(),
            self.peers
                .values()
                .map(|peer| format!("{},{}", peer.p2p.to_override(), peer.api.to_override(),))
                .collect::<Vec<String>>()
                .join(","),
        )]
        .into_iter()
    }
}
