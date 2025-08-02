use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use fedimint_core::envs::FM_IROH_CONNECT_OVERRIDES_ENV;
use fedimint_core::{NumPeers, PeerId};
use iroh_base::NodeAddr;
use iroh_base::ticket::{NodeTicket, Ticket};

use super::ToEnvVar;
use crate::federation::{
    FEDIMINTD_API_PORT_OFFSET, FEDIMINTD_METRICS_PORT_OFFSET, FEDIMINTD_P2P_PORT_OFFSET,
    FEDIMINTD_UI_PORT_OFFSET, PORTS_PER_FEDIMINTD,
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
    pub ui: u16,
    pub metrics: u16,
}

impl FedimintdPeerOverrides {
    fn new(p2p_port: u16, api_port: u16, ui_port: u16, metrics_port: u16) -> Self {
        Self {
            p2p: FedimintdEndpoint::new(p2p_port),
            api: FedimintdEndpoint::new(api_port),
            ui: ui_port,
            metrics: metrics_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FederationNetOverrides {
    pub num_peers: NumPeers,
    pub peers: BTreeMap<PeerId, FedimintdPeerOverrides>,
}

impl FederationNetOverrides {
    pub fn new_from_ports(ports: &[u16], num_peers: NumPeers) -> Self {
        let peers = num_peers
            .peer_ids()
            .map(|peer_id| {
                let peer_idx = peer_id.to_usize();
                let peer_base_idx = peer_idx * PORTS_PER_FEDIMINTD as usize;
                (peer_id, {
                    FedimintdPeerOverrides::new(
                        ports[peer_base_idx + FEDIMINTD_P2P_PORT_OFFSET as usize],
                        ports[peer_base_idx + FEDIMINTD_API_PORT_OFFSET as usize],
                        ports[peer_base_idx + FEDIMINTD_UI_PORT_OFFSET as usize],
                        ports[peer_base_idx + FEDIMINTD_METRICS_PORT_OFFSET as usize],
                    )
                })
            })
            .collect();
        Self { num_peers, peers }
    }

    pub fn peer_expect(&self, peer_id: PeerId) -> &FedimintdPeerOverrides {
        self.peers.get(&peer_id).expect("Wrong peer_id?")
    }
}

#[derive(Debug, Clone)]
pub struct FederationsNetOverrides {
    federations: Vec<FederationNetOverrides>,
}

impl FederationsNetOverrides {
    pub fn new_from_ports(ports: &[u16], num_federations: usize, num_peers: NumPeers) -> Self {
        let ports_per_federation = num_peers.total() * PORTS_PER_FEDIMINTD as usize;
        Self {
            federations: (0..num_federations)
                .map(|fed_i| {
                    let start = fed_i * ports_per_federation;
                    let end = start + ports_per_federation;
                    FederationNetOverrides::new_from_ports(&ports[start..end], num_peers)
                })
                .collect(),
        }
    }

    pub fn fed_expect(&self, fed_i: usize) -> &FederationNetOverrides {
        self.federations.get(fed_i).expect("Wrong fed_i")
    }

    pub fn peer_expect(&self, fed_i: usize, peer_id: PeerId) -> &FedimintdPeerOverrides {
        self.federations
            .get(fed_i)
            .expect("Wrong fed_i")
            .peers
            .get(&peer_id)
            .expect("Wrong peer_id?")
    }
}

impl ToEnvVar for FederationsNetOverrides {
    fn to_env_values(&self, _base_env: &str) -> impl Iterator<Item = (String, String)> {
        vec![(
            FM_IROH_CONNECT_OVERRIDES_ENV.to_string(),
            self.federations
                .iter()
                .flat_map(|f| f.peers.values())
                .map(|peer| format!("{},{}", peer.p2p.to_override(), peer.api.to_override(),))
                .collect::<Vec<String>>()
                .join(","),
        )]
        .into_iter()
    }
}
