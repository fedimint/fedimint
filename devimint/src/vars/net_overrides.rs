use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use fedimint_core::envs::{FM_GW_IROH_CONNECT_OVERRIDES_ENV, FM_IROH_CONNECT_OVERRIDES_ENV};
use fedimint_core::{NumPeers, PeerId};
use iroh_base::NodeAddr;
use iroh_base::ticket::{NodeTicket, Ticket};

use super::ToEnvVar;
use crate::federation::{
    FEDIMINTD_API_PORT_OFFSET, FEDIMINTD_P2P_PORT_OFFSET, PORTS_PER_FEDIMINTD,
};

#[derive(Debug, Clone)]
pub struct FedimintIrohEndpoint {
    node_id: iroh_base::NodeId,
    secret_key: iroh_base::SecretKey,
    port: u16,
}

impl FedimintIrohEndpoint {
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

    pub fn node_id(&self) -> iroh_base::NodeId {
        self.node_id
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
    pub p2p: FedimintIrohEndpoint,
    pub api: FedimintIrohEndpoint,
    pub base_port: u16,
}

impl FedimintdPeerOverrides {
    fn new(base_port: u16) -> Self {
        Self {
            p2p: FedimintIrohEndpoint::new(base_port + FEDIMINTD_P2P_PORT_OFFSET),
            api: FedimintIrohEndpoint::new(base_port + FEDIMINTD_API_PORT_OFFSET),
            base_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FederationNetOverrides {
    pub base_port: u16,
    pub num_peers: NumPeers,
    pub peers: BTreeMap<PeerId, FedimintdPeerOverrides>,
}

impl FederationNetOverrides {
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

#[derive(Debug, Clone)]
pub struct FederationsNetOverrides {
    federations: Vec<FederationNetOverrides>,
}

impl FederationsNetOverrides {
    pub fn new(base_port: u16, num_federations: usize, num_peers: NumPeers) -> Self {
        Self {
            federations: (0..num_federations)
                .map(|fed_i| {
                    FederationNetOverrides::new(
                        base_port + fed_i as u16 * PORTS_PER_FEDIMINTD * num_peers.total() as u16,
                        num_peers,
                    )
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

#[derive(Debug, Clone)]
pub struct GatewaydNetOverrides {
    pub gateway_iroh_endpoints: Vec<FedimintIrohEndpoint>,
}

impl GatewaydNetOverrides {
    pub fn new(base_port: u16, num_gateways: usize) -> Self {
        Self {
            gateway_iroh_endpoints: (0..num_gateways)
                .map(|gw_i| FedimintIrohEndpoint::new(base_port + gw_i as u16))
                .collect(),
        }
    }
}

impl ToEnvVar for GatewaydNetOverrides {
    fn to_env_values(&self, _base_env: &str) -> impl Iterator<Item = (String, String)> {
        vec![(
            FM_GW_IROH_CONNECT_OVERRIDES_ENV.to_string(),
            self.gateway_iroh_endpoints
                .iter()
                .map(|gw| gw.to_override().to_string())
                .collect::<Vec<String>>()
                .join(","),
        )]
        .into_iter()
    }
}
