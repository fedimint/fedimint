use std::str::FromStr;

use fedimint_core::ChainId;
use fedimint_core::bitcoin::{BlockHash, Network};

use super::network_from_chain_id;

fn chain_id(block_1_hash: &str) -> ChainId {
    ChainId::new(BlockHash::from_str(block_1_hash).expect("valid block hash"))
}

#[test]
fn well_known_chain_ids_map_to_their_network() {
    for (block_1_hash, network) in [
        (
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            Network::Bitcoin,
        ),
        (
            "00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206",
            Network::Testnet,
        ),
        (
            "0000000012982b6d5f621229286b880e909984df669c2afabb102ce311b13f28",
            Network::Testnet4,
        ),
        (
            "00000086d6b2636cb2a392d45edc4ec544a10024d30141c9adf4bfd9de533b53",
            Network::Signet,
        ),
        (
            "000002855893a0a9b24eaffc5efc770558a326fee4fc10c9da22fc19cd2954f9",
            Network::Signet,
        ),
    ] {
        assert_eq!(
            network_from_chain_id(chain_id(block_1_hash)),
            network,
            "{block_1_hash}"
        );
    }
}

#[test]
fn unknown_chain_id_maps_to_regtest() {
    assert_eq!(
        network_from_chain_id(chain_id(
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        )),
        Network::Regtest
    );
}
