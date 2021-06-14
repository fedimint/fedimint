use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use config::{ClientConfig, Feerate, Peer, ServerConfig, WalletConfig};
use hbbft::crypto::serde_impl::SerdeSecret;
use miniscript::descriptor::Wsh;
use mint_api::{Amount, CompressedPublicKey, PegInDescriptor};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use structopt::StructOpt;
use tbs::dealer_keygen;

#[derive(StructOpt)]
struct Options {
    cfg_path: PathBuf,
    nodes: u16,
    hbbft_base_port: u16,
    api_base_port: u16,
    amount_tiers: Vec<Amount>,
}

fn main() {
    let opts: Options = StructOpt::from_args();
    let mut rng = OsRng::new().unwrap();
    let secp = Secp256k1::new();

    let per_utxo_fee = bitcoin::Amount::from_sat(500);

    let ids = 0..opts.nodes;
    let netinfo = hbbft::NetworkInfo::generate_map(ids.clone(), &mut rng)
        .expect("Could not generate HBBFT netinfo");

    println!(
        "Generating keys such that up to {} peers may fail/be evil",
        hbbft::util::max_faulty(opts.nodes as usize)
    );
    let tbs_threshold = (opts.nodes as usize) - hbbft::util::max_faulty(opts.nodes as usize) - 1;

    let tbs_keys = opts
        .amount_tiers
        .iter()
        .map(|&amount| {
            let (tbs_pk, tbs_pks, tbs_sks) = dealer_keygen(tbs_threshold, opts.nodes as usize);
            (amount, (tbs_pk, tbs_pks, tbs_sks))
        })
        .collect::<HashMap<_, _>>();

    let btc_pegin_keys = ids
        .map(|_id| secp.generate_keypair(&mut rng))
        .collect::<Vec<_>>();
    let peg_in_descriptor = PegInDescriptor::Wsh(
        Wsh::new_sortedmulti(
            tbs_threshold,
            btc_pegin_keys
                .iter()
                .map(|(_, pk)| CompressedPublicKey { key: *pk })
                .collect(),
        )
        .unwrap(),
    );

    let peers = netinfo
        .iter()
        .map(|(&id, netinf)| {
            let peer = Peer {
                hbbft_port: opts.hbbft_base_port + id,
                api_port: opts.api_base_port + id,
                hbbft_pk: netinf.public_key(&id).unwrap().clone(),
                tbs_pks: opts
                    .amount_tiers
                    .iter()
                    .map(|&amount| (amount, tbs_keys[&amount].1[id as usize]))
                    .collect(),
            };

            (id, peer)
        })
        .collect::<BTreeMap<_, _>>();

    for (&id, netinf) in netinfo.iter() {
        let mut path: PathBuf = opts.cfg_path.clone();
        path.push(format!("server-{}.json", id));

        let file = std::fs::File::create(path).expect("Could not create cfg file");
        let cfg = ServerConfig {
            identity: id,
            hbbft_port: opts.hbbft_base_port + id,
            api_port: opts.api_base_port + id,
            peers: peers.clone(),
            hbbft_sk: SerdeSecret(netinf.secret_key().clone()),
            hbbft_sks: SerdeSecret(netinf.secret_key_share().unwrap().clone()),
            hbbft_pk_set: netinf.public_key_set().clone(),
            tbs_sks: opts
                .amount_tiers
                .iter()
                .map(|&amount| (amount, tbs_keys[&amount].2[id as usize]))
                .collect(),
            db_path: format!("cfg/mint-{}.db", id).into(),
            wallet: WalletConfig {
                network: Network::Regtest,
                peg_in_descriptor: peg_in_descriptor.clone(),
                peg_in_key: btc_pegin_keys[id as usize].0,
                finalty_delay: 10,
                default_fee: Feerate { sats_per_kvb: 2000 },
                start_consensus_height: 0,
                per_utxo_fee,
                btc_rpc_address: "127.0.0.1:18443".to_string(),
                btc_rpc_user: "bitcoin".to_string(),
                btc_rpc_pass: "bitcoin".to_string(),
            },
        };
        serde_json::to_writer_pretty(file, &cfg).unwrap();
    }

    let mut client_cfg_file_path: PathBuf = opts.cfg_path.clone();
    client_cfg_file_path.push("client.json");

    let client_cfg_file =
        std::fs::File::create(client_cfg_file_path).expect("Could not create cfg file");

    let client_cfg = ClientConfig {
        mints: (0..opts.nodes)
            .map(|node| format!("http://127.0.0.1:{}", opts.api_base_port + node))
            .collect(),
        mint_pk: opts
            .amount_tiers
            .iter()
            .map(|&amount| (amount, tbs_keys[&amount].0))
            .collect(),
        peg_in_descriptor,
        network: Network::Regtest,
        per_utxo_fee,
    };
    serde_json::to_writer_pretty(client_cfg_file, &client_cfg).unwrap();
}
