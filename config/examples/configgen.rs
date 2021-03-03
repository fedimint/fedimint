use config::{ClientConfig, Peer, ServerConfig};
use hbbft::crypto::serde_impl::SerdeSecret;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::path::PathBuf;
use structopt::StructOpt;
use tbs::dealer_keygen;

#[derive(StructOpt)]
struct Options {
    cfg_path: PathBuf,
    nodes: u16,
    hbbft_base_port: u16,
    api_base_port: u16,
}

fn main() {
    let opts: Options = StructOpt::from_args();
    let mut rng = OsRng::new().unwrap();

    let ids = 0..opts.nodes;
    let netinfo =
        hbbft::NetworkInfo::generate_map(ids, &mut rng).expect("Could not generate HBBFT netinfo");

    println!(
        "Generating keys such that up to {} peers may fail/be evil",
        hbbft::util::max_faulty(opts.nodes as usize)
    );
    let tbs_threshold = (opts.nodes as usize) - hbbft::util::max_faulty(opts.nodes as usize) - 1;
    let (tbs_pk, tbs_pks, tbs_sks) = dealer_keygen(tbs_threshold, opts.nodes as usize);

    let peers = netinfo
        .iter()
        .zip(tbs_pks.iter())
        .map(|((id, netinf), tbs_pks)| {
            let peer = Peer {
                hbbft_port: opts.hbbft_base_port + *id,
                api_port: opts.api_base_port + *id,
                hbbft_pk: netinf.public_key(id).unwrap().clone(),
                tbs_pks: tbs_pks.clone(),
            };

            (*id, peer)
        })
        .collect::<BTreeMap<_, _>>();

    for ((id, netinf), tbs_sks) in netinfo.iter().zip(tbs_sks.iter()) {
        let mut path: PathBuf = opts.cfg_path.clone();
        path.push(format!("server-{}.json", id));

        let file = std::fs::File::create(path).expect("Could not create cfg file");
        let cfg = ServerConfig {
            identity: *id,
            hbbft_port: opts.hbbft_base_port + *id,
            api_port: opts.api_base_port + *id,
            peers: peers.clone(),
            hbbft_sk: SerdeSecret(netinf.secret_key().clone()),
            hbbft_sks: SerdeSecret(netinf.secret_key_share().unwrap().clone()),
            hbbft_pk_set: netinf.public_key_set().clone(),
            tbs_sks: tbs_sks.clone(),
            db_path: format!("cfg/mint-{}.db", *id).into(),
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
        mint_pk: tbs_pk,
    };
    serde_json::to_writer_pretty(client_cfg_file, &client_cfg).unwrap();
}
