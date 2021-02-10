use minimint::config::{load_from_file, ClientConfig, ClientOpts};
use minimint::mint::{Coin, RequestId, SigResponse, SignRequest};
use minimint::net::api::{PegInRequest, ReissuanceRequest};
use rand::Rng;
use reqwest::StatusCode;
use std::process::exit;
use structopt::StructOpt;
use tbs::{blind_message, unblind_signature, BlindingKey, Message};
use tokio::time::Duration;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts: ClientOpts = StructOpt::from_args();
    let cfg: ClientConfig = load_from_file(&opts.cfg_path);

    info!("Sending peg-in request for {} coins", opts.issue_amt);
    let (req_id, nonces) = request_issuance(&cfg, opts.issue_amt).await;
    let coins = fetch_coins(&cfg, req_id, nonces).await;
    assert!(coins.iter().all(|c| c.verify(cfg.mint_pk)));
    info!("Received {} valid coins", coins.len());

    info!("Sending reissuance request for {} coins", coins.len());
    let (req_id, nonces) = request_reissuance(&cfg, coins).await;
    let coins = fetch_coins(&cfg, req_id, nonces).await;
    assert!(coins.iter().all(|c| c.verify(cfg.mint_pk)));
    info!("Received {} valid coins", coins.len());
}

async fn fetch_coins(
    cfg: &ClientConfig,
    req_id: u64,
    nonces: Vec<([u8; 32], BlindingKey)>,
) -> Vec<Coin> {
    let client = reqwest::Client::new();
    let resp: SigResponse = loop {
        let url = format!("{}/issuance/{}", cfg.url, req_id);

        debug!("looking for coins: {}", url);

        let api_resp = client.get(&url).send().await;
        match api_resp {
            Ok(r) => {
                if r.status() == StatusCode::OK {
                    break r.json().await.expect("invalid reply");
                } else {
                    debug!("Status: {:?}", r.status());
                }
            }
            Err(e) => {
                if e.status() != Some(StatusCode::NOT_FOUND) {
                    panic!("Error: {:?}", e);
                }
            }
        };
        tokio::time::sleep(Duration::from_millis(5000)).await;
    };

    resp.1
        .into_iter()
        .zip(nonces)
        .map(|(sig, (nonce, bkey))| {
            let sig = unblind_signature(bkey, sig);
            Coin(nonce, sig)
        })
        .collect()
}

fn generate_signing_request(amount: usize) -> (Vec<([u8; 32], BlindingKey)>, SignRequest) {
    let mut rng = rand::rngs::OsRng::new().unwrap();

    let (nonces, bmsgs): (Vec<_>, _) = (0..amount)
        .map(|_| {
            let nonce: [u8; 32] = rng.gen();
            let (bkey, bmsg) = blind_message(Message::from_bytes(&nonce));
            ((nonce, bkey), bmsg)
        })
        .unzip();

    let sig_req = SignRequest(bmsgs);
    (nonces, sig_req)
}

async fn request_issuance(
    cfg: &ClientConfig,
    amount: usize,
) -> (u64, Vec<([u8; 32], BlindingKey)>) {
    let (nonces, sig_req) = generate_signing_request(amount);
    let req_id = sig_req.id();
    let req = PegInRequest {
        blind_tokens: sig_req,
        proof: (),
    };
    let client = reqwest::Client::new();
    let res = client
        .put(&format!("{}/issuance/pegin", cfg.url))
        .json(&req)
        .send()
        .await
        .expect("API error");

    if res.status() != StatusCode::OK {
        error!("API returned error when pegging in: {:?}", res.status());
        exit(-1);
    }

    (req_id, nonces)
}

async fn request_reissuance(
    cfg: &ClientConfig,
    old_coins: Vec<Coin>,
) -> (u64, Vec<([u8; 32], BlindingKey)>) {
    let (nonces, sig_req) = generate_signing_request(old_coins.len());
    let req_id = sig_req.id();
    let req = ReissuanceRequest {
        coins: old_coins,
        blind_tokens: sig_req,
        sig: (),
    };
    let client = reqwest::Client::new();
    let res = client
        .put(&format!("{}/issuance/reissue", cfg.url))
        .json(&req)
        .send()
        .await
        .expect("API error");

    if res.status() != StatusCode::OK {
        error!("API returned error when reissuing: {:?}", res.status());
        exit(-1);
    }

    (req_id, nonces)
}
