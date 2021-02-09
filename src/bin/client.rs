use minimint::config::{load_from_file, ClientConfig, ClientOpts};
use minimint::mint::{Coin, RequestId, SigResponse, SignRequest};
use minimint::net::api::PegInRequest;
use rand::Rng;
use reqwest::StatusCode;
use structopt::StructOpt;
use tbs::{blind_message, unblind_signature, Message};
use tokio::time::Duration;

#[tokio::main]
async fn main() {
    let opts: ClientOpts = StructOpt::from_args();
    let cfg: ClientConfig = load_from_file(&opts.cfg_path);
    let mut rng = rand::rngs::OsRng::new().unwrap();

    let (nonces, bmsgs): (Vec<_>, _) = (0..opts.issue_amt)
        .map(|_| {
            let nonce: [u8; 32] = rng.gen();
            let (bkey, bmsg) = blind_message(Message::from_bytes(&nonce));
            ((nonce, bkey), bmsg)
        })
        .unzip();

    let sig_req = SignRequest(bmsgs);
    let req_id = sig_req.id();
    let req = PegInRequest {
        blind_tokens: sig_req,
        proof: (),
    };
    let client = reqwest::Client::new();
    client
        .put(&format!("{}/issuance", cfg.url))
        .json(&req)
        .send()
        .await
        .expect("API error");

    let resp: SigResponse = loop {
        let url = format!("{}/issuance/{}", cfg.url, req_id);

        println!("looking for coins: {}", url);

        let api_resp = client.get(&url).send().await;
        match api_resp {
            Ok(r) => {
                if r.status() == StatusCode::OK {
                    break r.json().await.expect("invalid reply");
                } else {
                    println!("Status: {:?}", r.status());
                }
            }
            Err(e) => {
                if e.status() != Some(StatusCode::NOT_FOUND) {
                    panic!("Error: {:?}", e);
                }
            }
        };
        tokio::time::sleep(Duration::from_millis(1500)).await;
    };

    let coins: Vec<Coin> = resp
        .1
        .into_iter()
        .zip(nonces)
        .map(|(sig, (nonce, bkey))| {
            let sig = unblind_signature(bkey, sig);
            Coin(nonce, sig)
        })
        .collect();

    assert!(coins.iter().all(|c| c.verify(cfg.mint_pk)));
}
