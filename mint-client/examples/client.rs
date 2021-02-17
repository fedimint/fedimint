use config::{load_from_file, ClientConfig, ClientOpts};
use mint_api::{PegInRequest, ReissuanceRequest, RequestId, SigResponse};
use mint_client::{CoinFinalizationError, IssuanceRequest, SpendableCoin};
use musig;
use rand::{CryptoRng, RngCore};
use reqwest::StatusCode;
use sha3::Sha3_256;
use std::process::exit;
use structopt::StructOpt;
use tokio::time::Duration;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut rng = rand::rngs::OsRng::new().unwrap();

    let opts: ClientOpts = StructOpt::from_args();
    let cfg: ClientConfig = load_from_file(&opts.cfg_path);

    info!("Sending peg-in request for {} coins", opts.issue_amt);
    let issuance_req = request_issuance(&cfg, opts.issue_amt, &mut rng).await;
    let coins = fetch_coins(&cfg, issuance_req)
        .await
        .expect("Couldn't qcquire coins");
    info!("Received {} valid coins", coins.len());

    info!("Sending reissuance request for {} coins", coins.len());
    let issuance_req = request_reissuance(&cfg, coins, &mut rng).await;
    let coins = fetch_coins(&cfg, issuance_req)
        .await
        .expect("Couldn't qcquire coins");
    info!("Received {} valid coins", coins.len());
}

async fn fetch_coins(
    cfg: &ClientConfig,
    req: IssuanceRequest,
) -> Result<Vec<SpendableCoin>, CoinFinalizationError> {
    let client = reqwest::Client::new();
    let resp: SigResponse = loop {
        let url = format!("{}/issuance/{}", cfg.url, req.id());

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

    req.finalize(resp, cfg.mint_pk)
}

async fn request_issuance(
    cfg: &ClientConfig,
    amount: usize,
    mut rng: impl RngCore + CryptoRng,
) -> IssuanceRequest {
    let (issuance_request, sig_req) = IssuanceRequest::new(amount, &mut rng);
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

    issuance_request
}

async fn request_reissuance(
    cfg: &ClientConfig,
    old_coins: Vec<SpendableCoin>,
    mut rng: impl RngCore + CryptoRng,
) -> IssuanceRequest {
    let (issuance_req, sig_req) = IssuanceRequest::new(old_coins.len(), &mut rng);

    let (spend_keys, coins): (Vec<_>, Vec<_>) = old_coins
        .into_iter()
        .map(|sc| (sc.spend_key, sc.coin))
        .unzip();

    let mut digest = Sha3_256::default();
    bincode::serialize_into(&mut digest, &coins).unwrap();
    bincode::serialize_into(&mut digest, &sig_req).unwrap();
    let rng = musig::rng_adapt::RngAdaptor(rand::rngs::OsRng::new().unwrap());
    let sig = musig::sign(digest, spend_keys.iter(), rng);

    let req = ReissuanceRequest {
        coins,
        blind_tokens: sig_req,
        sig,
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

    issuance_req
}
