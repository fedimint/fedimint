use config::{load_from_file, ClientConfig, ClientOpts};
use futures::future::select_all;
use itertools::Itertools;
use mint_api::{PegInRequest, ReissuanceRequest, RequestId, SigResponse};
use mint_client::{CoinFinalizationError, IssuanceRequest, SpendableCoin};
use musig;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use reqwest::StatusCode;
use sha3::Sha3_256;
use std::process::exit;
use structopt::StructOpt;
use tokio::select;
use tokio::time::{Duration, Instant};
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

    let num_coins = 50 * opts.issuance_per_1000_s / 1000 * opts.issue_amt;

    info!("Sending peg-in request for {} coins", num_coins);

    let issuance_req = request_issuance(&cfg, num_coins, &mut rng).await;
    let coins = fetch_coins(&cfg, issuance_req)
        .await
        .expect("Couldn't qcquire coins");
    let mut coins = coins
        .into_iter()
        .chunks(opts.issue_amt)
        .into_iter()
        .map(|chunk| chunk.collect())
        .collect::<Vec<Vec<_>>>();

    info!(
        "Beginning to send {} reissuance requests with {} coins each to two random mints per second",
        (opts.issuance_per_1000_s as f32) / 1000f32, opts.issue_amt
    );
    let mut interval = tokio::time::interval(Duration::from_micros(
        1_000_000_000 / (opts.issuance_per_1000_s as u64),
    ));
    let mut ongoing_requests = vec![];
    let mut delays = vec![];

    let reissuance = tokio::spawn(reissue(
        rng.clone(),
        cfg.clone(),
        coins.pop().expect("ran out of coins"),
    ));
    ongoing_requests.push(reissuance);

    loop {
        let ongoing_select = select_all(ongoing_requests.iter_mut());
        select! {
            _ = interval.tick() => {
                let reissuance = tokio::spawn(reissue(rng.clone(), cfg.clone(), coins.pop().expect("ran out of coins")));
                ongoing_requests.push(reissuance);
            },
            (result, idx, _) = ongoing_select => {
                let (delay, new_coins) = result.unwrap();
                ongoing_requests.remove(idx);
                coins.push(new_coins);
                delays.push(delay);
                let average = delays.iter().map(|d| d.as_secs_f32()).sum::<f32>() / (delays.len() as f32);
                info!("Finished reissuance after {}s ({}s avg)", delay.as_secs_f32(), average);
            }
        }
    }
}

async fn reissue(
    mut rng: OsRng,
    cfg: ClientConfig,
    coins: Vec<SpendableCoin>,
) -> (Duration, Vec<SpendableCoin>) {
    let begin = Instant::now();
    debug!("Sending reissuance request for {} coins", coins.len());
    let issuance_req = request_reissuance(&cfg, coins, &mut rng).await;
    let coins = fetch_coins(&cfg, issuance_req)
        .await
        .expect("Couldn't acquire coins");

    let time_passed = Instant::now().duration_since(begin);
    debug!(
        "Received {} valid coins after {}s",
        coins.len(),
        time_passed.as_secs_f32()
    );
    (time_passed, coins)
}

async fn fetch_coins(
    cfg: &ClientConfig,
    req: IssuanceRequest,
) -> Result<Vec<SpendableCoin>, CoinFinalizationError> {
    let client = reqwest::Client::new();
    let resp: SigResponse = loop {
        let url = format!("{}/issuance/{}", cfg.mints[0], req.id());

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

    for url in cfg.mints.choose_multiple(&mut rng, 2) {
        let res = client
            .put(&format!("{}/issuance/pegin", url))
            .json(&req)
            .send()
            .await
            .expect("API error");

        if res.status() != StatusCode::OK {
            error!("API returned error when pegging in: {:?}", res.status());
            exit(-1);
        }
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
    let rng_adapt = musig::rng_adapt::RngAdaptor(&mut rng);
    let sig = musig::sign(digest, spend_keys.iter(), rng_adapt);

    let req = ReissuanceRequest {
        coins,
        blind_tokens: sig_req,
        sig,
    };
    let client = reqwest::Client::new();
    for url in cfg.mints.choose_multiple(&mut rng, 2) {
        let res = client
            .put(&format!("{}/issuance/reissue", url))
            .json(&req)
            .send()
            .await
            .expect("API error");

        if res.status() != StatusCode::OK {
            error!("API returned error when reissuing: {:?}", res.status());
            exit(-1);
        }
    }

    issuance_req
}
