use bitcoin_hashes::hex::ToHex;
use clap::Parser;
use serde::Serialize;
use tbs::dealer_keygen;

#[derive(Parser)]
struct Args {
    number: usize,
    threshold: usize,
}

fn main() {
    let args = Args::parse();

    let (pk, pks, sks) = dealer_keygen(args.threshold, args.number);

    println!("apk={}", to_hex(&pk));
    for (idx, (pk, sk)) in pks.iter().zip(sks.iter()).enumerate() {
        println!("peer {}: pk={}; sk={}", idx, to_hex(&pk), to_hex(&sk));
    }
}

fn to_hex<T: Serialize>(obj: &T) -> String {
    let bytes = bincode::serialize(obj).unwrap();
    bytes.to_hex()
}
