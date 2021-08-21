use database::{BincodeSerialized, DatabaseKeyPrefix, PrefixSearchable};
use minimint::consensus::ConsensusItem;
use minimint::database::{
    AllConsensusItemsKeyPrefix, AllPartialSignaturesKey, PartialSignatureKey, TransactionStatusKey,
    DB_PREFIX_TX_STATUS,
};
use mint_api::{PartialSigResponse, SigResponse};
use serde::Serialize;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opts {
    db: PathBuf,
    table: Tables,
}

enum Tables {
    ConsensusItem,
    FinalizedSignature,
    PartialSiganture,
}

impl FromStr for Tables {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ci" => Ok(Tables::ConsensusItem),
            "sig" => Ok(Tables::FinalizedSignature),
            "part" => Ok(Tables::PartialSiganture),
            _ => Err("Unknown table"),
        }
    }
}

#[derive(Debug)]
pub struct AllFinalizedSignatures;

impl DatabaseKeyPrefix for AllFinalizedSignatures {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_TX_STATUS]
    }
}

#[derive(Serialize)]
struct Element<K, V> {
    key: K,
    value: V,
}

fn main() {
    let opts: Opts = StructOpt::from_args();

    let db = sled::open(&opts.db).unwrap().open_tree("mint").unwrap();
    let mut stdout = std::io::stdout();

    match opts.table {
        Tables::ConsensusItem => {
            for item in db.find_by_prefix::<_, ConsensusItem, ()>(&AllConsensusItemsKeyPrefix) {
                let ci = item.expect("DB error").0;
                serde_json::to_writer_pretty(&mut stdout, &ci).unwrap();
            }
        }
        Tables::FinalizedSignature => {
            for item in db
                .find_by_prefix::<_, TransactionStatusKey, BincodeSerialized<SigResponse>>(
                    &AllFinalizedSignatures,
                )
            {
                let (key, value) = item.expect("DB error");
                serde_json::to_writer_pretty(
                    &mut stdout,
                    &Element {
                        key,
                        value: value.into_owned(),
                    },
                )
                .unwrap();
            }
        }
        Tables::PartialSiganture => {
            for item in db
                .find_by_prefix::<_, PartialSignatureKey, BincodeSerialized<PartialSigResponse>>(
                    &AllPartialSignaturesKey,
                )
            {
                let (key, value) = item.expect("DB error");
                serde_json::to_writer_pretty(
                    &mut stdout,
                    &Element {
                        key,
                        value: value.into_owned(),
                    },
                )
                .unwrap();
            }
        }
    }
}
