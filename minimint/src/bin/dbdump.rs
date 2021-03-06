use database::PrefixSearchable;
use minimint::consensus::ConsensusItem;
use minimint::database::AllConsensusItemsKeyPrefix;
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
}

impl FromStr for Tables {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ci" => Ok(Tables::ConsensusItem),
            _ => Err("Unknown table"),
        }
    }
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
    }
}
