use structopt::StructOpt;

mod config;

fn main() {
    let cfg: config::Config = StructOpt::from_args();
}
