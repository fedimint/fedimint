use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Config {
    federation_size: usize,
    identity: usize,
    port: u16,
}