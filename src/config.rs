use structopt::StructOpt;

#[derive(Debug, Clone, StructOpt)]
pub struct Config {
    pub federation_size: u16,
    pub identity: u16,
    pub base_port: u16,
}

impl Config {
    pub fn get_my_port(&self) -> u16 {
        self.base_port + self.identity
    }
    pub fn get_api_port(&self) -> u16 {
        self.base_port + self.federation_size + self.identity
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.identity
    }
}
