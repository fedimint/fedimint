use crate::api::FederationApi;
use crate::mint::SpendableCoin;
use bitcoin::Network;
use lightning_invoice::Currency;
use minimint_api::db::Database;
use minimint_api::encoding::Decodable;
use minimint_core::modules::mint::tiered::coins::Coins;

pub fn parse_coins(s: &str) -> Coins<SpendableCoin> {
    let bytes = base64::decode(s).unwrap();
    bincode::deserialize(&bytes).unwrap()
}

pub fn serialize_coins(c: &Coins<SpendableCoin>) -> String {
    let bytes = bincode::serialize(&c).unwrap();
    base64::encode(&bytes)
}

pub fn from_hex<D: Decodable>(s: &str) -> Result<D, anyhow::Error> {
    let bytes = hex::decode(s)?;
    Ok(D::consensus_decode(std::io::Cursor::new(bytes))?)
}

pub fn parse_bitcoin_amount(
    s: &str,
) -> Result<bitcoin::Amount, bitcoin::util::amount::ParseAmountError> {
    bitcoin::Amount::from_str_in(s, bitcoin::Denomination::Satoshi)
}

pub struct BorrowedClientContext<'a, C> {
    pub config: &'a C,
    pub db: &'a dyn Database,
    pub api: &'a dyn FederationApi,
    pub secp: &'a secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
}

pub struct OwnedClientContext<C> {
    pub config: C,
    pub db: Box<dyn Database>,
    pub api: Box<dyn FederationApi>,
    pub secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
}

impl<CO> OwnedClientContext<CO> {
    pub fn borrow_with_module_config<'c, CB, F>(
        &'c self,
        to_cfg: F,
    ) -> BorrowedClientContext<'c, CB>
    where
        F: FnOnce(&'c CO) -> &'c CB,
    {
        BorrowedClientContext {
            config: to_cfg(&self.config),
            db: self.db.as_ref(),
            api: self.api.as_ref(),
            secp: &self.secp,
        }
    }
}

pub fn network_to_currency(network: Network) -> Currency {
    match network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Regtest => Currency::Regtest,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Signet => Currency::Signet,
    }
}
