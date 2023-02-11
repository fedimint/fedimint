use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::hash::Hasher;
use std::path::PathBuf;

use bitcoin::hashes::sha256::Hash;
use bitcoin::OutPoint;
use clap::{ArgGroup, Parser};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
use fedimint_core::db::Database;
use fedimint_rocksdb::RocksDb;
use fedimint_server::config::io::read_server_config;
use fedimint_wallet::config::WalletConfig;
use fedimint_wallet::db::{UTXOKey, UTXOPrefixKey};
use fedimint_wallet::keys::CompressedPublicKey;
use fedimint_wallet::tweakable::Tweakable;
use fedimint_wallet::{PegInDescriptor, SpendableUTXO};
use futures::stream::StreamExt;
use miniscript::{Descriptor, MiniscriptKey, ToPublicKey, TranslatePk, Translator};
use secp256k1::SecretKey;
use serde::Serialize;
use tracing_subscriber::EnvFilter;

/// Tool to recover the on-chain wallet of a Fedimint federation
#[derive(Debug, Parser)]
#[command(group(
    ArgGroup::new("keysource")
        .required(true)
        .args(["config", "descriptor"]),
))]
struct RecoveryTool {
    /// Extract UTXOs from a database without module partitioning
    #[arg(long = "legacy")]
    legacy: bool,
    /// Path to database
    #[arg(long = "db")]
    db: PathBuf,
    /// Directory containing server config files
    #[arg(long = "cfg")]
    config: Option<PathBuf>,
    /// The password that encrypts the configs
    #[arg(long = "password", env = "FM_PASSWORD", requires = "config")]
    password: String,
    /// Wallet descriptor, can be used instead of --cfg
    #[arg(long = "descriptor")]
    descriptor: Option<PegInDescriptor>,
    /// Wallet secret key, can be used instead of config together with
    /// --descriptor
    #[arg(long = "key", requires = "descriptor")]
    key: Option<SecretKey>,
    /// Network to operate on, has to be specified if --cfg isn't present
    #[arg(long = "network", default_value = "bitcoin", requires = "descriptor")]
    network: bitcoin::network::constants::Network,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("error,mint_client=info,fedimint_cli=info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let opts: RecoveryTool = RecoveryTool::parse();

    let (base_descriptor, base_key, network) = if let Some(config) = opts.config {
        let cfg = read_server_config(&opts.password, config).expect("Could not read config file");
        let wallet_cfg: WalletConfig = cfg
            .get_module_config_typed(LEGACY_HARDCODED_INSTANCE_ID_WALLET)
            .expect("Malformed wallet config");
        let base_descriptor = wallet_cfg.consensus.peg_in_descriptor;
        let base_key = wallet_cfg.private.peg_in_key;
        let network = wallet_cfg.consensus.network;

        (base_descriptor, base_key, network)
    } else if let (Some(descriptor), Some(key)) = (opts.descriptor, opts.key) {
        (descriptor, key, opts.network)
    } else {
        panic!("Either config or descriptor will be provided by clap");
    };

    let db = Database::new(
        RocksDb::open(opts.db).expect("Error opening DB"),
        Default::default(),
    );

    let db = if opts.legacy {
        db
    } else {
        db.new_isolated(LEGACY_HARDCODED_INSTANCE_ID_WALLET)
    };

    let ctx = secp256k1::Secp256k1::new();

    let utxos: Vec<ImportableWallet> = db
        .begin_transaction()
        .await
        .find_by_prefix(&UTXOPrefixKey)
        .await
        .map(|res| {
            let (UTXOKey(outpoint), SpendableUTXO { tweak, amount }) = res.expect("DB error");
            let secret_key = base_key.tweak(&tweak, &ctx);
            let pub_key =
                CompressedPublicKey::new(secp256k1::PublicKey::from_secret_key_global(&secret_key));
            let descriptor = base_descriptor
                .tweak(&tweak, &ctx)
                .translate_pk(&mut SecretKeyInjector {
                    secret: bitcoin::util::key::PrivateKey {
                        compressed: true,
                        network,
                        inner: secret_key,
                    },
                    public: pub_key,
                })
                .expect("can't fail");

            ImportableWallet {
                outpoint,
                descriptor,
                amount_sat: amount,
            }
        })
        .collect()
        .await;

    serde_json::to_writer(std::io::stdout().lock(), &utxos).expect("Could not encode to stdout")
}

/// A UTXO with its Bitcoin Core importable descriptor
#[derive(Debug, Serialize)]
struct ImportableWallet {
    outpoint: OutPoint,
    descriptor: Descriptor<Key>,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    amount_sat: bitcoin::Amount,
}

/// `MiniscriptKey` that is either a WIF-encoded private key or a compressed,
/// hex-encoded public key
#[derive(Debug, Clone, Copy, Eq)]
enum Key {
    Public(CompressedPublicKey),
    Private(bitcoin::util::key::PrivateKey),
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_compressed_public_key()
            .partial_cmp(&other.to_compressed_public_key())
    }
}

impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_compressed_public_key()
            .cmp(&other.to_compressed_public_key())
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.to_compressed_public_key()
            .eq(&other.to_compressed_public_key())
    }
}

impl std::hash::Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_compressed_public_key().hash(state)
    }
}

impl Key {
    fn to_compressed_public_key(self) -> CompressedPublicKey {
        match self {
            Key::Public(pk) => pk,
            Key::Private(sk) => {
                CompressedPublicKey::new(secp256k1::PublicKey::from_secret_key_global(&sk.inner))
            }
        }
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Public(pk) => Display::fmt(pk, f),
            Key::Private(sk) => Display::fmt(sk, f),
        }
    }
}

impl MiniscriptKey for Key {
    fn is_uncompressed(&self) -> bool {
        false
    }

    type RawPkHash = Key;
    type Sha256 = bitcoin::hashes::sha256::Hash;
    type Hash256 = miniscript::hash256::Hash;
    type Ripemd160 = bitcoin::hashes::ripemd160::Hash;
    type Hash160 = bitcoin::hashes::hash160::Hash;

    fn to_pubkeyhash(&self) -> Self::RawPkHash {
        *self
    }
}

impl ToPublicKey for Key {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        self.to_compressed_public_key().to_public_key()
    }

    fn hash_to_hash160(
        hash: &<Self as MiniscriptKey>::RawPkHash,
    ) -> bitcoin::hashes::hash160::Hash {
        <CompressedPublicKey as ToPublicKey>::hash_to_hash160(&hash.to_compressed_public_key())
    }

    fn to_sha256(hash: &<Self as MiniscriptKey>::Sha256) -> Hash {
        *hash
    }

    fn to_hash256(hash: &<Self as MiniscriptKey>::Hash256) -> miniscript::hash256::Hash {
        *hash
    }

    fn to_ripemd160(hash: &<Self as MiniscriptKey>::Ripemd160) -> bitcoin::hashes::ripemd160::Hash {
        *hash
    }

    fn to_hash160(hash: &<Self as MiniscriptKey>::Hash160) -> bitcoin::hashes::hash160::Hash {
        *hash
    }
}

/// Miniscript [`Translator`] that replaces a public key with a private key we
/// know.
#[derive(Debug)]
struct SecretKeyInjector {
    secret: bitcoin::util::key::PrivateKey,
    public: CompressedPublicKey,
}

impl Translator<CompressedPublicKey, Key, ()> for SecretKeyInjector {
    fn pk(&mut self, pk: &CompressedPublicKey) -> Result<Key, ()> {
        if &self.public == pk {
            Ok(Key::Private(self.secret))
        } else {
            Ok(Key::Public(*pk))
        }
    }

    fn pkh(
        &mut self,
        pkh: &<CompressedPublicKey as MiniscriptKey>::RawPkHash,
    ) -> Result<<Key as MiniscriptKey>::RawPkHash, ()> {
        if &self.public == pkh {
            Ok(Key::Private(self.secret))
        } else {
            Ok(Key::Public(*pkh))
        }
    }

    fn sha256(
        &mut self,
        _sha256: &<CompressedPublicKey as MiniscriptKey>::Sha256,
    ) -> Result<<Key as MiniscriptKey>::Sha256, ()> {
        unimplemented!()
    }

    fn hash256(
        &mut self,
        _hash256: &<CompressedPublicKey as MiniscriptKey>::Hash256,
    ) -> Result<<Key as MiniscriptKey>::Hash256, ()> {
        unimplemented!()
    }

    fn ripemd160(
        &mut self,
        _ripemd160: &<CompressedPublicKey as MiniscriptKey>::Ripemd160,
    ) -> Result<<Key as MiniscriptKey>::Ripemd160, ()> {
        unimplemented!()
    }

    fn hash160(
        &mut self,
        _hash160: &<CompressedPublicKey as MiniscriptKey>::Hash160,
    ) -> Result<<Key as MiniscriptKey>::Hash160, ()> {
        unimplemented!()
    }
}
