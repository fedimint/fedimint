#![deny(clippy::pedantic)]

mod envs;
mod key;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use bitcoin::OutPoint;
use bitcoin::network::Network;
use bitcoin::secp256k1::{PublicKey, SECP256K1, SecretKey};
use clap::{ArgGroup, Parser, Subcommand};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::fedimint_build_code_version_env;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::session_outcome::SignedSessionOutcome;
use fedimint_core::transaction::Transaction;
use fedimint_core::util::handle_version_hash_command;
use fedimint_logging::TracingSetup;
use fedimint_rocksdb::RocksDbReadOnly;
use fedimint_server::config::ServerConfig;
use fedimint_server::config::io::read_server_config;
use fedimint_server::consensus::db::SignedSessionOutcomePrefix;
use fedimint_server::core::ServerModule;
use fedimint_wallet_server::common::config::WalletConfig;
use fedimint_wallet_server::common::keys::CompressedPublicKey;
use fedimint_wallet_server::common::tweakable::Tweakable;
use fedimint_wallet_server::common::{
    PegInDescriptor, SpendableUTXO, WalletCommonInit, WalletInput,
};
use fedimint_wallet_server::db::{UTXOKey, UTXOPrefixKey};
use fedimint_wallet_server::{Wallet, nonce_from_idx};
use futures::stream::StreamExt;
use hex::FromHex;
use miniscript::{Descriptor, MiniscriptKey, TranslatePk, Translator};
use serde::Serialize;
use tracing::info;

use crate::envs::FM_PASSWORD_ENV;
use crate::key::Key;

/// Tool to recover the on-chain wallet of a Fedimint federation
#[derive(Debug, Parser)]
#[command(version)]
#[command(group(
    ArgGroup::new("keysource")
        .required(true)
        .args(["config", "descriptor"]),
))]
struct RecoveryTool {
    /// Directory containing server config files
    #[arg(long = "cfg")]
    config: Option<PathBuf>,
    /// The password that encrypts the configs
    #[arg(long, env = FM_PASSWORD_ENV, requires = "config")]
    password: String,
    /// Wallet descriptor, can be used instead of --cfg
    #[arg(long)]
    descriptor: Option<PegInDescriptor>,
    /// Wallet secret key, can be used instead of config together with
    /// --descriptor
    #[arg(long, requires = "descriptor")]
    key: Option<SecretKey>,
    /// Network to operate on, has to be specified if --cfg isn't present
    #[arg(long, default_value = "bitcoin", requires = "descriptor")]
    network: Network,
    #[command(subcommand)]
    strategy: TweakSource,
}

#[derive(Debug, Clone, Subcommand)]
enum TweakSource {
    /// Derive the wallet descriptor using a single tweak
    Direct {
        #[arg(long, value_parser = tweak_parser)]
        tweak: [u8; 33],
    },
    /// Derive all wallet descriptors of confirmed UTXOs in the on-chain wallet.
    /// Note that unconfirmed change UTXOs will not appear here.
    Utxos {
        /// Extract UTXOs from a database without module partitioning
        #[arg(long)]
        legacy: bool,
        /// Path to database
        #[arg(long)]
        db: PathBuf,
    },
    /// Derive all wallet descriptors of tweaks that were ever used according to
    /// the epoch log. In a long-running and busy federation this list will
    /// contain many empty descriptors.
    Epochs {
        /// Path to database
        #[arg(long)]
        db: PathBuf,
    },
}

fn tweak_parser(hex: &str) -> anyhow::Result<[u8; 33]> {
    <Vec<u8> as FromHex>::from_hex(hex)?
        .try_into()
        .map_err(|_| anyhow!("tweaks have to be 33 bytes long"))
}

/// Get the wallet module instance ID from a server config by looking up the
/// module kind
fn get_wallet_module_id(cfg: &ServerConfig) -> anyhow::Result<ModuleInstanceId> {
    cfg.consensus
        .modules
        .iter()
        .find_map(|(id, module_cfg)| {
            if module_cfg.kind == WalletCommonInit::KIND {
                Some(*id)
            } else {
                None
            }
        })
        .context("Wallet module not found in config")
}

async fn get_db(path: &Path, module_decoders: ModuleDecoderRegistry) -> Database {
    Database::new(
        RocksDbReadOnly::open_read_only(path)
            .await
            .expect("Error opening readonly DB"),
        module_decoders,
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    handle_version_hash_command(fedimint_build_code_version_env!());

    let opts: RecoveryTool = RecoveryTool::parse();

    let (base_descriptor, base_key, network, wallet_module_id) = if let Some(config) = opts.config {
        let cfg = read_server_config(&opts.password, &config).expect("Could not read config file");
        let wallet_module_id =
            get_wallet_module_id(&cfg).expect("Wallet module not found in config");
        let wallet_cfg: WalletConfig = cfg
            .get_module_config_typed(wallet_module_id)
            .expect("Malformed wallet config");
        let base_descriptor = wallet_cfg.consensus.peg_in_descriptor;
        let base_key = wallet_cfg.private.peg_in_key;
        let network = wallet_cfg.consensus.network.0;

        (base_descriptor, base_key, network, wallet_module_id)
    } else if let (Some(descriptor), Some(key)) = (opts.descriptor, opts.key) {
        // When using descriptor directly without config, we don't have a known wallet
        // module ID. Use 0 as a placeholder since it's only used for DB
        // prefix/decoder matching which isn't needed with direct descriptor usage.
        (descriptor, key, opts.network, 0)
    } else {
        panic!("Either config or descriptor need to be provided by clap");
    };

    process_and_print_tweak_source(
        &opts.strategy,
        &base_descriptor,
        &base_key,
        network,
        wallet_module_id,
    )
    .await;

    Ok(())
}

async fn process_and_print_tweak_source(
    tweak_source: &TweakSource,
    base_descriptor: &Descriptor<CompressedPublicKey>,
    base_key: &SecretKey,
    network: Network,
    wallet_module_id: ModuleInstanceId,
) {
    match tweak_source {
        TweakSource::Direct { tweak } => {
            let descriptor = tweak_descriptor(base_descriptor, base_key, tweak, network);
            let wallets = vec![ImportableWalletMin { descriptor }];

            serde_json::to_writer(std::io::stdout().lock(), &wallets)
                .expect("Could not encode to stdout");
        }
        TweakSource::Utxos { legacy, db } => {
            let db = get_db(db, ModuleRegistry::default()).await;

            let db = if *legacy {
                db
            } else {
                db.with_prefix_module_id(wallet_module_id).0
            };

            let utxos: Vec<ImportableWallet> = db
                .begin_transaction_nc()
                .await
                .find_by_prefix(&UTXOPrefixKey)
                .await
                .map(|(UTXOKey(outpoint), SpendableUTXO { tweak, amount })| {
                    let descriptor = tweak_descriptor(base_descriptor, base_key, &tweak, network);

                    ImportableWallet {
                        outpoint,
                        descriptor,
                        amount_sat: amount,
                    }
                })
                .collect()
                .await;

            serde_json::to_writer(std::io::stdout().lock(), &utxos)
                .expect("Could not encode to stdout");
        }
        TweakSource::Epochs { db } => {
            let decoders = ModuleDecoderRegistry::from_iter([(
                wallet_module_id,
                WalletCommonInit::KIND,
                <Wallet as ServerModule>::decoder(),
            )])
            .with_fallback();

            let db = get_db(db, decoders).await;
            let mut dbtx = db.begin_transaction_nc().await;

            let mut change_tweak_idx: u64 = 0;

            let tweaks = dbtx
                .find_by_prefix(&SignedSessionOutcomePrefix)
                .await
                .flat_map(
                    |(
                        _key,
                        SignedSessionOutcome {
                            session_outcome: block,
                            ..
                        },
                    )| {
                        let transaction_cis: Vec<Transaction> = block
                            .items
                            .into_iter()
                            .filter_map(|item| match item.item {
                                ConsensusItem::Transaction(tx) => Some(tx),
                                ConsensusItem::Module(_) | ConsensusItem::Default { .. } => None,
                            })
                            .collect();

                        // Get all user-submitted tweaks and number of peg-out transactions in
                        // session
                        let (mut peg_in_tweaks, peg_out_count) = input_tweaks_and_peg_out_count(
                            transaction_cis.into_iter(),
                            wallet_module_id,
                        );

                        for _ in 0..peg_out_count {
                            info!("Found change output, adding tweak {change_tweak_idx} to list");
                            peg_in_tweaks.insert(nonce_from_idx(change_tweak_idx));
                            change_tweak_idx += 1;
                        }

                        futures::stream::iter(peg_in_tweaks.into_iter())
                    },
                );

            let wallets = tweaks
                .map(|tweak| {
                    let descriptor = tweak_descriptor(base_descriptor, base_key, &tweak, network);
                    ImportableWalletMin { descriptor }
                })
                .collect::<Vec<_>>()
                .await;

            serde_json::to_writer(std::io::stdout().lock(), &wallets)
                .expect("Could not encode to stdout");
        }
    }
}

fn input_tweaks_and_peg_out_count(
    transactions: impl Iterator<Item = Transaction>,
    wallet_module_id: ModuleInstanceId,
) -> (BTreeSet<[u8; 33]>, u64) {
    let mut peg_out_count = 0;
    let tweaks = transactions
        .flat_map(|tx| {
            tx.outputs.iter().for_each(|output| {
                if output.module_instance_id() == wallet_module_id {
                    peg_out_count += 1;
                }
            });

            tx.inputs.into_iter().filter_map(|input| {
                if input.module_instance_id() != wallet_module_id {
                    return None;
                }

                Some(
                    match input
                        .as_any()
                        .downcast_ref::<WalletInput>()
                        .expect("Instance id mapping incorrect")
                    {
                        WalletInput::V0(input) => input.tweak_key().serialize(),
                        WalletInput::V1(input) => input.tweak_key.serialize(),
                        WalletInput::Default { .. } => {
                            panic!("recoverytool only supports v0 wallet inputs")
                        }
                    },
                )
            })
        })
        .collect::<BTreeSet<_>>();

    (tweaks, peg_out_count)
}

fn tweak_descriptor(
    base_descriptor: &PegInDescriptor,
    base_sk: &SecretKey,
    tweak: &[u8; 33],
    network: Network,
) -> Descriptor<Key> {
    let secret_key = base_sk.tweak(tweak, SECP256K1);
    let pub_key = CompressedPublicKey::new(PublicKey::from_secret_key_global(&secret_key));
    base_descriptor
        .tweak(tweak, SECP256K1)
        .translate_pk(&mut SecretKeyInjector {
            secret: bitcoin::key::PrivateKey {
                compressed: true,
                network: network.into(),
                inner: secret_key,
            },
            public: pub_key,
        })
        .expect("can't fail")
}

/// A UTXO with its Bitcoin Core importable descriptor
#[derive(Debug, Serialize)]
struct ImportableWallet {
    outpoint: OutPoint,
    descriptor: Descriptor<Key>,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    amount_sat: bitcoin::Amount,
}

/// A Bitcoin Core importable descriptor
#[derive(Debug, Serialize)]
struct ImportableWalletMin {
    descriptor: Descriptor<Key>,
}

/// Miniscript [`Translator`] that replaces a public key with a private key we
/// know.
#[derive(Debug)]
struct SecretKeyInjector {
    secret: bitcoin::key::PrivateKey,
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

#[test]
fn parses_valid_length_tweaks() {
    use hex::ToHex;

    let bad_length_tweak_hex = rand::random::<[u8; 32]>().encode_hex::<String>();
    // rand::random only supports random byte arrays up to 32 bytes
    let good_length_tweak: [u8; 33] = core::array::from_fn(|_| rand::random::<u8>());
    let good_length_tweak_hex = good_length_tweak.encode_hex::<String>();
    assert_eq!(
        tweak_parser(good_length_tweak_hex.as_str()).expect("should parse valid length hex"),
        good_length_tweak
    );
    assert!(tweak_parser(bad_length_tweak_hex.as_str()).is_err());
}
