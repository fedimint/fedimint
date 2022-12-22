use std::collections::BTreeMap;

use docopt::Docopt;
use erased_serde::Serialize;
use fedimint_api::db::ReadOnlyDatabaseTransaction;
use fedimint_api::encoding::Encodable;
use fedimint_core::all_decoders;
use fedimint_ln::db as LightningRange;
use fedimint_mint::db as MintRange;
use fedimint_rocksdb::RocksDbReadOnly;
use fedimint_server::db as ConsensusRange;
use fedimint_wallet::db as WalletRange;
use mint_client::db as ClientRange;
use mint_client::ln::db as ClientLightningRange;
use mint_client::mint::db as ClientMintRange;
use mint_client::wallet::db as ClientWalletRange;
use serde::Deserialize;
use strum::IntoEnumIterator;

macro_rules! filter_prefixes {
    ($table:ident, $self:ident) => {
        if !$self.include_all_prefixes
            && !$self.prefixes.contains(&$table.to_string().to_lowercase())
        {
            continue;
        }
    };
}

macro_rules! push_db_pair_items {
    ($self:ident, $prefix_type:expr, $key_type:ty, $value_type:ty, $map:ident, $key_literal:literal) => {
        let db_items = $self.read_only.find_by_prefix(&$prefix_type).await;
        let mut items: Vec<($key_type, $value_type)> = Vec::new();
        for item in db_items {
            items.push(item.unwrap());
        }
        $map.insert($key_literal.to_string(), Box::new(items));
    };
}

#[derive(Debug, serde::Serialize)]
struct SerdeWrapper(#[serde(with = "hex::serde")] Vec<u8>);

impl SerdeWrapper {
    fn from_encodable<T: Encodable>(e: T) -> SerdeWrapper {
        let mut bytes = vec![];
        e.consensus_encode(&mut bytes)
            .expect("Write to vec can't fail");
        SerdeWrapper(bytes)
    }
}

macro_rules! push_db_pair_items_no_serde {
    ($self:ident, $prefix_type:expr, $key_type:ty, $value_type:ty, $map:ident, $key_literal:literal) => {
        let db_items = $self.read_only.find_by_prefix(&$prefix_type).await;
        let mut items: Vec<($key_type, SerdeWrapper)> = Vec::new();
        for item in db_items {
            let (k, v) = item.unwrap();
            items.push((k, SerdeWrapper::from_encodable(v)));
        }
        $map.insert($key_literal.to_string(), Box::new(items));
    };
}

macro_rules! push_db_key_items {
    ($self:ident, $prefix_type:expr, $key_type:ty, $map:ident, $key_literal:literal) => {
        let db_items = $self.read_only.find_by_prefix(&$prefix_type).await;
        let mut items: Vec<$key_type> = Vec::new();
        for item in db_items {
            items.push(item.unwrap().0);
        }
        $map.insert($key_literal.to_string(), Box::new(items));
    };
}

/// Structure to hold the deserialized structs from the database.
/// Also includes metadata on which sections of the database to read.
struct DatabaseDump<'a> {
    serialized: BTreeMap<String, Box<dyn Serialize>>,
    read_only: ReadOnlyDatabaseTransaction<'a>,
    ranges: Vec<String>,
    prefixes: Vec<String>,
    include_all_prefixes: bool,
}

impl<'a> DatabaseDump<'a> {
    /// Prints the contents of the BTreeMap to a pretty JSON string
    fn print_database(&self) {
        let json = serde_json::to_string_pretty(&self.serialized).unwrap();
        println!("{}", json);
    }

    /// Iterates through all the specified ranges in the database and retrieves the
    /// data for each range. Prints serialized contents at the end.
    pub async fn dump_database(&mut self) {
        for range in self.ranges.clone() {
            match range.as_str() {
                "consensus" => {
                    self.get_consensus_data().await;
                }
                "mint" => {
                    self.get_mint_data().await;
                }
                "wallet" => {
                    self.get_wallet_data().await;
                }
                "lightning" => {
                    self.get_lightning_data().await;
                }
                "mintclient" => {
                    self.get_mint_client_data().await;
                }
                "lightningclient" => {
                    self.get_ln_client_data().await;
                }
                "walletclient" => {
                    self.get_wallet_client_data().await;
                }
                "client" => {
                    self.get_client_data().await;
                }
                _ => {}
            }
        }

        self.print_database();
    }

    /// Iterates through each of the prefixes within the consensus range and retrieves
    /// the corresponding data.
    async fn get_consensus_data(&mut self) {
        let mut consensus: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();

        for table in ConsensusRange::DbKeyPrefix::iter() {
            filter_prefixes!(table, self);

            match table {
                ConsensusRange::DbKeyPrefix::ProposedTransaction => {
                    push_db_pair_items_no_serde!(
                        self,
                        ConsensusRange::ProposedTransactionKeyPrefix,
                        ConsensusRange::ProposedTransactionKey,
                        fedimint_core::transaction::Transaction,
                        consensus,
                        "Pending Transactions"
                    );
                }
                ConsensusRange::DbKeyPrefix::AcceptedTransaction => {
                    push_db_pair_items_no_serde!(
                        self,
                        ConsensusRange::AcceptedTransactionKeyPrefix,
                        ConsensusRange::AcceptedTransactionKey,
                        fedimint_server::consensus::AcceptedTransaction,
                        consensus,
                        "Accepted Transactions"
                    );
                }
                ConsensusRange::DbKeyPrefix::DropPeer => {
                    push_db_key_items!(
                        self,
                        ConsensusRange::DropPeerKeyPrefix,
                        ConsensusRange::DropPeerKey,
                        consensus,
                        "Dropped Peers"
                    );
                }
                ConsensusRange::DbKeyPrefix::RejectedTransaction => {
                    push_db_pair_items!(
                        self,
                        ConsensusRange::RejectedTransactionKeyPrefix,
                        ConsensusRange::RejectedTransactionKey,
                        String,
                        consensus,
                        "Rejected Transactions"
                    );
                }
                ConsensusRange::DbKeyPrefix::EpochHistory => {
                    push_db_pair_items_no_serde!(
                        self,
                        ConsensusRange::EpochHistoryKeyPrefix,
                        ConsensusRange::EpochHistoryKey,
                        fedimint_core::epoch::EpochHistory,
                        consensus,
                        "Epoch History"
                    );
                }
                ConsensusRange::DbKeyPrefix::LastEpoch => {
                    let last_epoch = self
                        .read_only
                        .get_value(&ConsensusRange::LastEpochKey)
                        .await
                        .unwrap();
                    if let Some(last_epoch) = last_epoch {
                        consensus.insert("LastEpoch".to_string(), Box::new(last_epoch));
                    }
                }
            }
        }

        self.serialized
            .insert("Consensus".to_string(), Box::new(consensus));
    }

    /// Iterates through each of the prefixes within the mint range and retrieves
    /// the corresponding data.
    async fn get_mint_data(&mut self) {
        let mut mint: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        for table in MintRange::DbKeyPrefix::iter() {
            filter_prefixes!(table, self);

            match table {
                MintRange::DbKeyPrefix::CoinNonce => {
                    push_db_key_items!(
                        self,
                        MintRange::NonceKeyPrefix,
                        MintRange::NonceKey,
                        mint,
                        "Used Coins"
                    );
                }
                MintRange::DbKeyPrefix::MintAuditItem => {
                    push_db_pair_items!(
                        self,
                        MintRange::MintAuditItemKeyPrefix,
                        MintRange::MintAuditItemKey,
                        fedimint_api::Amount,
                        mint,
                        "Mint Audit Items"
                    );
                }
                MintRange::DbKeyPrefix::OutputOutcome => {
                    push_db_pair_items!(
                        self,
                        MintRange::OutputOutcomeKeyPrefix,
                        MintRange::OutputOutcomeKey,
                        fedimint_mint::OutputOutcome,
                        mint,
                        "Output Outcomes"
                    );
                }
                MintRange::DbKeyPrefix::ProposedPartialSig => {
                    push_db_pair_items!(
                        self,
                        MintRange::ProposedPartialSignaturesKeyPrefix,
                        MintRange::ProposedPartialSignatureKey,
                        fedimint_mint::OutputConfirmationSignatures,
                        mint,
                        "Proposed Signature Shares"
                    );
                }
                MintRange::DbKeyPrefix::ReceivedPartialSig => {
                    push_db_pair_items!(
                        self,
                        MintRange::ReceivedPartialSignaturesKeyPrefix,
                        MintRange::ReceivedPartialSignatureKey,
                        fedimint_mint::OutputConfirmationSignatures,
                        mint,
                        "Received Signature Shares"
                    );
                }
                MintRange::DbKeyPrefix::EcashBackup => {
                    push_db_pair_items!(
                        self,
                        MintRange::EcashBackupKeyPrefix,
                        MintRange::EcashBackupKey,
                        fedimint_mint::db::ECashUserBackupSnapshot,
                        mint,
                        "User Ecash Backup"
                    );
                }
            }
        }

        self.serialized.insert("Mint".to_string(), Box::new(mint));
    }

    /// Iterates through each of the prefixes within the wallet range and retrieves
    /// the corresponding data.
    async fn get_wallet_data(&mut self) {
        let mut wallet: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        for table in WalletRange::DbKeyPrefix::iter() {
            filter_prefixes!(table, self);

            match table {
                WalletRange::DbKeyPrefix::BlockHash => {
                    push_db_key_items!(
                        self,
                        WalletRange::BlockHashKeyPrefix,
                        WalletRange::BlockHashKey,
                        wallet,
                        "Blocks"
                    );
                }
                WalletRange::DbKeyPrefix::PegOutBitcoinOutPoint => {
                    push_db_pair_items!(
                        self,
                        WalletRange::PegOutBitcoinTransactionPrefix,
                        WalletRange::PegOutBitcoinTransaction,
                        fedimint_wallet::WalletOutputOutcome,
                        wallet,
                        "Peg Out Bitcoin Transaction"
                    );
                }
                WalletRange::DbKeyPrefix::PegOutTxSigCi => {
                    push_db_pair_items!(
                        self,
                        WalletRange::PegOutTxSignatureCIPrefix,
                        WalletRange::PegOutTxSignatureCI,
                        Vec<secp256k1::ecdsa::Signature>,
                        wallet,
                        "Peg Out Transaction Signatures"
                    );
                }
                WalletRange::DbKeyPrefix::PendingTransaction => {
                    push_db_pair_items!(
                        self,
                        WalletRange::PendingTransactionPrefixKey,
                        WalletRange::PendingTransactionKey,
                        fedimint_wallet::PendingTransaction,
                        wallet,
                        "Pending Transactions"
                    );
                }
                WalletRange::DbKeyPrefix::RoundConsensus => {
                    let round_consensus = self
                        .read_only
                        .get_value(&WalletRange::RoundConsensusKey)
                        .await
                        .unwrap();
                    if let Some(round_consensus) = round_consensus {
                        wallet.insert("Round Consensus".to_string(), Box::new(round_consensus));
                    }
                }
                WalletRange::DbKeyPrefix::UnsignedTransaction => {
                    push_db_pair_items!(
                        self,
                        WalletRange::UnsignedTransactionPrefixKey,
                        WalletRange::UnsignedTransactionKey,
                        fedimint_wallet::UnsignedTransaction,
                        wallet,
                        "Unsigned Transactions"
                    );
                }
                WalletRange::DbKeyPrefix::Utxo => {
                    push_db_pair_items!(
                        self,
                        WalletRange::UTXOPrefixKey,
                        WalletRange::UTXOKey,
                        fedimint_wallet::SpendableUTXO,
                        wallet,
                        "UTXOs"
                    );
                }
            }
        }

        self.serialized
            .insert("Wallet".to_string(), Box::new(wallet));
    }

    /// Iterates through each of the prefixes within the lightning range and retrieves
    /// the corresponding data.
    async fn get_lightning_data(&mut self) {
        let mut lightning: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        for table in LightningRange::DbKeyPrefix::iter() {
            filter_prefixes!(table, self);

            match table {
                LightningRange::DbKeyPrefix::AgreedDecryptionShare => {
                    push_db_pair_items!(
                        self,
                        LightningRange::AgreedDecryptionShareKeyPrefix,
                        LightningRange::AgreedDecryptionShareKey,
                        fedimint_ln::contracts::PreimageDecryptionShare,
                        lightning,
                        "Accepted Decryption Shares"
                    );
                }
                LightningRange::DbKeyPrefix::Contract => {
                    push_db_pair_items!(
                        self,
                        LightningRange::ContractKeyPrefix,
                        LightningRange::ContractKey,
                        fedimint_ln::ContractAccount,
                        lightning,
                        "Contracts"
                    );
                }
                LightningRange::DbKeyPrefix::ContractUpdate => {
                    push_db_pair_items!(
                        self,
                        LightningRange::ContractUpdateKeyPrefix,
                        LightningRange::ContractUpdateKey,
                        fedimint_ln::LightningOutputOutcome,
                        lightning,
                        "Contract Updates"
                    );
                }
                LightningRange::DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        self,
                        LightningRange::LightningGatewayKeyPrefix,
                        LightningRange::LightningGatewayKey,
                        fedimint_ln::LightningGateway,
                        lightning,
                        "Lightning Gateways"
                    );
                }
                LightningRange::DbKeyPrefix::Offer => {
                    push_db_pair_items!(
                        self,
                        LightningRange::OfferKeyPrefix,
                        LightningRange::OfferKey,
                        fedimint_ln::contracts::incoming::IncomingContractOffer,
                        lightning,
                        "Offers"
                    );
                }
                LightningRange::DbKeyPrefix::ProposeDecryptionShare => {
                    push_db_pair_items!(
                        self,
                        LightningRange::ProposeDecryptionShareKeyPrefix,
                        LightningRange::ProposeDecryptionShareKey,
                        fedimint_ln::contracts::PreimageDecryptionShare,
                        lightning,
                        "Proposed Decryption Shares"
                    );
                }
            }
        }

        self.serialized
            .insert("Lightning".to_string(), Box::new(lightning));
    }

    /// Iterates through each of the prefixes within the lightning client range and retrieves
    /// the corresponding data.
    async fn get_ln_client_data(&mut self) {
        let mut ln_client: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        for table in ClientLightningRange::DbKeyPrefix::iter() {
            filter_prefixes!(table, self);

            match table {
                ClientLightningRange::DbKeyPrefix::ConfirmedInvoice => {
                    push_db_pair_items!(
                        self,
                        ClientLightningRange::ConfirmedInvoiceKeyPrefix,
                        ClientLightningRange::ConfirmedInvoiceKey,
                        mint_client::ln::incoming::ConfirmedInvoice,
                        ln_client,
                        "Confirmed Invoices"
                    );
                }
                ClientLightningRange::DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        self,
                        ClientLightningRange::LightningGatewayKeyPrefix,
                        ClientLightningRange::LightningGatewayKey,
                        fedimint_ln::LightningGateway,
                        ln_client,
                        "Lightning Gateways"
                    );
                }
                ClientLightningRange::DbKeyPrefix::OutgoingContractAccount => {
                    push_db_pair_items!(
                        self,
                        ClientLightningRange::OutgoingContractAccountKeyPrefix,
                        ClientLightningRange::OutgoingContractAccountKey,
                        mint_client::ln::outgoing::OutgoingContractAccount,
                        ln_client,
                        "Outgoing Contract Accounts"
                    );
                }
                ClientLightningRange::DbKeyPrefix::OutgoingPayment => {
                    push_db_pair_items!(
                        self,
                        ClientLightningRange::OutgoingPaymentKeyPrefix,
                        ClientLightningRange::OutgoingPaymentKey,
                        mint_client::ln::outgoing::OutgoingContractData,
                        ln_client,
                        "Outgoing Payments"
                    );
                }
                ClientLightningRange::DbKeyPrefix::OutgoingPaymentClaim => {
                    push_db_key_items!(
                        self,
                        ClientLightningRange::OutgoingPaymentClaimKeyPrefix,
                        ClientLightningRange::OutgoingPaymentClaimKey,
                        ln_client,
                        "Outgoing Payment Claims"
                    );
                }
            }
        }

        self.serialized
            .insert("Client Lightning".to_string(), Box::new(ln_client));
    }

    /// Iterates through each of the prefixes within the mint client range and retrieves
    /// the corresponding data.
    async fn get_mint_client_data(&mut self) {
        let mut mint_client: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        for table in ClientMintRange::DbKeyPrefix::iter() {
            filter_prefixes!(table, self);

            match table {
                ClientMintRange::DbKeyPrefix::Coin => {
                    push_db_pair_items!(
                        self,
                        ClientMintRange::CoinKeyPrefix,
                        ClientMintRange::CoinKey,
                        mint_client::mint::SpendableNote,
                        mint_client,
                        "Coins"
                    );
                }
                ClientMintRange::DbKeyPrefix::OutputFinalizationData => {
                    push_db_pair_items!(
                        self,
                        ClientMintRange::OutputFinalizationKeyPrefix,
                        ClientMintRange::OutputFinalizationKey,
                        mint_client::mint::NoteIssuanceRequests,
                        mint_client,
                        "Output Finalization"
                    );
                }
                ClientMintRange::DbKeyPrefix::PendingCoins => {
                    push_db_pair_items!(
                        self,
                        ClientMintRange::PendingCoinsKeyPrefix,
                        ClientMintRange::PendingCoinsKey,
                        fedimint_api::TieredMulti<mint_client::mint::SpendableNote>,
                        mint_client,
                        "Pending Coins"
                    );
                }
                ClientMintRange::DbKeyPrefix::NextECashNoteIndex => {
                    push_db_pair_items!(
                        self,
                        ClientMintRange::NextECashNoteIndexKeyPrefix,
                        ClientMintRange::NextECashNoteIndexKey,
                        u64,
                        mint_client,
                        "Last e-cash note index"
                    );
                }
                ClientMintRange::DbKeyPrefix::NotesPerDenomination => {
                    let notes = self
                        .read_only
                        .get_value(&ClientMintRange::NotesPerDenominationKey)
                        .await
                        .unwrap();
                    if let Some(notes) = notes {
                        mint_client.insert("NotesPerDenomination".to_string(), Box::new(notes));
                    }
                }
            }
        }

        self.serialized
            .insert("Client Mint".to_string(), Box::new(mint_client));
    }

    /// Iterates through each of the prefixes within the wallet client range and retrieves
    /// the corresponding data.
    async fn get_wallet_client_data(&mut self) {
        let mut wallet_client: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        for table in ClientWalletRange::DbKeyPrefix::iter() {
            filter_prefixes!(table, self);

            match table {
                ClientWalletRange::DbKeyPrefix::PegIn => {
                    push_db_pair_items!(
                        self,
                        ClientWalletRange::PegInPrefixKey,
                        ClientWalletRange::PegInKey,
                        [u8; 32],
                        wallet_client,
                        "Peg Ins"
                    );
                }
            }
        }

        self.serialized
            .insert("Client Wallet".to_string(), Box::new(wallet_client));
    }

    async fn get_client_data(&mut self) {
        let mut client: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();

        for table in ClientRange::DbKeyPrefix::iter() {
            filter_prefixes!(table, self);

            match table {
                ClientRange::DbKeyPrefix::ClientSecret => {
                    let secret = self
                        .read_only
                        .get_value(&ClientRange::ClientSecretKey)
                        .await
                        .unwrap();
                    if let Some(secret) = secret {
                        client.insert("Client Secret".to_string(), Box::new(secret));
                    }
                }
            }
        }

        self.serialized
            .insert("Client".to_string(), Box::new(client));
    }
}

const USAGE: &str = "
Usage:
    fedimint-dbdump <path> [--range=<range>] [--prefix=<prefix>]
    
Options:
    --range=<range>    A CSV list of the ranges of the database to dump [default: All].
    --prefix=<prefix>  A CSV list of he prefixes within the range of the database to dump [default: All].

    RANGES=consensus,mint,wallet,lightning,mintclient,lightningclient,walletclient,client
";

const RANGES: [&str; 8] = [
    "consensus",
    "mint",
    "wallet",
    "lightning",
    "mintclient",
    "lightningclient",
    "walletclient",
    "client",
];

#[derive(Debug, Deserialize)]
struct Args {
    arg_path: String,
    flag_range: String,
    flag_prefix: String,
}

#[tokio::main]
async fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let db_path = args.arg_path;
    let csv_range = args.flag_range;
    let csv_prefix = args.flag_prefix;

    let ranges: Vec<String> = if csv_range != "All" {
        csv_range
            .split(',')
            .map(|s| s.to_string().to_lowercase())
            .collect::<Vec<String>>()
    } else {
        RANGES.map(|s| s.to_string().to_lowercase()).to_vec()
    };

    let prefixes = csv_prefix
        .split(',')
        .map(|s| s.to_string().to_lowercase())
        .collect::<Vec<String>>();

    let read_only = match RocksDbReadOnly::open_read_only(db_path) {
        Ok(db) => db,
        Err(_) => {
            eprintln!("Error reading RocksDB database. Quitting...");
            return;
        }
    };

    let serialized: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
    let mut dbdump = DatabaseDump {
        serialized,
        read_only: ReadOnlyDatabaseTransaction::new(read_only, all_decoders()),
        ranges,
        prefixes,
        include_all_prefixes: csv_prefix == "All",
    };

    dbdump.dump_database().await;
}
