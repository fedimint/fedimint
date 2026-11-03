use std::cell::{Cell, RefCell};

use bitcoin::Txid;
use bitcoin::hashes::Hash as _;

use super::{
    LIST_TRANSACTIONS_PAGE_SIZE, MAX_SCRIPT_HISTORY, collect_script_history_txids,
    ensure_wallet_loaded,
};
use crate::BitcoinRpcError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletError {
    LoadedInventory,
    DirectoryInventory,
    Load,
    Create(i32),
    NotLoaded,
}

#[derive(Debug)]
struct MockWallet {
    name: &'static str,
    loaded: Cell<bool>,
    exists: bool,
    contents: &'static str,
    loaded_inventory_error: Cell<bool>,
    directory_inventory_error: Cell<bool>,
    load_error: Cell<bool>,
    create_error: Cell<Option<i32>>,
    load_calls: Cell<usize>,
    create_calls: Cell<usize>,
}

impl MockWallet {
    fn existing(name: &'static str, loaded: bool) -> Self {
        Self {
            name,
            loaded: Cell::new(loaded),
            exists: true,
            contents: "existing wallet contents",
            loaded_inventory_error: Cell::new(false),
            directory_inventory_error: Cell::new(false),
            load_error: Cell::new(false),
            create_error: Cell::new(None),
            load_calls: Cell::new(0),
            create_calls: Cell::new(0),
        }
    }

    fn absent(name: &'static str) -> Self {
        Self {
            exists: false,
            contents: "new wallet contents",
            ..Self::existing(name, false)
        }
    }

    fn ensure_loaded(&self) -> Result<(), WalletError> {
        ensure_wallet_loaded(
            self.name,
            || {
                if self.loaded_inventory_error.get() {
                    Err(WalletError::LoadedInventory)
                } else if self.loaded.get() {
                    Ok(vec!["gateway-backup".to_owned(), self.name.to_owned()])
                } else {
                    Ok(vec!["gateway-backup".to_owned()])
                }
            },
            || {
                if self.directory_inventory_error.get() {
                    Err(WalletError::DirectoryInventory)
                } else if self.exists {
                    Ok(vec!["gateway-backup".to_owned(), self.name.to_owned()])
                } else {
                    Ok(vec!["gateway-backup".to_owned()])
                }
            },
            || {
                self.load_calls.set(self.load_calls.get() + 1);
                if self.load_error.get() {
                    Err(WalletError::Load)
                } else {
                    self.loaded.set(true);
                    Ok(())
                }
            },
            || {
                self.create_calls.set(self.create_calls.get() + 1);
                if let Some(code) = self.create_error.get() {
                    Err(WalletError::Create(code))
                } else {
                    self.loaded.set(true);
                    Ok(())
                }
            },
        )
    }

    fn use_wallet(&self) -> Result<&str, WalletError> {
        if self.loaded.get() {
            Ok(self.contents)
        } else {
            Err(WalletError::NotLoaded)
        }
    }
}

#[test]
fn loaded_wallet_is_reused() {
    let wallet = MockWallet::existing("gateway", true);
    wallet.directory_inventory_error.set(true);

    wallet.ensure_loaded().expect("loaded wallet can be reused");

    assert_eq!(wallet.load_calls.get(), 0);
    assert_eq!(wallet.create_calls.get(), 0);
}

#[test]
fn unloaded_existing_wallet_is_loaded_and_usable() {
    let wallet = MockWallet::existing("gateway", false);

    wallet
        .ensure_loaded()
        .expect("existing wallet should be loaded");

    assert_eq!(wallet.load_calls.get(), 1);
    assert_eq!(wallet.create_calls.get(), 0);
    assert_eq!(
        wallet.use_wallet().expect("loaded wallet should be usable"),
        "existing wallet contents"
    );
}

#[test]
fn absent_wallet_is_created() {
    let wallet = MockWallet::absent("gateway");

    wallet.ensure_loaded().expect("absent wallet is created");

    assert_eq!(wallet.load_calls.get(), 0);
    assert_eq!(wallet.create_calls.get(), 1);
    assert_eq!(
        wallet
            .use_wallet()
            .expect("created wallet should be usable"),
        "new wallet contents"
    );
}

#[test]
fn generic_wallet_creation_error_is_propagated() {
    let wallet = MockWallet::absent("gateway");
    wallet.create_error.set(Some(-4));

    let error = wallet
        .ensure_loaded()
        .expect_err("generic creation error must not imply readiness");

    assert_eq!(error, WalletError::Create(-4));
    assert_eq!(wallet.use_wallet(), Err(WalletError::NotLoaded));
}

#[test]
fn wallet_load_error_is_propagated() {
    let wallet = MockWallet::existing("gateway", false);
    wallet.load_error.set(true);

    let error = wallet
        .ensure_loaded()
        .expect_err("load failure must be returned");

    assert_eq!(error, WalletError::Load);
    assert_eq!(wallet.create_calls.get(), 0);
}

#[test]
fn loaded_wallet_inventory_error_is_propagated() {
    let wallet = MockWallet::existing("gateway", false);
    wallet.loaded_inventory_error.set(true);

    let error = wallet
        .ensure_loaded()
        .expect_err("loaded-wallet inventory failure must be returned");

    assert_eq!(error, WalletError::LoadedInventory);
    assert_eq!(wallet.load_calls.get(), 0);
    assert_eq!(wallet.create_calls.get(), 0);
}

#[test]
fn wallet_directory_inventory_error_is_propagated() {
    let wallet = MockWallet::existing("gateway", false);
    wallet.directory_inventory_error.set(true);

    let error = wallet
        .ensure_loaded()
        .expect_err("wallet-directory inventory failure must be returned");

    assert_eq!(error, WalletError::DirectoryInventory);
    assert_eq!(wallet.load_calls.get(), 0);
    assert_eq!(wallet.create_calls.get(), 0);
}

#[test]
fn repeated_construction_reuses_wallet_after_loading_it() {
    let wallet = MockWallet::existing("gateway", false);

    wallet
        .ensure_loaded()
        .expect("first construction should load wallet");
    wallet
        .ensure_loaded()
        .expect("second construction should reuse loaded wallet");

    assert_eq!(wallet.load_calls.get(), 1);
    assert_eq!(wallet.create_calls.get(), 0);
}

fn txid(n: u64) -> Txid {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    Txid::from_byte_array(bytes)
}

/// The `(count, skip)` of every `listtransactions` page requested.
type PageRequests = Vec<(usize, usize)>;

/// Pages through `entries`, oldest first, the way `listtransactions` does.
fn collect_from(entries: &[Txid]) -> (Result<Vec<Txid>, BitcoinRpcError>, PageRequests) {
    let calls = RefCell::new(vec![]);

    let result = collect_script_history_txids(|count, skip| {
        calls.borrow_mut().push((count, skip));

        let end = entries.len().saturating_sub(skip);
        let start = end.saturating_sub(count);

        Ok(entries[start..end].to_vec())
    });

    (result, calls.into_inner())
}

#[test]
fn script_history_includes_entries_beyond_the_first_page() {
    let entries = (0..250).map(txid).collect::<Vec<_>>();

    let (txids, calls) = collect_from(&entries);

    assert_eq!(txids.expect("history is short enough"), entries);
    assert_eq!(
        calls,
        vec![
            (LIST_TRANSACTIONS_PAGE_SIZE, 0),
            (LIST_TRANSACTIONS_PAGE_SIZE, 100),
            (LIST_TRANSACTIONS_PAGE_SIZE, 200),
        ]
    );
}

#[test]
fn script_history_reads_one_more_page_after_a_full_one() {
    let entries = (0..100).map(txid).collect::<Vec<_>>();

    let (txids, calls) = collect_from(&entries);

    assert_eq!(txids.expect("history is short enough"), entries);
    assert_eq!(calls.len(), 2);
}

#[test]
fn script_history_lists_each_transaction_once() {
    // A transaction is listed once per output and category, e.g. a deposit
    // that pays the script twice, and these can straddle a page boundary.
    let mut entries = (0..150).map(txid).collect::<Vec<_>>();
    entries.insert(50, txid(49));
    entries.insert(100, txid(98));

    let (txids, _) = collect_from(&entries);

    assert_eq!(
        txids.expect("history is short enough"),
        (0..150).map(txid).collect::<Vec<_>>()
    );
}

#[test]
fn script_history_is_limited_like_the_esplora_backend() {
    let entries = (0..MAX_SCRIPT_HISTORY as u64).map(txid).collect::<Vec<_>>();

    let (txids, _) = collect_from(&entries);

    assert!(matches!(
        txids,
        Err(BitcoinRpcError::ScriptHistoryTooLong {
            max: MAX_SCRIPT_HISTORY
        })
    ));

    let (txids, _) = collect_from(&entries[1..]);

    assert_eq!(
        txids.expect("history is short enough").len(),
        MAX_SCRIPT_HISTORY - 1
    );
}
