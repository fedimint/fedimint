//! Integration test for 1p1c package submission against a real bitcoind.
//!
//! [`IServerBitcoinRpc::submit_package`] exists so that a parent paying no fee
//! at all can still reach the network, carried by a child that pays for both.
//! Such a parent sits below the minimum relay fee and can never be broadcast on
//! its own, so this rests on a property plain transaction submission does not
//! have: a package is accepted where its parent alone is rejected.
//!
//! Nothing in the tree calls `submit_package` yet. It is groundwork for a
//! future wallet module that batches its transactions this way, so these tests
//! stand in as the specification of the RPC contract rather than as coverage of
//! an existing caller. They pin down the three parts of it that a periodic
//! broadcast loop would depend on: that the package is accepted at all, that
//! resubmitting one already in the mempool succeeds, and that resubmitting one
//! that has already been mined does *not*.
//!
//! Requires real daemons. The mock backend has no mempool policy and no block
//! assembler, so it cannot express any of this. Both tests drive the same
//! bitcoind wallet and mine blocks, so they must not run concurrently;
//! `./scripts/tests/package-submission-test.sh` runs them with
//! `--test-threads=1`.

use anyhow::{Context, Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoincore_rpc::json::SignRawTransactionInput;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use fedimint_core::util::SafeUrl;
use fedimint_server_bitcoin_rpc::bitcoind::BitcoindClient;
use fedimint_server_bitcoin_rpc::esplora::EsploraClient;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;

/// Mirrors `fedimint_testing_core::envs::FM_TEST_USE_REAL_DAEMONS_ENV`, which
/// is not depended on here to keep this crate's dev-dependencies light.
const FM_TEST_USE_REAL_DAEMONS: &str = "FM_TEST_USE_REAL_DAEMONS";

/// Mirrors `fedimint_testing_core::envs::FM_TEST_BITCOIND_RPC_ENV`.
const FM_TEST_BITCOIND_RPC: &str = "FM_TEST_BITCOIND_RPC";

/// Mirrors `fedimint_testing_core::envs::FM_PORT_ESPLORA_ENV`.
const FM_PORT_ESPLORA: &str = "FM_PORT_ESPLORA";

/// Fee paid by the child. It covers both transactions, since the parent pays
/// nothing.
const CHILD_FEE_SAT: u64 = 10_000;

/// Minimum value of the UTXO funding the parent. Comfortably above the child
/// fee plus the dust limit.
const MIN_FUNDING_SAT: u64 = 1_000_000;

/// Returns the bitcoind RPC url, or `None` when not running against real
/// daemons, in which case the test is skipped.
fn bitcoind_url() -> Option<SafeUrl> {
    if std::env::var(FM_TEST_USE_REAL_DAEMONS).is_err() {
        // Announce the skip loudly. A silent early return is indistinguishable
        // from a pass, which would let this test look green while asserting
        // nothing at all.
        eprintln!(
            "SKIPPING package submission test: {FM_TEST_USE_REAL_DAEMONS} is not set. \
             Run it with ./scripts/tests/package-submission-test.sh"
        );

        return None;
    }

    Some(
        std::env::var(FM_TEST_BITCOIND_RPC)
            .expect("Must have bitcoind RPC defined for real tests")
            .parse()
            .expect("Failed to parse bitcoind RPC url"),
    )
}

/// Connects to the bitcoind wallet directly, which the tests use to fund
/// packages, mine blocks and inspect the mempool.
fn wallet_client(url: &SafeUrl) -> Result<Client> {
    let host = url
        .without_auth()
        .map_err(|()| anyhow!("Failed to strip auth from the bitcoind url"))?;

    Ok(Client::new(
        host.as_str(),
        Auth::UserPass(
            url.username().to_owned(),
            url.password()
                .context("Bitcoind url has no password")?
                .to_owned(),
        ),
    )?)
}

fn unsigned_txin(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: bitcoin::ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }
}

fn sign(
    wallet: &Client,
    unsigned: &Transaction,
    prevouts: &[SignRawTransactionInput],
) -> Result<Transaction> {
    let result = wallet.sign_raw_transaction_with_wallet(unsigned, Some(prevouts), None)?;

    anyhow::ensure!(
        result.complete,
        "Wallet signing failed: {:?}",
        result.errors
    );

    result
        .transaction()
        .context("Failed to decode the signed transaction")
}

/// Builds a zero-fee parent and a child that pays for both, funded from the
/// test wallet. The parent is deliberately unbroadcastable on its own, which is
/// the shape a batching wallet module would produce.
fn build_zero_fee_package(wallet: &Client) -> Result<(Transaction, Transaction)> {
    let funding_address = wallet.get_new_address(None, None)?.assume_checked();

    if wallet.get_balance(None, None)? < Amount::from_sat(MIN_FUNDING_SAT) {
        wallet.generate_to_address(101, &funding_address)?;
    }

    let utxo = wallet
        .list_unspent(Some(1), None, None, None, None)?
        .into_iter()
        .find(|utxo| utxo.spendable && utxo.amount >= Amount::from_sat(MIN_FUNDING_SAT))
        .context("No mature UTXO large enough to fund the package")?;

    // The parent spends its input entirely into a single output, so it pays no
    // fee at all.
    let parent_output = wallet.get_new_address(None, None)?.assume_checked();

    let parent = sign(
        wallet,
        &Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![unsigned_txin(OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            })],
            output: vec![TxOut {
                value: utxo.amount,
                script_pubkey: parent_output.script_pubkey(),
            }],
        },
        &[SignRawTransactionInput {
            txid: utxo.txid,
            vout: utxo.vout,
            script_pub_key: utxo.script_pub_key.clone(),
            redeem_script: None,
            amount: Some(utxo.amount),
        }],
    )?;

    let parent_txid = parent.compute_txid();

    // The child spends the parent's only output and pays for both.
    let child_output = wallet.get_new_address(None, None)?.assume_checked();

    let child = sign(
        wallet,
        &Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![unsigned_txin(OutPoint {
                txid: parent_txid,
                vout: 0,
            })],
            output: vec![TxOut {
                value: utxo.amount - Amount::from_sat(CHILD_FEE_SAT),
                script_pubkey: child_output.script_pubkey(),
            }],
        },
        &[SignRawTransactionInput {
            txid: parent_txid,
            vout: 0,
            script_pub_key: parent.output[0].script_pubkey.clone(),
            redeem_script: None,
            amount: Some(parent.output[0].value),
        }],
    )?;

    Ok((parent, child))
}

/// Asserts the whole [`IServerBitcoinRpc::submit_package`] contract against
/// whichever backend is passed in, so that both are held to the same standard.
///
/// `wallet` talks to bitcoind directly and is only used to observe the results,
/// which keeps the assertions independent of how quickly a backend's own view
/// of the chain catches up.
async fn assert_package_submission_contract(
    rpc: &impl IServerBitcoinRpc,
    wallet: &Client,
) -> Result<()> {
    let (parent, child) = build_zero_fee_package(wallet)?;

    let parent_txid = parent.compute_txid();
    let child_txid = child.compute_txid();

    // Ablation: without this, the test could pass simply because both
    // transactions relay fine on their own, which would tell us nothing about
    // package submission.
    assert!(
        rpc.submit_transaction(parent.clone()).await.is_err(),
        "The zero-fee parent was accepted on its own, so this test would pass \
         even if package submission did nothing"
    );

    assert!(
        !wallet.get_raw_mempool()?.contains(&parent_txid),
        "The rejected parent still entered the mempool"
    );

    let package = [parent, child];

    rpc.submit_package(&package)
        .await
        .context("Package submission failed")?;

    let mempool = wallet.get_raw_mempool()?;

    assert!(
        mempool.contains(&parent_txid),
        "Parent is missing from the mempool after package submission"
    );

    assert!(
        mempool.contains(&child_txid),
        "Child is missing from the mempool after package submission"
    );

    // A broadcast loop resubmits on a timer, so submitting a package whose
    // transactions are already in the mempool must not be an error.
    rpc.submit_package(&package)
        .await
        .context("Resubmitting a package already in the mempool must succeed")?;

    // The child pays for the parent, so linearization puts them in one chunk
    // and they are mined together.
    let mining_address = wallet.get_new_address(None, None)?.assume_checked();

    let block_hash = wallet.generate_to_address(1, &mining_address)?[0];

    let block = wallet.get_block_info(&block_hash)?;

    assert!(
        block.tx.contains(&parent_txid),
        "Parent did not confirm in the next block"
    );

    assert!(
        block.tx.contains(&child_txid),
        "Child did not confirm alongside its parent"
    );

    // Once mined, resubmission does *not* succeed. Unlike `sendrawtransaction`,
    // which reports an already-confirmed transaction as RPC error -27,
    // `submitpackage` returns a result object whose per-transaction errors are
    // `txn-already-known` for the parent and `bad-txns-inputs-missingorspent`
    // for the child, whose input the parent's confirmation consumed.
    //
    // This is deliberately not smoothed over into a success:
    // `bad-txns-inputs-missingorspent` is also how a genuinely invalidated
    // child reports itself, which is precisely the signal a batch fallback
    // would need to see. A broadcast loop logs and ignores, as documented on
    // `IServerBitcoinRpc::submit_package`.
    let error = rpc
        .submit_package(&package)
        .await
        .expect_err("Resubmitting a confirmed package is expected to fail");

    assert!(
        error.to_string().contains("txn-already-known"),
        "Unexpected error resubmitting a confirmed package: {error}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn package_submission_accepts_a_zero_fee_parent() -> Result<()> {
    let Some(url) = bitcoind_url() else {
        // Skipped unless running against real daemons.
        return Ok(());
    };

    let wallet = wallet_client(&url)?;

    let rpc = BitcoindClient::new(
        url.username().to_owned(),
        url.password()
            .context("Bitcoind url has no password")?
            .to_owned(),
        &url,
    )?;

    assert_package_submission_contract(&rpc, &wallet).await
}

/// The esplora backend must honour the same contract.
///
/// A batching wallet module pays nothing on the parent, so package submission
/// is not an optimisation for it — it is the only way its transactions reach
/// the network at all. A guardian running esplora therefore needs an instance
/// exposing `POST /txs/package`, which is why the pinned esplora build was
/// moved off a fork and onto current upstream.
#[tokio::test(flavor = "multi_thread")]
async fn esplora_package_submission_accepts_a_zero_fee_parent() -> Result<()> {
    let Some(url) = bitcoind_url() else {
        return Ok(());
    };

    let wallet = wallet_client(&url)?;

    let esplora_port =
        std::env::var(FM_PORT_ESPLORA).expect("Must have the esplora port defined for real tests");

    let esplora = EsploraClient::new(
        &format!("http://127.0.0.1:{esplora_port}")
            .parse::<SafeUrl>()
            .expect("Failed to parse the esplora url"),
    )?;

    assert_package_submission_contract(&esplora, &wallet)
        .await
        .context("Does the pinned esplora expose /txs/package?")
}
