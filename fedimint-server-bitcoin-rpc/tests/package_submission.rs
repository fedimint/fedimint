//! Integration test for 1p1c package submission against a real bitcoind.
//!
//! The `walletv2` pinning fix broadcasts a zero-fee parent together with a
//! child that carries the whole fee (see `PINNING.md`). That parent is below
//! the minimum relay fee and can never reach the network on its own, so the
//! design rests on a property that plain transaction submission does not have:
//! a package is accepted where its parent alone is rejected.
//!
//! This test pins that property down, and additionally checks the two things
//! the broadcast loop will depend on — that resubmitting a package already in
//! the mempool succeeds, and that parent and child are mined together.
//!
//! Requires a real bitcoind. The mock backend has no mempool policy and no
//! block assembler, so it cannot express any of this. Run with
//! `./scripts/tests/package-submission-test.sh`.

use anyhow::{Context, Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoincore_rpc::json::SignRawTransactionInput;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use fedimint_core::util::SafeUrl;
use fedimint_server_bitcoin_rpc::bitcoind::BitcoindClient;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;

/// Mirrors `fedimint_testing_core::envs::FM_TEST_USE_REAL_DAEMONS_ENV`, which
/// is not depended on here to keep this crate's dev-dependencies light.
const FM_TEST_USE_REAL_DAEMONS: &str = "FM_TEST_USE_REAL_DAEMONS";

/// Mirrors `fedimint_testing_core::envs::FM_TEST_BITCOIND_RPC_ENV`.
const FM_TEST_BITCOIND_RPC: &str = "FM_TEST_BITCOIND_RPC";

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

#[tokio::test(flavor = "multi_thread")]
async fn package_submission_accepts_a_zero_fee_parent() -> Result<()> {
    let Some(url) = bitcoind_url() else {
        // Skipped unless running against real daemons.
        return Ok(());
    };

    let username = url.username().to_owned();
    let password = url
        .password()
        .context("Bitcoind url has no password")?
        .to_owned();
    let host = url
        .without_auth()
        .map_err(|()| anyhow!("Failed to strip auth from the bitcoind url"))?;

    let wallet = Client::new(
        host.as_str(),
        Auth::UserPass(username.clone(), password.clone()),
    )?;

    let rpc = BitcoindClient::new(username, password, &url)?;

    // Make sure the wallet holds a mature, spendable coin.
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
    // fee at all — exactly the shape walletv2's batch parent will have.
    let parent_output = wallet.get_new_address(None, None)?.assume_checked();

    let parent = sign(
        &wallet,
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
        &wallet,
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

    rpc.submit_package(vec![parent.clone(), child.clone()])
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

    // The broadcast loop resubmits on a timer, so submitting a package whose
    // transactions are already in the mempool must not be an error.
    rpc.submit_package(vec![parent.clone(), child.clone()])
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
    // child reports itself, which is precisely the signal the batch fallback
    // needs to see. The broadcast loop logs and ignores, as documented on
    // `IServerBitcoinRpc::submit_package`.
    let error = rpc
        .submit_package(vec![parent, child])
        .await
        .expect_err("Resubmitting a confirmed package is expected to fail");

    assert!(
        error.to_string().contains("txn-already-known"),
        "Unexpected error resubmitting a confirmed package: {error}"
    );

    Ok(())
}
