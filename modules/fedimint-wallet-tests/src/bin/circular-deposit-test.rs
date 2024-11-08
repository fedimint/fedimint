use std::str::FromStr;

use anyhow::Result;
use bitcoin::Transaction;
use bitcoincore_rpc::bitcoin::address::Address;
use bitcoincore_rpc::bitcoin::Txid;
use devimint::cmd;
use devimint::federation::Client;
use fedimint_core::encoding::Decodable;
use tokio::try_join;

async fn assert_withdrawal(
    send_client: &Client,
    receive_client: &Client,
    bitcoind: &devimint::external::Bitcoind,
    fed: &devimint::federation::Federation,
) -> Result<()> {
    let withdrawal_amount_sats = 50_000;
    let withdrawal_amount_msats = withdrawal_amount_sats * 1000;

    if send_client.balance().await? < withdrawal_amount_msats {
        fed.pegin_client(withdrawal_amount_sats * 2, send_client)
            .await?;
    }

    let send_client_pre_balance = send_client.balance().await?;
    let receive_client_pre_balance = receive_client.balance().await?;

    let (deposit_address, operation_id) = receive_client.get_deposit_addr().await?;
    let withdraw_res = cmd!(
        send_client,
        "withdraw",
        "--address",
        &deposit_address,
        "--amount",
        "{withdrawal_amount_sats} sat"
    )
    .out_json()
    .await?;

    // Verify federation broadcasts withdrawal tx
    let txid: Txid = withdraw_res["txid"].as_str().unwrap().parse().unwrap();
    let tx_hex = bitcoind.poll_get_transaction(txid).await?;

    let parsed_address = Address::from_str(&deposit_address)?;
    let tx = Transaction::consensus_decode_hex(&tx_hex, &Default::default())?;
    assert!(tx.output.iter().any(|o| o.script_pubkey
        == parsed_address.clone().assume_checked().script_pubkey()
        && o.value.to_sat() == withdrawal_amount_sats));

    // Verify the receive client gets the deposit
    try_join!(
        bitcoind.mine_blocks(21),
        receive_client.await_deposit(&operation_id),
    )?;

    // Balance checks
    let send_client_post_balance = send_client.balance().await?;
    let receive_client_post_balance = receive_client.balance().await?;
    let fed_deposit_fees_msats = fed.deposit_fees()?.msats;
    let onchain_fees_msats = withdraw_res["fees_sat"].as_u64().unwrap() * 1000;

    let expected_send_client_balance = if send_client.get_name() == receive_client.get_name() {
        send_client_pre_balance - onchain_fees_msats - fed_deposit_fees_msats
    } else {
        send_client_pre_balance - withdrawal_amount_msats - onchain_fees_msats
    };

    let expected_receive_client_balance = if send_client.get_name() == receive_client.get_name() {
        receive_client_pre_balance - onchain_fees_msats - fed_deposit_fees_msats
    } else {
        receive_client_pre_balance + withdrawal_amount_msats - fed_deposit_fees_msats
    };

    assert_eq!(send_client_post_balance, expected_send_client_balance);
    assert_eq!(receive_client_post_balance, expected_receive_client_balance);

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let (fed, bitcoind) = try_join!(dev_fed.fed(), dev_fed.bitcoind())?;

        let send_client = fed
            .new_joined_client("circular-deposit-send-client")
            .await?;

        // Verify withdrawal to deposit address from same client
        assert_withdrawal(&send_client, &send_client, bitcoind, fed).await?;

        // Verify withdrawal to deposit address from different client in same federation
        let receive_client = fed
            .new_joined_client("circular-deposit-receive-client")
            .await?;
        assert_withdrawal(&send_client, &receive_client, bitcoind, fed).await?;

        Ok(())
    })
    .await
}
