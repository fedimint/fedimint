use std::collections::BTreeMap;

use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Txid, WScriptHash};
use fedimint_walletv2_common::{MempoolVisibility, PendingOutput, PendingOutputs};

use super::{ReceiveProgress, owned_receive_progress};

fn script(byte: u8) -> ScriptBuf {
    ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([byte; 32]))
}

fn address(script: &ScriptBuf) -> Address {
    Address::from_script(script, Network::Regtest).expect("A P2WSH script has an address")
}

fn output(script: ScriptBuf, txid_byte: u8, height: Option<u64>) -> PendingOutput {
    PendingOutput {
        script,
        outpoint: OutPoint {
            txid: Txid::from_byte_array([txid_byte; 32]),
            vout: 0,
        },
        value: Amount::from_sat(50_000),
        height,
    }
}

#[test]
fn only_deposits_to_owned_addresses_are_reported() {
    let ours = BTreeMap::from([(script(1), address(&script(1)))]);
    let pending = PendingOutputs {
        block_count: Some(103),
        outputs: vec![
            output(script(2), 3, Some(100)),
            output(script(1), 2, None),
            output(script(1), 1, Some(100)),
        ],
        mempool_visibility: MempoolVisibility::Partial,
    };

    let progress = owned_receive_progress(&pending, &ours, Clone::clone);

    let reported: Vec<_> = progress
        .deposits
        .iter()
        .map(|(paid, outpoint, _)| (paid.clone(), outpoint.txid))
        .collect();
    assert_eq!(
        reported,
        vec![
            (address(&script(1)), Txid::from_byte_array([1; 32])),
            (address(&script(1)), Txid::from_byte_array([2; 32])),
        ],
        "Only our deposits are reported, ordered by outpoint"
    );
    assert!(matches!(
        progress.deposits[0].2,
        ReceiveProgress::Confirming {
            confirmations: 3,
            ..
        }
    ));
    assert!(matches!(
        progress.deposits[1].2,
        ReceiveProgress::Mempool { .. }
    ));
    assert_eq!(progress.mempool_visibility, MempoolVisibility::Partial);
}

#[test]
fn no_deposits_keep_the_mempool_visibility_they_were_read_with() {
    let ours = BTreeMap::from([(script(1), address(&script(1)))]);

    for mempool_visibility in [MempoolVisibility::Unavailable, MempoolVisibility::Complete] {
        let pending = PendingOutputs {
            block_count: None,
            outputs: vec![output(script(2), 1, None)],
            mempool_visibility,
        };

        let progress = owned_receive_progress(&pending, &ours, Clone::clone);

        assert!(progress.deposits.is_empty());
        assert_eq!(progress.mempool_visibility, mempool_visibility);
    }
}
