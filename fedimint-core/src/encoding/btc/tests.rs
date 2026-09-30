use std::io::{Error, ErrorKind, Write};
use std::str::FromStr;

use bitcoin::hashes::Hash as BitcoinHash;
use hex::FromHex;

use crate::ModuleDecoderRegistry;
use crate::db::DatabaseValue;
use crate::encoding::btc::NetworkLegacyEncodingWrapper;
use crate::encoding::tests::{test_roundtrip, test_roundtrip_expected};
use crate::encoding::{Decodable, DecodeError, Encodable};

struct FailAfter {
    bytes_remaining: usize,
    bytes_written: Vec<u8>,
}

impl FailAfter {
    fn new(bytes_remaining: usize) -> Self {
        Self {
            bytes_remaining,
            bytes_written: Vec::new(),
        }
    }
}

impl Write for FailAfter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes_remaining == 0 {
            return Err(Error::new(ErrorKind::BrokenPipe, "injected write failure"));
        }

        let bytes_to_write = buffer.len().min(self.bytes_remaining);
        self.bytes_written
            .extend_from_slice(&buffer[..bytes_to_write]);
        self.bytes_remaining -= bytes_to_write;
        Ok(bytes_to_write)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        panic!("encoding must not flush the caller's writer");
    }
}

struct ShortWriter {
    max_write_size: usize,
    bytes_written: Vec<u8>,
}

impl Write for ShortWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let bytes_to_write = buffer.len().min(self.max_write_size);
        self.bytes_written
            .extend_from_slice(&buffer[..bytes_to_write]);
        Ok(bytes_to_write)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        panic!("encoding must not flush the caller's writer");
    }
}

#[test_log::test]
fn bitcoin_encoding_propagates_buffer_drain_errors() {
    let blockhash = bitcoin::BlockHash::from_str(
        "0000000000000000000065bda8f8a88f2e1e00d9a6887a43d640e52a4c7660f2",
    )
    .unwrap();
    let error = blockhash
        .consensus_encode(&mut FailAfter::new(0))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);

    let txid =
        bitcoin::Txid::from_str("51f7ed2f23e58cc6e139e715e9ce304a1e858416edc9079dd7b74fa8d2efc09a")
            .unwrap();
    let mut partial_writer = FailAfter::new(7);
    let error = txid.consensus_encode(&mut partial_writer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    assert_eq!(partial_writer.bytes_written.len(), 7);
}

#[test_log::test]
fn large_transaction_encoding_matches_bitcoin_consensus() {
    let transaction = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0xab; 16 * 1024]),
        }],
    };
    let expected = bitcoin::consensus::serialize(&transaction);
    let mut short_writer = ShortWriter {
        max_write_size: 257,
        bytes_written: Vec::new(),
    };

    transaction.consensus_encode(&mut short_writer).unwrap();

    assert_eq!(transaction.consensus_encode_to_vec(), expected);
    assert_eq!(short_writer.bytes_written, expected);
}

#[test_log::test]
fn block_hash_roundtrip() {
    let blockhash = bitcoin::BlockHash::from_str(
        "0000000000000000000065bda8f8a88f2e1e00d9a6887a43d640e52a4c7660f2",
    )
    .unwrap();
    test_roundtrip_expected(
        &blockhash,
        &[
            242, 96, 118, 76, 42, 229, 64, 214, 67, 122, 136, 166, 217, 0, 30, 46, 143, 168, 248,
            168, 189, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
}

#[test_log::test]
fn tx_roundtrip() {
    let transaction: Vec<u8> = FromHex::from_hex(
        "02000000000101d35b66c54cf6c09b81a8d94cd5d179719cd7595c258449452a9305ab9b12df250200000000fdffffff020cd50a0000000000160014ae5d450b71c04218e6e81c86fcc225882d7b7caae695b22100000000160014f60834ef165253c571b11ce9fa74e46692fc5ec10248304502210092062c609f4c8dc74cd7d4596ecedc1093140d90b3fd94b4bdd9ad3e102ce3bc02206bb5a6afc68d583d77d5d9bcfb6252a364d11a307f3418be1af9f47f7b1b3d780121026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea28600000000"
    ).unwrap();
    let transaction =
        bitcoin::Transaction::from_bytes(&transaction, &ModuleDecoderRegistry::default()).unwrap();
    test_roundtrip_expected(
        &transaction,
        &[
            2, 0, 0, 0, 0, 1, 1, 211, 91, 102, 197, 76, 246, 192, 155, 129, 168, 217, 76, 213, 209,
            121, 113, 156, 215, 89, 92, 37, 132, 73, 69, 42, 147, 5, 171, 155, 18, 223, 37, 2, 0,
            0, 0, 0, 253, 255, 255, 255, 2, 12, 213, 10, 0, 0, 0, 0, 0, 22, 0, 20, 174, 93, 69, 11,
            113, 192, 66, 24, 230, 232, 28, 134, 252, 194, 37, 136, 45, 123, 124, 170, 230, 149,
            178, 33, 0, 0, 0, 0, 22, 0, 20, 246, 8, 52, 239, 22, 82, 83, 197, 113, 177, 28, 233,
            250, 116, 228, 102, 146, 252, 94, 193, 2, 72, 48, 69, 2, 33, 0, 146, 6, 44, 96, 159,
            76, 141, 199, 76, 215, 212, 89, 110, 206, 220, 16, 147, 20, 13, 144, 179, 253, 148,
            180, 189, 217, 173, 62, 16, 44, 227, 188, 2, 32, 107, 181, 166, 175, 198, 141, 88, 61,
            119, 213, 217, 188, 251, 98, 82, 163, 100, 209, 26, 48, 127, 52, 24, 190, 26, 249, 244,
            127, 123, 27, 61, 120, 1, 33, 2, 110, 86, 40, 80, 110, 205, 51, 36, 46, 92, 235, 95,
            218, 254, 77, 48, 102, 181, 192, 241, 89, 179, 192, 90, 98, 30, 246, 95, 23, 126, 162,
            134, 0, 0, 0, 0,
        ],
    );
}

#[test_log::test]
fn txid_roundtrip() {
    let txid =
        bitcoin::Txid::from_str("51f7ed2f23e58cc6e139e715e9ce304a1e858416edc9079dd7b74fa8d2efc09a")
            .unwrap();
    test_roundtrip_expected(
        &txid,
        &[
            154, 192, 239, 210, 168, 79, 183, 215, 157, 7, 201, 237, 22, 132, 133, 30, 74, 48, 206,
            233, 21, 231, 57, 225, 198, 140, 229, 35, 47, 237, 247, 81,
        ],
    );
}

#[test_log::test]
fn network_roundtrip() {
    let networks: [(bitcoin::Network, [u8; 5], [u8; 4]); 5] = [
        (
            bitcoin::Network::Bitcoin,
            [0xFE, 0xD9, 0xB4, 0xBE, 0xF9],
            [0xF9, 0xBE, 0xB4, 0xD9],
        ),
        (
            bitcoin::Network::Testnet,
            [0xFE, 0x07, 0x09, 0x11, 0x0B],
            [0x0B, 0x11, 0x09, 0x07],
        ),
        (
            bitcoin::Network::Testnet4,
            [0xFE, 0x28, 0x3F, 0x16, 0x1C],
            [0x1C, 0x16, 0x3F, 0x28],
        ),
        (
            bitcoin::Network::Signet,
            [0xFE, 0x40, 0xCF, 0x03, 0x0A],
            [0x0A, 0x03, 0xCF, 0x40],
        ),
        (
            bitcoin::Network::Regtest,
            [0xFE, 0xDA, 0xB5, 0xBF, 0xFA],
            [0xFA, 0xBF, 0xB5, 0xDA],
        ),
    ];

    for (network, magic_legacy_bytes, magic_bytes) in networks {
        let network_legacy_encoded =
            NetworkLegacyEncodingWrapper(network).consensus_encode_to_vec();

        let network_encoded = network.consensus_encode_to_vec();

        let network_legacy_decoded = NetworkLegacyEncodingWrapper::consensus_decode_whole(
            &network_legacy_encoded,
            &ModuleDecoderRegistry::default(),
        )
        .unwrap()
        .0;

        let network_decoded = bitcoin::Network::consensus_decode_whole(
            &network_encoded,
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();

        assert_eq!(magic_legacy_bytes, *network_legacy_encoded);
        assert_eq!(magic_bytes, *network_encoded);
        assert_eq!(network, network_legacy_decoded);
        assert_eq!(network, network_decoded);
    }
}

#[test_log::test]
fn address_roundtrip() {
    let addresses = [
        "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5",
        "mxMYaq5yWinZ9AKjCDcBEbiEwPJD9n2uLU",
        "1FK8o7mUxyd6QWJAUw7J4vW7eRxuyjj6Ne",
        "3JSrSU7z7R1Yhh26pt1zzRjQz44qjcrXwb",
        "tb1qunn0thpt8uk3yk2938ypjccn3urxprt78z9ccq",
        "2MvUMRv2DRHZi3VshkP7RMEU84mVTfR9xjq",
    ];

    for address_str in addresses {
        let address =
            bitcoin::Address::from_str(address_str).expect("All tested addresses are valid");
        let encoding = address.consensus_encode_to_vec();
        let parsed_address =
            bitcoin::Address::consensus_decode_whole(&encoding, &ModuleDecoderRegistry::default())
                .expect("Decoding address failed");

        assert_eq!(address, parsed_address);
    }
}

#[test_log::test]
fn sha256_roundtrip() {
    test_roundtrip_expected(
        &bitcoin::hashes::sha256::Hash::hash(b"Hello world!"),
        &[
            192, 83, 94, 75, 226, 183, 159, 253, 147, 41, 19, 5, 67, 107, 248, 137, 49, 78, 74, 63,
            174, 192, 94, 207, 252, 187, 125, 243, 26, 217, 229, 26,
        ],
    );
}

#[test_log::test]
fn bolt11_invoice_roundtrip() {
    let invoice_str = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
			h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
			5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
			h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
			j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
			ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
			guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
			ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
			p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
			8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
			j5r6drg6k6zcqj0fcwg";
    let invoice = invoice_str
        .parse::<lightning_invoice::Bolt11Invoice>()
        .unwrap();
    test_roundtrip(&invoice);
}

#[test_log::test]
fn truncated_outpoint_is_an_io_error() {
    let outpoint = bitcoin::OutPoint {
        txid: bitcoin::Txid::from_str(
            "51f7ed2f23e58cc6e139e715e9ce304a1e858416edc9079dd7b74fa8d2efc09a",
        )
        .unwrap(),
        vout: 0,
    };
    let mut encoded = outpoint.consensus_encode_to_vec();
    encoded.truncate(encoded.len() - 1);

    let err =
        bitcoin::OutPoint::consensus_decode_whole(&encoded, &ModuleDecoderRegistry::default())
            .expect_err("35 of 36 bytes are not a full outpoint");
    assert!(matches!(err, DecodeError::Io(_)), "{err:?}");
}

#[test_log::test]
fn empty_psbt_input_is_an_io_error() {
    // The PSBT magic is read through rust-bitcoin's consensus decoder, so a short
    // read arrives wrapped in `ConsensusEncoding` rather than as a
    // top-level `Io`.
    let err = bitcoin::psbt::Psbt::consensus_decode_whole(&[], &ModuleDecoderRegistry::default())
        .expect_err("empty input is not a psbt");
    assert!(matches!(err, DecodeError::Io(_)), "{err:?}");
}
