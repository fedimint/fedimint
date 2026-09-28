use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::txoproof::TxOutProof;
use hex::FromHex;

#[test_log::test]
fn test_txoutproof_happy_path() {
    let txoutproof_hex = "0000a020c7f74cb7d4cbf90a40f38b8194d17996d29ad8cb8d42030000000000000\
    0000045e274cbfff8fe34e6df61079ae8c8cf5af6d53ff158488e26df5a072363693be15a6760482a0c1731b169\
    074a0a00000dc525bdf029c9d77ac1039826be603bf08837d5dfd58b763590fb3f2db32693eacd2a8b13842289e\
    d8b6b10ffbae3498987ca510d6b54a278bb85a9b6f2daa0efa52ae55f39842e890144f998258b365ae903fd5b8e\
    32b651acc65682378db2ac8376b8a8ed3777f297e5ec354ff31b80c79fd40e0aa8e961b582959db470a25db8bb8\
    0f87602a7b53fe0d0ecd3597d03b75e1af64cb229eb680daec7848e78fcf822717de5268738d49b610dd8f8eb22\
    2fa477bc85d46582c4aaa659848c8aac9440e429110c5848517b8459fd91fc8bf5ec6740c708e2980ddf4070f7f\
    c2c14247830c014b559c6fb3dad9408237a78bb2bca0b2016a3c4cac2e450a09b78e1a78fcb9fd1edc4989a5ae6\
    ba438b81a400a22fa172da6e2bec5b67e21841e975a696b51dff22d12dcc27417f9017b0fedcf7bbf7ae4c1d278\
    d92c364b1a1675855927a8a8f22e1e3441bb3389d7d82e57d68b46fe946546e7aea7f58ed3ae5aec4b3b99ca87e\
    9602cb7c776730435c1713a1ca57c0c6761576fbfb17da642aae2a4ce874e32b5c0cba450163b14b6b94bc479cb\
    58a30f7ae5b909ffdd020073f04ff370000";

    let empty_module_registry = ModuleDecoderRegistry::default();
    let txoutproof = TxOutProof::consensus_decode_whole(
        &Vec::from_hex(txoutproof_hex).unwrap(),
        &empty_module_registry,
    )
    .unwrap();

    assert_eq!(
        txoutproof.block(),
        "0000000000000000000761505b672f2f7fc3822a5a95089fa469c3fb16ee574b"
            .parse()
            .unwrap()
    );

    assert!(
        txoutproof.contains_tx(
            "efa0daf2b6a985bb78a2546b0d51ca878949e3baff106b8bed892284138b2acd"
                .parse()
                .unwrap()
        )
    );
}
