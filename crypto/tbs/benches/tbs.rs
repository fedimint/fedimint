#![cfg_attr(feature = "unstable", feature(test))]

#[cfg(feature = "unstable")]
mod bench {
    extern crate test;

    use tbs::{
        blind_message, combine_valid_shares, dealer_keygen, sign_blinded_msg, unblind_signature,
        verify, BlindingKey, Message,
    };
    use test::Bencher;

    #[bench]
    fn bench_blinding(bencher: &mut Bencher) {
        bencher.iter(|| {
            let msg = Message::from_bytes(b"Hello World!");
            let bkey = BlindingKey::random();
            blind_message(msg, bkey)
        });
    }

    #[bench]
    fn bench_signing(bencher: &mut Bencher) {
        let msg = Message::from_bytes(b"Hello World!");
        let bkey = BlindingKey::random();
        let bmsg = blind_message(msg, bkey);
        let (_pk, _pks, sks) = dealer_keygen(4, 5);

        bencher.iter(|| sign_blinded_msg(bmsg, sks[0]));
    }

    #[bench]
    fn bench_combine(bencher: &mut Bencher) {
        let msg = Message::from_bytes(b"Hello World!");
        let bkey = BlindingKey::random();
        let bmsg = blind_message(msg, bkey);
        let (_pk, _pks, sks) = dealer_keygen(4, 5);
        let shares = sks
            .iter()
            .map(|sk| sign_blinded_msg(bmsg, *sk))
            .enumerate()
            .collect::<Vec<_>>();

        bencher.iter(move || combine_valid_shares(shares.clone(), 4));
    }

    #[bench]
    fn bench_unblind(bencher: &mut Bencher) {
        let msg = Message::from_bytes(b"Hello World!");
        let bkey = BlindingKey::random();
        let bmsg = blind_message(msg, bkey);
        let (_pk, _pks, sks) = dealer_keygen(4, 5);
        let shares = sks
            .iter()
            .map(|sk| sign_blinded_msg(bmsg, *sk))
            .enumerate()
            .collect::<Vec<_>>();
        let bsig = combine_valid_shares(shares, 4);

        bencher.iter(|| unblind_signature(bkey, bsig));
    }

    #[bench]
    fn bench_verify(bencher: &mut Bencher) {
        let msg = Message::from_bytes(b"Hello World!");
        let bkey = BlindingKey::random();
        let bmsg = blind_message(msg, bkey);
        let (pk, _pks, sks) = dealer_keygen(4, 5);
        let shares = sks
            .iter()
            .map(|sk| sign_blinded_msg(bmsg, *sk))
            .enumerate()
            .collect::<Vec<_>>();
        let bsig = combine_valid_shares(shares, 4);
        let sig = unblind_signature(bkey, bsig);

        bencher.iter(|| verify(msg, sig, pk));
    }
}
