#![cfg_attr(feature = "unstable", feature(test))]

#[cfg(feature = "unstable")]
mod bench {
    extern crate test;

    use std::collections::BTreeMap;

    use tbs::{
        aggregate_signature_shares, blind_message, dealer_keygen, sign_blinded_msg,
        unblind_signature, verify, BlindedSignatureShare, BlindingKey, Message,
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
    fn bench_aggregate(bencher: &mut Bencher) {
        let msg = Message::from_bytes(b"Hello World!");
        let bkey = BlindingKey::random();
        let bmsg = blind_message(msg, bkey);
        let (_pk, _pks, sks) = dealer_keygen(4, 5);
        let shares: BTreeMap<u64, BlindedSignatureShare> = (1_u64..)
            .zip(sks.iter().map(|sk| sign_blinded_msg(bmsg, *sk)))
            .take(4)
            .collect();

        bencher.iter(move || aggregate_signature_shares(&shares));
    }

    #[bench]
    fn bench_unblind(bencher: &mut Bencher) {
        let msg = Message::from_bytes(b"Hello World!");
        let bkey = BlindingKey::random();
        let bmsg = blind_message(msg, bkey);
        let (_pk, _pks, sks) = dealer_keygen(4, 5);
        let shares = (1_u64..)
            .zip(sks.iter().map(|sk| sign_blinded_msg(bmsg, *sk)))
            .take(4)
            .collect();
        let bsig = aggregate_signature_shares(&shares);

        bencher.iter(|| unblind_signature(bkey, bsig));
    }

    #[bench]
    fn bench_verify(bencher: &mut Bencher) {
        let msg = Message::from_bytes(b"Hello World!");
        let bkey = BlindingKey::random();
        let bmsg = blind_message(msg, bkey);
        let (pk, _pks, sks) = dealer_keygen(4, 5);
        let shares = (1_u64..)
            .zip(sks.iter().map(|sk| sign_blinded_msg(bmsg, *sk)))
            .take(4)
            .collect();
        let bsig = aggregate_signature_shares(&shares);
        let sig = unblind_signature(bkey, bsig);

        bencher.iter(|| verify(msg, sig, pk));
    }
}
