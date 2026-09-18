use super::NumPeers;

#[test]
fn quorum_parameters_match_supported_federation_sizes() {
    for (total, max_evil, one_honest, degree, threshold) in [
        (1, 0, 1, 0, 1),
        (4, 1, 2, 2, 3),
        (7, 2, 3, 4, 5),
        (10, 3, 4, 6, 7),
    ] {
        let peers = NumPeers::from(total);

        assert_eq!(peers.max_evil_expect(), max_evil);
        assert_eq!(peers.one_honest_expect(), one_honest);
        assert_eq!(peers.degree_expect(), degree);
        assert_eq!(peers.threshold_expect(), threshold);
    }
}

#[test]
#[should_panic(expected = "a federation must have at least one guardian")]
fn max_evil_rejects_zero_peers() {
    NumPeers::from(0).max_evil_expect();
}

#[test]
#[should_panic(expected = "a federation must have at least one guardian")]
fn one_honest_rejects_zero_peers() {
    NumPeers::from(0).one_honest_expect();
}

#[test]
#[should_panic(expected = "a federation must have at least one guardian")]
fn degree_rejects_zero_peers() {
    NumPeers::from(0).degree_expect();
}

#[test]
#[should_panic(expected = "a federation must have at least one guardian")]
fn threshold_rejects_zero_peers() {
    NumPeers::from(0).threshold_expect();
}
