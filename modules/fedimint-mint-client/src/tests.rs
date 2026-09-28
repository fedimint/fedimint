use std::fmt::Display;
use std::str::FromStr;

use assert_matches::assert_matches;
use bitcoin_hashes::Hash;
use fedimint_core::base32::FEDIMINT_PREFIX;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, DecodeError};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::{Amount, OutPoint, PeerId, Tiered, TieredCounts, TieredMulti, TransactionId};
use fedimint_mint_common::config::FeeConsensus;
use itertools::Itertools;
use serde_json::json;

use crate::error::{AwaitOutputFinalizedError, OOBNotesParseError, SelectNotesError};
use crate::{
    MintOperationMetaVariant, NotesSelector, OOBNotes, OOBNotesPart, SelectNotesWithExactAmount,
    SpendableNote, SpendableNoteUndecoded, represent_amount, select_notes_from_stream,
};

#[test]
fn represent_amount_targets_denomination_sets() {
    fn tiers(tiers: Vec<u64>) -> Tiered<()> {
        tiers
            .into_iter()
            .map(|tier| (Amount::from_sats(tier), ()))
            .collect()
    }

    fn denominations(denominations: Vec<(Amount, usize)>) -> TieredCounts {
        TieredCounts::from_iter(denominations)
    }

    let starting = notes(vec![
        (Amount::from_sats(1), 1),
        (Amount::from_sats(2), 3),
        (Amount::from_sats(3), 2),
    ])
    .summary();
    let tiers = tiers(vec![1, 2, 3, 4]);

    // target 3 tiers will fill out the 1 and 3 denominations
    assert_eq!(
        represent_amount(
            Amount::from_sats(6),
            &starting,
            &tiers,
            3,
            &FeeConsensus::zero()
        ),
        denominations(vec![(Amount::from_sats(1), 3), (Amount::from_sats(3), 1),])
    );

    // target 2 tiers will fill out the 1 and 4 denominations
    assert_eq!(
        represent_amount(
            Amount::from_sats(6),
            &starting,
            &tiers,
            2,
            &FeeConsensus::zero()
        ),
        denominations(vec![(Amount::from_sats(1), 2), (Amount::from_sats(4), 1)])
    );
}

#[test_log::test(tokio::test)]
async fn select_notes_avg_test() {
    let max_amount = Amount::from_sats(1_000_000);
    let tiers = Tiered::gen_denominations(2, max_amount);
    let tiered = represent_amount::<()>(
        max_amount,
        &TieredCounts::default(),
        &tiers,
        3,
        &FeeConsensus::zero(),
    );

    let mut total_notes = 0;
    for multiplier in 1..100 {
        let stream = reverse_sorted_note_stream(tiered.iter().collect());
        let select = select_notes_from_stream(
            stream,
            Amount::from_sats(multiplier * 1000),
            FeeConsensus::zero(),
        )
        .await;
        total_notes += select.unwrap().into_iter_items().count();
    }
    assert_eq!(total_notes / 100, 10);
}

#[test_log::test(tokio::test)]
async fn select_notes_returns_exact_amount_with_minimum_notes() {
    let f = || {
        reverse_sorted_note_stream(vec![
            (Amount::from_sats(1), 10),
            (Amount::from_sats(5), 10),
            (Amount::from_sats(20), 10),
        ])
    };
    assert_eq!(
        select_notes_from_stream(f(), Amount::from_sats(7), FeeConsensus::zero())
            .await
            .unwrap(),
        notes(vec![(Amount::from_sats(1), 2), (Amount::from_sats(5), 1)])
    );
    assert_eq!(
        select_notes_from_stream(f(), Amount::from_sats(20), FeeConsensus::zero())
            .await
            .unwrap(),
        notes(vec![(Amount::from_sats(20), 1)])
    );
}

#[test_log::test(tokio::test)]
async fn select_notes_returns_next_smallest_amount_if_exact_change_cannot_be_made() {
    let stream = reverse_sorted_note_stream(vec![
        (Amount::from_sats(1), 1),
        (Amount::from_sats(5), 5),
        (Amount::from_sats(20), 5),
    ]);
    assert_eq!(
        select_notes_from_stream(stream, Amount::from_sats(7), FeeConsensus::zero())
            .await
            .unwrap(),
        notes(vec![(Amount::from_sats(5), 2)])
    );
}

#[test_log::test(tokio::test)]
async fn select_notes_uses_big_note_if_small_amounts_are_not_sufficient() {
    let stream = reverse_sorted_note_stream(vec![
        (Amount::from_sats(1), 3),
        (Amount::from_sats(5), 3),
        (Amount::from_sats(20), 2),
    ]);
    assert_eq!(
        select_notes_from_stream(stream, Amount::from_sats(39), FeeConsensus::zero())
            .await
            .unwrap(),
        notes(vec![(Amount::from_sats(20), 2)])
    );
}

#[test_log::test(tokio::test)]
async fn select_notes_returns_error_if_amount_is_too_large() {
    let stream = reverse_sorted_note_stream(vec![(Amount::from_sats(10), 1)]);
    let error = select_notes_from_stream(stream, Amount::from_sats(100), FeeConsensus::zero())
        .await
        .unwrap_err();
    assert_eq!(error.total_amount, Amount::from_sats(10));
}

#[test_log::test(tokio::test)]
async fn selecting_an_unrepresentable_exact_amount_reports_what_was_selected() {
    let notes = reverse_sorted_note_stream(vec![(Amount::from_msats(4), 1)]);

    let err = SelectNotesWithExactAmount
        .select_notes(notes, Amount::from_msats(3), FeeConsensus::zero())
        .await
        .expect_err("Three msats cannot be made from a single four-msat note");

    assert_matches!(
        err,
        SelectNotesError::NoExactAmount { requested, selected }
            if requested == Amount::from_msats(3) && selected == Amount::from_msats(4)
    );
}

fn reverse_sorted_note_stream(
    notes: Vec<(Amount, usize)>,
) -> impl futures::Stream<Item = (Amount, String)> {
    futures::stream::iter(
        notes
            .into_iter()
            // We are creating `number` dummy notes of `amount` value
            .flat_map(|(amount, number)| vec![(amount, "dummy note".into()); number])
            .sorted()
            .rev(),
    )
}

fn notes(notes: Vec<(Amount, usize)>) -> TieredMulti<String> {
    notes
        .into_iter()
        .flat_map(|(amount, number)| vec![(amount, "dummy note".into()); number])
        .collect()
}

#[test]
fn decoding_empty_oob_notes_fails() {
    let empty_oob_notes = OOBNotes::new(FederationId::dummy().to_prefix(), TieredMulti::default());
    let oob_notes_string = empty_oob_notes.to_string();

    let res = oob_notes_string.parse::<OOBNotes>();

    assert!(res.is_err(), "An empty OOB notes string should not parse");
}

fn test_roundtrip_serialize_str<T, F>(data: T, assertions: F)
where
    T: FromStr + Display + crate::Encodable + crate::Decodable,
    <T as FromStr>::Err: std::fmt::Debug,
    F: Fn(T),
{
    let data_parsed = data.to_string().parse().expect("Deserialization failed");

    assertions(data_parsed);

    let data_parsed = crate::base32::encode_prefixed(FEDIMINT_PREFIX, &data)
        .parse()
        .expect("Deserialization failed");

    assertions(data_parsed);

    assertions(data);
}

#[test]
fn notes_encode_decode() {
    let federation_id_1 = FederationId(bitcoin_hashes::sha256::Hash::from_byte_array([0x21; 32]));
    let federation_id_prefix_1 = federation_id_1.to_prefix();
    let federation_id_2 = FederationId(bitcoin_hashes::sha256::Hash::from_byte_array([0x42; 32]));
    let federation_id_prefix_2 = federation_id_2.to_prefix();

    let notes = vec![(
        Amount::from_sats(1),
        SpendableNote::consensus_decode_hex("a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd", &ModuleRegistry::default()).unwrap(),
    )]
    .into_iter()
    .collect::<TieredMulti<_>>();

    // Can decode inviteless notes
    let notes_no_invite = OOBNotes::new(federation_id_prefix_1, notes.clone());
    test_roundtrip_serialize_str(notes_no_invite, |oob_notes| {
        assert_eq!(oob_notes.notes(), &notes);
        assert_eq!(oob_notes.federation_id_prefix(), federation_id_prefix_1);
        assert_eq!(oob_notes.federation_invite(), None);
    });

    // Can decode notes with invite
    let invite = InviteCode::new(
        "wss://foo.bar".parse().unwrap(),
        PeerId::from(0),
        federation_id_1,
        None,
    );
    let notes_invite = OOBNotes::new_with_invite(notes.clone(), &invite);
    test_roundtrip_serialize_str(notes_invite, |oob_notes| {
        assert_eq!(oob_notes.notes(), &notes);
        assert_eq!(oob_notes.federation_id_prefix(), federation_id_prefix_1);
        assert_eq!(oob_notes.federation_invite(), Some(invite.clone()));
    });

    // Can decode notes without federation id prefix, so we can optionally remove it
    // in the future
    let notes_no_prefix = OOBNotes(vec![
        OOBNotesPart::Notes(notes.clone()),
        OOBNotesPart::Invite {
            peer_apis: vec![(PeerId::from(0), "wss://foo.bar".parse().unwrap())],
            federation_id: federation_id_1,
        },
    ]);
    test_roundtrip_serialize_str(notes_no_prefix, |oob_notes| {
        assert_eq!(oob_notes.notes(), &notes);
        assert_eq!(oob_notes.federation_id_prefix(), federation_id_prefix_1);
    });

    // Rejects notes with inconsistent federation id
    let notes_inconsistent = OOBNotes(vec![
        OOBNotesPart::Notes(notes),
        OOBNotesPart::Invite {
            peer_apis: vec![(PeerId::from(0), "wss://foo.bar".parse().unwrap())],
            federation_id: federation_id_1,
        },
        OOBNotesPart::FederationIdPrefix(federation_id_prefix_2),
    ]);
    let notes_inconsistent_str = notes_inconsistent.to_string();
    assert!(notes_inconsistent_str.parse::<OOBNotes>().is_err());
}

#[test]
fn spendable_note_undecoded_sanity() {
    // TODO: add more hex dumps to the loop
    #[allow(clippy::single_element_loop)]
    for note_hex in [
        "a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd",
    ] {
        let note =
            SpendableNote::consensus_decode_hex(note_hex, &ModuleRegistry::default()).unwrap();
        let note_undecoded =
            SpendableNoteUndecoded::consensus_decode_hex(note_hex, &ModuleRegistry::default())
                .unwrap()
                .decode()
                .unwrap();
        assert_eq!(note, note_undecoded,);
        assert_eq!(
            serde_json::to_string(&note).unwrap(),
            serde_json::to_string(&note_undecoded).unwrap(),
        );
    }
}

#[test]
fn reissuance_meta_compatibility_02_03() {
    let dummy_outpoint = OutPoint {
        txid: TransactionId::all_zeros(),
        out_idx: 0,
    };

    let old_meta_json = json!({
        "reissuance": {
            "out_point": dummy_outpoint
        }
    });

    let old_meta: MintOperationMetaVariant =
        serde_json::from_value(old_meta_json).expect("parsing old reissuance meta failed");
    assert_eq!(
        old_meta,
        MintOperationMetaVariant::Reissuance {
            legacy_out_point: Some(dummy_outpoint),
            txid: None,
            out_point_indices: vec![],
        }
    );

    let new_meta_json = serde_json::to_value(MintOperationMetaVariant::Reissuance {
        legacy_out_point: None,
        txid: Some(dummy_outpoint.txid),
        out_point_indices: vec![0],
    })
    .expect("serializing always works");
    assert_eq!(
        new_meta_json,
        json!({
            "reissuance": {
                "txid": dummy_outpoint.txid,
                "out_point_indices": [dummy_outpoint.out_idx],
            }
        })
    );
}

#[test]
fn spend_oob_meta_no_timeout_defaults_to_false() {
    let notes = vec![(
        Amount::from_sats(1),
        SpendableNote::consensus_decode_hex("a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd", &ModuleRegistry::default()).unwrap(),
    )]
    .into_iter()
    .collect::<TieredMulti<_>>();
    let oob_notes = OOBNotes::new(FederationId::dummy().to_prefix(), notes);
    let mut old_meta_json = serde_json::to_value(MintOperationMetaVariant::SpendOOB {
        requested_amount: Amount::from_sats(42),
        oob_notes: oob_notes.clone(),
        no_timeout: false,
    })
    .expect("serializing always works");
    old_meta_json
        .get_mut("spend_o_o_b")
        .expect("spend OOB variant should serialize as spend_o_o_b")
        .as_object_mut()
        .expect("spend OOB variant should serialize to an object")
        .remove("no_timeout");
    assert_eq!(
        old_meta_json,
        json!({
            "spend_o_o_b": {
                "requested_amount": Amount::from_sats(42),
                "oob_notes": oob_notes.clone(),
            }
        })
    );

    let old_meta: MintOperationMetaVariant =
        serde_json::from_value(old_meta_json).expect("parsing old spend OOB meta failed");
    assert_eq!(
        old_meta,
        MintOperationMetaVariant::SpendOOB {
            requested_amount: Amount::from_sats(42),
            oob_notes,
            no_timeout: false,
        }
    );
}

#[test]
fn parsing_a_non_encoded_string_names_the_encoding() {
    let err = OOBNotes::from_str("not base32 or base64 $$$")
        .expect_err("A string that is neither base32 nor base64 cannot be notes");

    assert_matches!(err, OOBNotesParseError::Encoding);
}

#[test]
fn the_parse_error_prints_its_cause_because_clap_only_shows_display() {
    let err = OOBNotesParseError::Decode(DecodeError::from_str("no notes here"));

    assert!(
        err.to_string().contains("no notes here"),
        "clap and serde print only Display, so the cause has to be in the message"
    );
}

#[test]
fn a_finalization_failure_carries_the_state_machines_reason() {
    use fedimint_core::util::FmtCompact as _;

    let err = AwaitOutputFinalizedError::Failed {
        reason: "guardian refused the blind signature".to_owned(),
    };

    assert!(
        err.fmt_compact().to_string().contains("guardian refused"),
        "the reason the state machine recorded has to survive into the Failed state"
    );
}

#[test]
fn a_share_from_a_peer_we_have_no_key_for_names_the_peer() {
    use std::collections::BTreeMap;

    use bls12_381::G1Affine;
    use fedimint_api_client::api::SerdeOutputOutcome;
    use fedimint_core::core::DynOutputOutcome;
    use fedimint_core::module::CommonModuleInit;
    use fedimint_mint_common::{MintCommonInit, MintOutputOutcome};
    use tbs::{BlindedMessage, BlindedSignatureShare};

    use crate::error::VerifyBlindShareError;
    use crate::output::verify_blind_share;

    let peer = PeerId::from(7);
    let decoder = MintCommonInit::decoder();
    let outcome = MintOutputOutcome::new_v0(BlindedSignatureShare(G1Affine::identity()));
    let serde_outcome = SerdeOutputOutcome::from(&DynOutputOutcome::from_typed(0, outcome));

    let err = verify_blind_share(
        peer,
        &serde_outcome,
        Amount::from_sats(1),
        BlindedMessage(G1Affine::identity()),
        &decoder,
        &BTreeMap::new(),
    )
    .expect_err("no peer keys are known, so no key can be found for the peer");

    assert_matches!(err, VerifyBlindShareError::UnknownPeer { peer: p } if p == peer);
}
