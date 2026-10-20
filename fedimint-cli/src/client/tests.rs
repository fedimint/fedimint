use std::collections::BTreeMap;

use fedimint_core::config::FederationId;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::{Amount, TieredMulti};
use fedimint_mint_client::{OOBNotes, SpendableNote};

use super::{combine_notes, split_notes};

#[test]
fn split_and_combine_preserve_notes_and_federation() {
    let federation: FederationId = "21".repeat(32).parse().expect("valid federation");
    let note = SpendableNote::consensus_decode_hex(
        "a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd",
        &ModuleRegistry::default(),
    ).expect("valid note fixture");
    let notes: TieredMulti<_> = [(Amount::from_sats(1), note), (Amount::from_sats(2), note)]
        .into_iter()
        .collect();
    let original = OOBNotes::new(federation.to_prefix(), notes.clone());
    let split = split_notes(&original);
    let bundles: BTreeMap<Amount, Vec<OOBNotes>> =
        serde_json::from_value(split["notes"].clone()).expect("split JSON");
    assert_eq!(bundles.len(), 2);
    let inputs: Vec<_> = bundles.into_values().flatten().collect();
    for input in &inputs {
        assert_eq!(input.notes().count_items(), 1);
        assert_eq!(input.federation_id_prefix(), federation.to_prefix());
    }
    let combined = combine_notes(&inputs).expect("same federation");
    let combined: OOBNotes =
        serde_json::from_value(combined["notes"].clone()).expect("combined JSON");
    assert_eq!(combined.federation_id_prefix(), federation.to_prefix());
    assert_eq!(combined.notes(), &notes);
}

#[test]
fn combine_rejects_mixed_federations_before_combining_notes() {
    let a: FederationId = "21".repeat(32).parse().expect("valid federation");
    let b: FederationId = "42".repeat(32).parse().expect("valid federation");
    let error = combine_notes(&[
        OOBNotes::new(a.to_prefix(), TieredMulti::default()),
        OOBNotes::new(b.to_prefix(), TieredMulti::default()),
    ])
    .expect_err("mixed federations");
    assert_eq!(
        error.to_string(),
        format!(
            "Trying to combine e-cash from different federations: {} and {}",
            a.to_prefix(),
            b.to_prefix()
        ),
    );
}
