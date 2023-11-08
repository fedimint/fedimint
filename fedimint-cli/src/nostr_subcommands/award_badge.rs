use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Clone, Debug)]
pub struct AwardBadgeSubCommand {
    /// Badge definition event id
    #[arg(short, long)]
    badge_event_id: String,
    /// Awarded pubkeys
    #[arg(short, long, action = clap::ArgAction::Append)]
    ptag: Vec<String>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn award_badge(
    _private_key: Option<String>,
    _relays: Vec<String>,
    _difficulty_target: u8,
    _sub_command_args: &AwardBadgeSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client: blocking::Client = create_client(&keys, relays,
    // difficulty_target)?;

    // let badge_definition_query = client.get_events_of(
    //     vec![Filter::new().id(sub_command_args.badge_event_id.clone())],
    //     Some(Duration::from_secs(10)),
    // )?;

    // if badge_definition_query.len() != 1 {
    //     eprintln!("Expected one event, got {}",
    // badge_definition_query.len());     exit(1)
    // };

    // let badge_definition_event = badge_definition_query.get(0).unwrap();
    // // Verify that this event is a badge definition event
    // if badge_definition_event.kind != Kind::BadgeDefinition {
    //     eprintln!(
    //         "Unexpected badge definition event. Expected of kind {}
    // but got {}",         Kind::BadgeDefinition.as_u32(),
    //         badge_definition_event.kind.as_u32()
    //     );
    //     exit(1)
    // }

    // // Verify that the user trying to award the badge is actually the author
    // of the // badge definition
    // if badge_definition_event.pubkey != keys.public_key() {
    //     eprint!("Incorrect private key. Only the private key used for issuing
    // the badge definition can award it to other public keys");     exit(1)
    // }

    // let awarded_pubkeys = sub_command_args
    //     .ptag
    //     .iter()
    //     .map(|pubkey_string| {
    //         Tag::PubKey(
    //             XOnlyPublicKey::from_str(pubkey_string).expect("Unable to
    // parse public key"),             None,
    //         )
    //     })
    //     .collect();

    // let event = EventBuilder::award_badge(badge_definition_event,
    // awarded_pubkeys)?     .to_pow_event(&keys, difficulty_target)?;

    // // Publish event
    // let event_id = client.send_event(event)?;
    // if !sub_command_args.hex {
    //     println!(
    //         "Published badge award event with id: {}",
    //         event_id.to_bech32()?
    //     );
    // } else {
    //     println!("Published badge award event with id: {}",
    // event_id.to_hex()); }

    // Ok(())
}
