use std::time::Duration;

use clap::Args;
use nostr_sdk::prelude::*;

use crate::utils::{create_client, handle_keys};

#[derive(Args, Clone, Debug)]
pub struct ProfileBadgesSubCommand {
    /// Badge definition event id
    #[arg(short, long, action = clap::ArgAction::Append)]
    badge_id: Vec<String>,
    /// Badge award event id
    #[arg(short, long, action = clap::ArgAction::Append)]
    award_id: Vec<String>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn set_profile_badges(
    private_key: Option<String>,
    relays: Vec<String>,
    difficulty_target: u8,
    sub_command_args: &ProfileBadgesSubCommand,
) -> Result<()> {
    todo!();
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client: blocking::Client = create_client(&keys, relays,
    // difficulty_target)?;

    // let badge_definition_filter = Filter::new()
    //     .ids(sub_command_args.badge_id.clone())
    //     .kind(Kind::BadgeDefinition);
    // let badge_definition_events = client
    //     .get_events_of(vec![badge_definition_filter],
    // Some(Duration::from_secs(10)))     .unwrap();

    // let badge_award_filter = Filter::new()
    //     .ids(sub_command_args.award_id.clone())
    //     .kind(Kind::BadgeAward);
    // let badge_award_events = client
    //     .get_events_of(vec![badge_award_filter],
    // Some(Duration::from_secs(10)))     .unwrap();

    // let event = EventBuilder::profile_badges(
    //     badge_definition_events,
    //     badge_award_events,
    //     &keys.public_key(),
    // )?
    // .to_pow_event(&keys, difficulty_target)?;

    // // Publish event
    // let event_id = client.send_event(event)?;
    // if !sub_command_args.hex {
    //     println!(
    //         "Published profile badges event with id: {}",
    //         event_id.to_bech32()?
    //     );
    // } else {
    //     println!(
    //         "Published profile badges event with id: {}",
    //         event_id.to_hex()
    //     );
    // }

    // Ok(())
}
