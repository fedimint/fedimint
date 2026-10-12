use clap::{Command, Subcommand};

use super::SetupAdminCmd;

#[test]
fn federation_name_help_explains_deprecation_and_replacement() {
    let mut command = SetupAdminCmd::augment_subcommands(Command::new("setup"));
    let help = command
        .find_subcommand_mut("set-local-params")
        .expect("setup has a set-local-params command")
        .render_long_help()
        .to_string();
    assert!(help.contains("--federation-name"));
    assert!(help.contains("Deprecated and ignored"));
    assert!(help.contains("Meta module"));
    assert!(help.contains("consensus threshold"));

    command
        .try_get_matches_from([
            "setup",
            "set-local-params",
            "guardian",
            "--federation-name",
            "Old name",
            "--federation-size",
            "4",
        ])
        .expect("the deprecated option remains accepted");
}
