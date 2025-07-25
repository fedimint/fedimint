use maud::{Markup, html};

// Card with invite code text and copy button
pub fn render(invite_code: &str) -> Markup {
    let observer_link = format!("https://observer.fedimint.org/nostr?check={invite_code}");

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Invite Code" }
            div class="card-body" {
                div class="alert alert-info text-break" {
                    (invite_code)
                }

                // Flex container for both buttons side by side
                div class="d-flex justify-content-center gap-2 mt-3" {
                    button type="button" class="btn btn-outline-primary" id="copyInviteCodeBtn"
                        onclick=(format!("navigator.clipboard.writeText('{}');", invite_code)) {
                        "Copy to Clipboard"
                    }

                    a href=(observer_link) target="_blank" class="btn btn-outline-success" {
                        "Announce on Nostr"
                    }
                }

                p class="text-center mt-3" {
                    "Share this invite code with users to onboard them to your federation."
                }
            }
        }
    }
}
