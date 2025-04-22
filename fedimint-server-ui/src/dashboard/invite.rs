use maud::{Markup, html};

// Card with invite code text and copy button
pub fn render(invite_code: &str) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Invite Code" }
            div class="card-body" {
                div class="alert alert-info text-break" {
                    (invite_code)
                }

                div class="text-center mt-3" {
                    button type="button" class="btn btn-outline-primary" id="copyInviteCodeBtn"
                        onclick=(format!("navigator.clipboard.writeText('{}');", invite_code)) {
                        "Copy to Clipboard"
                    }
                }

                p class="text-center mt-3" {
                    "Share this invite code with users to onboard them to your federation."
                }
            }
        }
    }
}
