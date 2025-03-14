use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;
use qrcode::render::svg;

// Function to generate QR code SVG from input string
pub fn generate_qr_code_svg(data: &str) -> String {
    QrCode::new(data)
        .expect("Failed to generate QR code - should never happen with valid invite code")
        .render()
        .min_dimensions(300, 300)
        .max_dimensions(300, 300)
        .quiet_zone(false)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build()
}

// Card with button to open the invite code modal
pub fn invite_code_card() -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Invite Code" }
            div class="card-body d-flex flex-column justify-content-center align-items-center" {
                // Information about the invite code
                p class="text-center mb-4" {
                    "Share this invite code with users to onboard them to your federation."
                }

                // Button to open the modal
                button type="button" class="btn btn-primary setup-btn"
                       data-bs-toggle="modal" data-bs-target="#inviteCodeModal" {
                    "View Invite Code"
                }
            }
        }
    }
}

// Modal displaying the invite code QR code
pub fn invite_code_modal(invite_code: &str) -> Markup {
    html! {
        // Modal for Invite Code QR
        div class="modal fade" id="inviteCodeModal" tabindex="-1" aria-labelledby="inviteCodeModalLabel" aria-hidden="true" {
            div class="modal-dialog modal-dialog-centered" style="max-width: 360px;" {
                div class="modal-content" {
                    div class="modal-header py-1" {
                        h5 class="modal-title fs-6" id="inviteCodeModalLabel" { "Invite Code" }
                        button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close" {}
                    }
                    div class="modal-body" style="padding: 30px; text-align: center;" {
                        // QR Code with 30px padding all around
                        (PreEscaped(generate_qr_code_svg(invite_code)))
                    }
                    div class="modal-footer justify-content-center py-2" {
                        // Copy button - centered and larger
                        button type="button" class="btn btn-primary" id="copyInviteCodeBtn"
                            onclick=(format!("navigator.clipboard.writeText('{}'); this.innerText='Copied!'; setTimeout(() => this.innerText='Copy Invite Code', 2000);", invite_code)) {
                            "Copy Invite Code"
                        }
                    }
                }
            }
        }
    }
}
