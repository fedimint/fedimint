use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;

// Card with invite code text and copy button
pub fn render(invite_code: &str, session_count: u64) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Invite Code" }
            div class="card-body" {
                @if session_count == 0 {
                    div class="alert alert-warning" {
                        "The invite code will be available once the federation has completed its first consensus session."
                    }
                } @else {
                    @let observer_link = format!("https://observer.fedimint.org/nostr?check={invite_code}");
                    @let qr_svg = QrCode::new(invite_code)
                        .expect("Failed to generate QR code")
                        .render::<qrcode::render::svg::Color>()
                        .build();

                    // QR Code
                    div class="text-center mb-3" {
                        div class="border rounded p-2 bg-white d-inline-block" style="width: 250px; max-width: 100%;" {
                            div style="width: 100%; height: auto; overflow: hidden;" {
                                (PreEscaped(format!(r#"<div style="width: 100%; height: auto;">{}</div>"#, qr_svg.replace("width=", "data-width=").replace("height=", "data-height=").replace("<svg", r#"<svg style="width: 100%; height: auto; display: block;""#))))
                            }
                        }
                    }

                    // Flex container for both buttons side by side
                    div class="d-flex justify-content-center gap-2 mt-3" {
                        button type="button" class="btn btn-outline-primary" id="copyInviteCodeBtn"
                            onclick=(format!("navigator.clipboard.writeText('{}').then(() => {{ this.textContent='Copied!'; setTimeout(() => this.textContent='Copy to Clipboard', 2000); }}).catch(() => alert('Copy failed'))", invite_code)) {
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
}
