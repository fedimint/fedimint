use fedimint_ui_common::copiable_text;
use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;

// Card with invite code text and copy button
pub fn render(invite_code: &str, ready_for_onchain_receive: bool) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Invite Code" }
            div class="card-body" {
                @if !ready_for_onchain_receive {
                    div class="alert alert-warning" {
                        "The invite code will be available once the federation is ready to receive on-chain deposits."
                    }
                } @else {
                    @let observer_link = format!("https://observer.fedimint.org/nostr?check={invite_code}");
                    @let qr_svg = QrCode::new(invite_code)
                        .expect("Failed to generate QR code")
                        .render::<qrcode::render::svg::Color>()
                        .build();

                    p { "Share this with users to onboard them to your federation." }

                    // QR Code
                    div class="text-center mb-3" {
                        div class="border rounded p-2 bg-white d-inline-block" style="width: 250px; max-width: 100%;" {
                            div style="width: 100%; height: auto; overflow: hidden;" {
                                (PreEscaped(format!(r#"<div style="width: 100%; height: auto;">{}</div>"#, qr_svg.replace("width=", "data-width=").replace("height=", "data-height=").replace("<svg", r#"<svg style="width: 100%; height: auto; display: block;""#))))
                            }
                        }
                    }

                    div class="mb-3" {
                        (copiable_text(invite_code))
                    }

                    a href=(observer_link) target="_blank" class="btn btn-outline-success w-100 py-2" {
                        "Announce on Nostr"
                    }
                }
            }
        }
    }
}
