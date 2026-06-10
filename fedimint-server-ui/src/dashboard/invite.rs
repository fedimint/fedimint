use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse};
use chrono::Utc;
use fedimint_server_core::dashboard_ui::DynDashboardApi;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{UiState, copiable_text};
use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;
use serde::Deserialize;

pub const INVITE_CREATE_ROUTE: &str = "/invite/create";

// Card with a form to generate invite codes with an expiration date and user
// limit
pub fn render(session_count: u64) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Invite Code" }
            div class="card-body" {
                @if session_count == 0 {
                    div class="alert alert-warning" {
                        "Invite codes will be available once the federation has completed its first consensus session."
                    }
                } @else {
                    div id="invite-container" {
                        (invite_form())
                    }
                }
            }
        }
    }
}

// Form to select the expiration and user limit of a new invite code; the
// generated invite code replaces it via htmx
fn invite_form() -> Markup {
    html! {
        div class="alert alert-info" {
            "Generate an invite code to onboard users to your federation. Every invite code has an expiration date and a limit on the number of users that can join with it."
        }

        form hx-post=(INVITE_CREATE_ROUTE) hx-target="#invite-container" hx-swap="innerHTML" {
            div class="form-group mb-3" {
                label for="expires_in" class="form-label" { "Expires in Days" }
                input type="number" class="form-control" id="expires_in" name="expires_in" min="1" value="30" required;
            }
            div class="form-group mb-3" {
                label for="user_limit" class="form-label" { "User Limit" }
                input type="number" class="form-control" id="user_limit" name="user_limit" min="1" value="50" required;
            }
            button type="submit" class="btn btn-primary w-100 py-2" { "Generate Invite Code" }
        }
    }
}

// QR Code
fn qr_code(data: &str) -> Markup {
    let qr_svg = QrCode::new(data)
        .expect("Failed to generate QR code")
        .render::<qrcode::render::svg::Color>()
        .build();

    html! {
        div class="text-center mb-3" {
            div class="border rounded p-2 bg-white d-inline-block" style="width: 250px; max-width: 100%;" {
                div style="width: 100%; height: auto; overflow: hidden;" {
                    (PreEscaped(format!(r#"<div style="width: 100%; height: auto;">{}</div>"#, qr_svg.replace("width=", "data-width=").replace("height=", "data-height=").replace("<svg", r#"<svg style="width: 100%; height: auto; display: block;""#))))
                }
            }
        }
    }
}

// Re-renders the form with an error alert below it so the user can retry
fn form_with_error(message: &str) -> Markup {
    html! {
        (invite_form())

        div class="alert alert-danger mt-3" { (message) }
    }
}

#[derive(Deserialize)]
pub struct CreateInviteInput {
    pub expires_in: u64,
    pub user_limit: u64,
}

// Creates an invite code with the selected expiration and user limit and
// returns the fragment htmx swaps into the invite card
pub async fn post_create_invite(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(input): Form<CreateInviteInput>,
) -> impl IntoResponse {
    if input.expires_in == 0 {
        return Html(
            form_with_error("The invite code needs to be valid for at least one day").into_string(),
        );
    }

    if input.user_limit == 0 {
        return Html(form_with_error("The user limit needs to be at least one").into_string());
    }

    let Some(expires_at) = Utc::now().checked_add_days(chrono::Days::new(input.expires_in)) else {
        return Html(form_with_error("Could not compute the expiration date").into_string());
    };

    let expiry = u64::try_from(expires_at.timestamp())
        .expect("Timestamp is positive since it is in the future");

    let invite_code = state.api.create_invite_code(expiry, input.user_limit).await;

    Html(
        html! {
            (qr_code(&invite_code))

            div class="mb-3" {
                (copiable_text(&invite_code))
            }

            div class="alert alert-info" {
                "This invite code expires on "
                (expires_at.format("%Y-%m-%d %H:%M UTC"))
                " and can be used by up to "
                (input.user_limit)
                " users."
            }
        }
        .into_string(),
    )
}
