use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect};
use fedimint_core::admin_client::DecommissionAnnouncement;
use fedimint_core::invite_code::InviteCode;
use fedimint_server_core::dashboard_ui::DynDashboardApi;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{ROOT_ROUTE, UiState, dashboard_layout};
use maud::{Markup, html};
use serde::Deserialize;

use crate::{CLEAR_DECOMMISSION_ROUTE, SET_DECOMMISSION_ROUTE};

#[derive(Debug, Deserialize)]
pub struct DecommissionForm {
    pub successor_invite_code: Option<String>,
}

pub fn render(announcement: Option<&DecommissionAnnouncement>) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Federation Decommission" }
            div class="card-body" {
                @if let Some(announcement) = announcement {
                    div class="alert alert-info" {
                        strong { "Decommission Announced" }
                        @if let Some(ref successor) = announcement.successor {
                            p class="mb-0 mt-2" { (successor.to_string()) }
                        }
                    }
                    form method="post" action=(CLEAR_DECOMMISSION_ROUTE) {
                        button type="submit" class="btn btn-primary" {
                            "Clear Decommission Announcement"
                        }
                    }
                } @else {
                    div class="alert alert-warning" {
                        "You can set an optional invite code for a successor federation - if you do this all guardians have to set the exact same invite code."
                    }
                    form method="post" action=(SET_DECOMMISSION_ROUTE) {
                        div class="form-group mb-3" {
                            input
                                type="text"
                                class="form-control"
                                id="successor_invite_code"
                                name="successor_invite_code"
                                placeholder="Enter Optional Invite Code";
                        }
                        button type="submit" class="btn btn-primary" {
                            "Announce Decommission"
                        }
                    }
                }
            }
        }
    }
}

pub async fn post_set_decommission(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<DecommissionForm>,
) -> impl IntoResponse {
    let input = form.successor_invite_code.filter(|s| !s.trim().is_empty());

    let successor = match &input {
        Some(s) => match s.parse::<InviteCode>() {
            Ok(code) => Some(code),
            Err(_) => {
                let content = html! {
                    div class="alert alert-danger" { "Invalid invite code format" }
                    div class="button-container" {
                        a href="/" class="btn btn-primary" { "Return to Dashboard" }
                    }
                };
                return Html(dashboard_layout(content, "Invalid Invite Code", None).into_string())
                    .into_response();
            }
        },
        None => None,
    };

    state
        .api
        .set_decommission_announcement(Some(DecommissionAnnouncement { successor }))
        .await;

    Redirect::to(ROOT_ROUTE).into_response()
}

pub async fn post_clear_decommission(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    state.api.set_decommission_announcement(None).await;

    Redirect::to(ROOT_ROUTE)
}
