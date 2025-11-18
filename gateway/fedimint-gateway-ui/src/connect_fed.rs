use std::fmt::Display;

use axum::Form;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use fedimint_gateway_common::ConnectFedPayload;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{ROOT_ROUTE, UiState, dashboard_layout};
use maud::{Markup, html};

use crate::{CONNECT_FEDERATION_ROUTE, DynGatewayApi};

pub fn render() -> Markup {
    html!(
        div class="card h-100" {
            div class="card-header dashboard-header" { "Connect a new Federation" }
            div class="card-body" {
                form method="post" action=(CONNECT_FEDERATION_ROUTE) {
                    div class="mb-3" {
                        label class="form-label" { "Invite Code" }
                        input type="text" class="form-control" name="invite_code" required;
                    }
                    button type="submit" class="btn btn-primary" { "Submit" }
                }
            }
        }
    )
}

pub async fn connect_federation_handler<E: Display>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<ConnectFedPayload>,
) -> impl IntoResponse {
    match state.api.handle_connect_federation(payload).await {
        Ok(_) => {
            // Redirect back to dashboard on success
            Redirect::to(ROOT_ROUTE).into_response()
        }
        Err(err) => {
            let content = html! {
                div class="alert alert-danger mt-4" {
                    strong { "Failed to connect federation: " }
                    (err.to_string())
                }
            };
            Html(dashboard_layout(content, "Connect Federation Error", None).into_string())
                .into_response()
        }
    }
}
