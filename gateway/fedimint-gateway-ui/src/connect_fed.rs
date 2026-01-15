use std::fmt::Display;

use axum::Form;
use axum::extract::State;
use axum::response::IntoResponse;
use fedimint_gateway_common::ConnectFedPayload;
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{Markup, html};

use crate::{CONNECT_FEDERATION_ROUTE, DynGatewayApi, redirect_error, redirect_success};

pub fn render() -> Markup {
    html!(
        div class="card h-100" {
            div class="card-header dashboard-header" { "Connect a new Federation" }
            div class="card-body" {
                form method="post" action=(CONNECT_FEDERATION_ROUTE)
                    onsubmit="var btn = this.querySelector('button[type=submit]'); \
                              var isRecover = this.querySelector('#recover-checkbox').checked; \
                              btn.disabled = true; \
                              btn.innerHTML = '<span class=\"spinner-border spinner-border-sm\" role=\"status\"></span> ' + (isRecover ? 'Recovering...' : 'Connecting...');"
                {
                    div class="mb-3" {
                        label class="form-label" { "Invite Code" }
                        input type="text" class="form-control" name="invite_code" required;
                    }
                    div class="mb-3 form-check" {
                        input type="checkbox" class="form-check-input" name="recover" value="true" id="recover-checkbox";
                        label class="form-check-label" for="recover-checkbox" { "Recover" }
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
        Ok(info) => {
            // Redirect back to dashboard on success
            redirect_success(format!(
                "Successfully joined {}",
                info.federation_name
                    .unwrap_or("Unnamed Federation".to_string())
            ))
            .into_response()
        }
        Err(err) => redirect_error(format!("Failed to join federation: {err}")).into_response(),
    }
}
