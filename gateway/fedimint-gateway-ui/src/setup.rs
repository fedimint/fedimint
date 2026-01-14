use axum::Form;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use fedimint_gateway_common::SetMnemonicPayload;
use fedimint_ui_common::{ROOT_ROUTE, UiState, login_layout};
use maud::html;
use serde::Deserialize;

use crate::{DashboardQuery, DynGatewayApi, RECOVER_WALLET_ROUTE, redirect_error};

#[derive(Deserialize)]
pub struct RecoverWalletForm {
    pub words: String,
}

/// Renders the main setup page with two options:
/// - Create New Wallet
/// - Recover Wallet
pub async fn setup_view<E>(
    State(_state): State<UiState<DynGatewayApi<E>>>,
    Query(msg): Query<DashboardQuery>,
) -> impl IntoResponse
where
    E: std::fmt::Display,
{
    let content = html! {
        @if let Some(error) = msg.ui_error {
            div class="alert alert-danger mb-3" { (error) }
        }
        @if let Some(success) = msg.success {
            div class="alert alert-success mb-3" { (success) }
        }

        p class="text-muted mb-4" {
            "Your gateway needs to be configured before use. "
            "Choose an option below to set up your wallet."
        }

        div class="d-grid gap-3" {
            // Create New Wallet button
            form action="/ui/wallet/create" method="post" {
                button type="submit" class="btn btn-primary btn-lg w-100" {
                    div class="fw-bold" { "Create New Wallet" }
                    small class="text-white-50" {
                        "Generate a new 12-word recovery phrase"
                    }
                }
            }

            // Recover Wallet button
            a href=(RECOVER_WALLET_ROUTE) class="btn btn-outline-secondary btn-lg w-100" {
                div class="fw-bold" { "Recover Wallet" }
                small {
                    "Use an existing 12-word recovery phrase"
                }
            }
        }
    };

    Html(login_layout("Gateway Setup", content).into_string())
}

/// Handler for creating a new wallet (generates new mnemonic)
pub async fn create_wallet_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
) -> impl IntoResponse
where
    E: std::fmt::Display,
{
    match state
        .api
        .handle_set_mnemonic_ui_msg(SetMnemonicPayload { words: None })
        .await
    {
        Ok(()) => Redirect::to(ROOT_ROUTE).into_response(),
        Err(err) => redirect_error(format!("Failed to create wallet: {err}")).into_response(),
    }
}

/// Renders the recovery form where user can enter their 12 words
pub async fn recover_wallet_form<E>(
    State(_state): State<UiState<DynGatewayApi<E>>>,
    Query(msg): Query<DashboardQuery>,
) -> impl IntoResponse
where
    E: std::fmt::Display,
{
    let content = html! {
        @if let Some(error) = msg.ui_error {
            div class="alert alert-danger mb-3" { (error) }
        }

        p class="text-muted mb-3" {
            "Enter your 12-word recovery phrase to restore your wallet."
        }

        form action=(RECOVER_WALLET_ROUTE) method="post" {
            div class="mb-3" {
                label for="words" class="form-label" {
                    "Recovery Phrase"
                }
                textarea
                    class="form-control"
                    id="words"
                    name="words"
                    rows="3"
                    placeholder="Enter your 12 words separated by spaces"
                    required
                    autocomplete="off"
                    autocapitalize="none"
                    spellcheck="false"
                {}
                div class="form-text" {
                    "Enter all 12 words in order, separated by spaces."
                }
            }

            div class="d-flex gap-2" {
                a href=(ROOT_ROUTE) class="btn btn-outline-secondary" { "Cancel" }
                button type="submit" class="btn btn-primary flex-grow-1" {
                    "Recover Wallet"
                }
            }
        }
    };

    Html(login_layout("Recover Wallet", content).into_string())
}

/// Handler for recovering a wallet with provided mnemonic words
pub async fn recover_wallet_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    Form(form): Form<RecoverWalletForm>,
) -> impl IntoResponse
where
    E: std::fmt::Display,
{
    // Normalize the words (trim, collapse whitespace)
    let words = form.words.split_whitespace().collect::<Vec<_>>().join(" ");

    match state
        .api
        .handle_set_mnemonic_ui_msg(SetMnemonicPayload { words: Some(words) })
        .await
    {
        Ok(()) => Redirect::to(ROOT_ROUTE).into_response(),
        Err(err) => redirect_error(format!("Failed to recover wallet: {err}")).into_response(),
    }
}
