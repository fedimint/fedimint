use axum::Form;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use bip39::Language;
use fedimint_gateway_common::SetMnemonicPayload;
use fedimint_ui_common::{ROOT_ROUTE, UiState, login_layout};
use maud::{PreEscaped, html};
use serde::Deserialize;

use crate::{
    CREATE_WALLET_ROUTE, DashboardQuery, DynGatewayApi, RECOVER_WALLET_ROUTE, redirect_error,
};

#[derive(Deserialize)]
pub struct RecoverWalletForm {
    pub word1: String,
    pub word2: String,
    pub word3: String,
    pub word4: String,
    pub word5: String,
    pub word6: String,
    pub word7: String,
    pub word8: String,
    pub word9: String,
    pub word10: String,
    pub word11: String,
    pub word12: String,
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
            form action=(CREATE_WALLET_ROUTE) method="post" {
                button type="submit" class="btn btn-primary btn-lg w-100" {
                    div class="fw-bold" { "Create New Wallet" }
                    small class="text-white" {
                        "Generate a new 12-word recovery phrase"
                    }
                }
            }

            // Recover Wallet button
            a href=(RECOVER_WALLET_ROUTE) class="btn btn-outline-secondary btn-lg w-100" {
                div class="fw-bold" { "Recover Wallet" }
                small class="text-secondary" {
                    "Use an existing 12-word recovery phrase"
                }
            }
        }
    };

    Html(login_layout("Setup Gateway", content).into_string())
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
        .handle_set_mnemonic_msg(SetMnemonicPayload { words: None })
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

        div class="alert alert-warning mb-3" {
            strong { "Note: " }
            "After recovery, you will need to re-join the federations you were previously connected to in order to recover your ecash."
        }

        form action=(RECOVER_WALLET_ROUTE) method="post" {
            div class="d-flex flex-column flex-wrap gap-2 mb-3" style="height: 19.5rem;" {
                @for i in 1..=12 {
                    div style="width: calc(50% - 0.25rem);" {
                        div class="input-group" {
                            span class="input-group-text" style="min-width: 3rem; justify-content: center;" {
                                (i)
                            }
                            input
                                type="text"
                                class="form-control"
                                id=(format!("word{}", i))
                                name=(format!("word{}", i))
                                placeholder=(format!("Word {}", i))
                                required
                                autocomplete="off"
                                autocapitalize="none"
                                spellcheck="false";
                        }
                    }
                }
            }

            div class="d-flex gap-2" {
                a href=(ROOT_ROUTE) class="btn btn-outline-secondary" { "Cancel" }
                button type="submit" class="btn btn-primary flex-grow-1" {
                    "Recover Wallet"
                }
            }
        }

        // Embed BIP39 word list and validation script
        script {
            (PreEscaped(format!(
                "const BIP39_WORDS = {};",
                serde_json::to_string(&Language::English.word_list().to_vec()).expect("Failed to serialize BIP39 word list")
            )))
            (PreEscaped(r#"
                const wordSet = new Set(BIP39_WORDS.map(w => w.toLowerCase()));

                document.querySelectorAll('input[id^="word"]').forEach(input => {
                    input.addEventListener('input', function() {
                        const value = this.value.trim().toLowerCase();
                        this.classList.remove('is-valid', 'is-invalid');
                        if (value.length > 0) {
                            if (wordSet.has(value)) {
                                this.classList.add('is-valid');
                            } else {
                                this.classList.add('is-invalid');
                            }
                        }
                    });
                });
            "#))
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
    // Collect and normalize the 12 words into a single space-separated string
    let words = [
        &form.word1,
        &form.word2,
        &form.word3,
        &form.word4,
        &form.word5,
        &form.word6,
        &form.word7,
        &form.word8,
        &form.word9,
        &form.word10,
        &form.word11,
        &form.word12,
    ]
    .iter()
    .map(|w| w.trim())
    .collect::<Vec<_>>()
    .join(" ");

    match state
        .api
        .handle_set_mnemonic_msg(SetMnemonicPayload { words: Some(words) })
        .await
    {
        Ok(()) => Redirect::to(ROOT_ROUTE).into_response(),
        Err(err) => redirect_error(format!("Failed to recover wallet: {err}")).into_response(),
    }
}
