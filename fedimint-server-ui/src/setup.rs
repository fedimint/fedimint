use axum::Router;
use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use fedimint_core::module::ApiAuth;
use fedimint_server_core::setup_ui::DynSetupApi;
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;

use crate::assets::WithStaticRoutesExt as _;
use crate::{
    AuthState, LoginInput, check_auth, common_head, login_form_response, login_submit_response,
};

#[derive(Debug, Deserialize)]
pub(crate) struct SetupInput {
    pub password: String,
    pub name: String,
    #[serde(default)]
    pub is_lead: bool,
    pub federation_name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PeerInfoInput {
    pub peer_info: String,
}

pub fn setup_layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (common_head(title))
            }
            body {
                div class="container" {
                    div class="row justify-content-center" {
                        div class="col-md-8 col-lg-5 narrow-container" {
                            header class="text-center" {
                                h1 class="header-title" { "Fedimint Guardian UI" }
                            }

                            div class="card" {
                                div class="card-body" {
                                    (content)
                                }
                            }
                        }
                    }
                }
                script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
            }
        }
    }
}

// GET handler for the /setup route (display the setup form)
async fn setup_form(State(state): State<AuthState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_some() {
        return Redirect::to("/federation-setup").into_response();
    }

    let content = html! {
        form method="post" action="/" {
            style {
                r#"
                .toggle-content {
                    display: none;
                }
                
                .toggle-control:checked ~ .toggle-content {
                    display: block;
                }
                "#
            }

            div class="form-group mb-4" {
                input type="text" class="form-control" id="name" name="name" placeholder="Guardian name" required;
            }

            div class="form-group mb-4" {
                input type="password" class="form-control" id="password" name="password" placeholder="Secure password" required;
            }

            div class="form-group mb-4" {
                div class="form-check" {
                    input type="checkbox" class="form-check-input toggle-control" id="is_lead" name="is_lead" value="true";

                    label class="form-check-label" for="is_lead" {
                        "I am the guardian setting up the global configuration for this federation."
                    }

                    div class="toggle-content mt-3" {
                        input type="text" class="form-control" id="federation_name" name="federation_name" placeholder="Federation name";
                    }
                }
            }

            div class="button-container" {
                button type="submit" class="btn btn-primary setup-btn" { "Set Parameters" }
            }
        }
    };

    Html(setup_layout("Setup Fedimint Guardian", content).into_string()).into_response()
}

// POST handler for the /setup route (process the password setup form)
async fn setup_submit(
    State(state): State<AuthState<DynSetupApi>>,
    Form(input): Form<SetupInput>,
) -> impl IntoResponse {
    // Only use federation_name if is_lead is true
    let federation_name = if input.is_lead {
        Some(input.federation_name)
    } else {
        None
    };

    match state
        .api
        .set_local_parameters(ApiAuth(input.password), input.name, federation_name)
        .await
    {
        Ok(_) => Redirect::to("/login").into_response(),
        Err(e) => {
            let content = html! {
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href="/" class="btn btn-primary setup-btn" { "Return to Setup" }
                }
            };

            Html(setup_layout("Setup Error", content).into_string()).into_response()
        }
    }
}

// GET handler for the /login route (display the login form)
async fn login_form(State(state): State<AuthState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_none() {
        return Redirect::to("/").into_response();
    }

    login_form_response().into_response()
}

// POST handler for the /login route (authenticate and set session cookie)
async fn login_submit(
    State(state): State<AuthState<DynSetupApi>>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    let auth = match state.api.auth().await {
        Some(auth) => auth,
        None => return Redirect::to("/").into_response(),
    };

    login_submit_response(
        auth,
        state.auth_cookie_name,
        state.auth_cookie_value,
        jar,
        input,
    )
    .into_response()
}

// GET handler for the /federation-setup route (main federation management page)
async fn federation_setup(
    State(state): State<AuthState<DynSetupApi>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    let our_connection_info = state
        .api
        .setup_code()
        .await
        .expect("Successful authentication ensures that the local parameters have been set");

    let connected_peers = state.api.connected_peers().await;

    let content = html! {
        section class="mb-4" {
            div class="alert alert-info mb-3" {
                (our_connection_info)
            }

            div class="text-center" {
                button type="button" class="btn btn-outline-primary setup-btn"
                    onclick=(format!("navigator.clipboard.writeText('{}')", our_connection_info)) {
                    "Copy to Clipboard"
                }
            }
        }

        hr class="my-4" {}

        section class="mb-4" {
            ul class="list-group mb-4" {
                @for peer in connected_peers {
                    li class="list-group-item" { (peer) }
                }
            }

            form method="post" action="/add-connection-info" {
                div class="mb-3" {
                    input type="text" class="form-control mb-2" id="peer_info" name="peer_info"
                        placeholder="Paste setup code from fellow guardian" required;
                }

                div class="row mt-3" {
                    div class="col-6" {
                        button type="button" class="btn btn-warning w-100" onclick="document.getElementById('reset-form').submit();" {
                            "Reset Guardians"
                        }
                    }

                    div class="col-6" {
                        button type="submit" class="btn btn-primary w-100" { "Add Guardian" }
                    }
                }
            }

            form id="reset-form" method="post" action="/reset-connection-info" class="d-none" {}
        }

        hr class="my-4" {}

        section class="mb-4" {
            div class="alert alert-warning mb-4" {
                "Make sure all information is correct and every guardian is ready before launching the federation. This process cannot be reversed once started."
            }

            div class="text-center" {
                form method="post" action="/start-dkg" {
                    button type="submit" class="btn btn-warning setup-btn" {
                        "🚀 Launch Federation"
                    }
                }
            }
        }
    };

    Html(setup_layout("Federation Setup", content).into_string()).into_response()
}

// POST handler for adding peer connection info
async fn add_peer_handler(
    State(state): State<AuthState<DynSetupApi>>,
    jar: CookieJar,
    Form(input): Form<PeerInfoInput>,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    match state.api.add_peer_setup_code(input.peer_info).await {
        Ok(..) => Redirect::to("/federation-setup").into_response(),
        Err(e) => {
            let content = html! {
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href="/federation-setup" class="btn btn-primary setup-btn" { "Return to Setup" }
                }
            };

            Html(setup_layout("Error", content).into_string()).into_response()
        }
    }
}

// POST handler for starting the DKG process
async fn start_dkg_handler(
    State(state): State<AuthState<DynSetupApi>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    match state.api.start_dkg().await {
        Ok(()) => {
            // Show simple DKG success page
            let content = html! {
                div class="alert alert-success my-4" {
                    "The distributed key generation has been started successfully. You can monitor the progress in your server logs."
                }
                p class="text-center" {
                    "Once the distributed key generation completes, the Guardian Dashboard will become available at the root URL."
                }
                div class="button-container mt-4" {
                    a href="/" class="btn btn-primary setup-btn" {
                        "Go to Dashboard"
                    }
                }
            };

            Html(setup_layout("DKG Started", content).into_string()).into_response()
        }
        Err(e) => {
            let content = html! {
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href="/federation-setup" class="btn btn-primary setup-btn" { "Return to Setup" }
                }
            };

            Html(setup_layout("Error", content).into_string()).into_response()
        }
    }
}

// POST handler for resetting peer connection info
async fn reset_peers_handler(
    State(state): State<AuthState<DynSetupApi>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    state.api.reset_setup_codes().await;

    Redirect::to("/federation-setup").into_response()
}

pub fn router(api: DynSetupApi) -> Router {
    Router::new()
        .route("/", get(setup_form).post(setup_submit))
        .route("/login", get(login_form).post(login_submit))
        .route("/federation-setup", get(federation_setup))
        .route("/add-connection-info", post(add_peer_handler))
        .route("/reset-connection-info", post(reset_peers_handler))
        .route("/start-dkg", post(start_dkg_handler))
        .with_static_routes()
        .with_state(AuthState::new(api))
}
