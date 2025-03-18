use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use axum::Router;
use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use fedimint_core::module::ApiAuth;
use fedimint_core::task::TaskHandle;
use fedimint_server_core::setup_ui::DynSetupApi;
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;
use tokio::net::TcpListener;

use crate::{LoginInput, check_auth, common_styles, login_form_response, login_submit_response};

#[derive(Debug, Deserialize)]
pub(crate) struct SetupInput {
    pub password: String,
    pub name: String,
    pub federation_name: Option<String>,
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
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { (title) }
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous";
                style {
                    (common_styles())
                }
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
async fn setup_form(State(config_api): State<DynSetupApi>) -> impl IntoResponse {
    if config_api.our_connection_info().await.is_some() {
        return Redirect::to("/federation-setup").into_response();
    }

    let content = html! {
        form method="post" action="/" {
            div class="form-group mb-4" {
                label for="name" class="form-label" { "Guardian Name" }
                input type="text" class="form-control" id="name" name="name"
                     placeholder="Your guardian name"
                     required;
            }

            div class="form-group mb-4" {
                label for="federation_name" class="form-label" { "Federation Name (optional)" }
                input type="text" class="form-control" id="federation_name" name="federation_name" placeholder="Federation name";
                div class="field-description" {
                    "The federation name needs to be set by exactly one guardian."
                }
            }

            div class="form-group mb-4" {
                label for="password" class="form-label" { "Guardian Password" }
                input type="password" class="form-control" id="password" name="password" placeholder="Secure password" required;
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
    State(config_api): State<DynSetupApi>,
    Form(input): Form<SetupInput>,
) -> impl IntoResponse {
    match config_api
        .set_local_parameters(
            ApiAuth(input.password.clone()),
            input.name,
            input.federation_name,
        )
        .await
    {
        Ok(_) => Redirect::to("/login").into_response(),
        Err(e) => {
            let content = html! {
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href="/" class="btn btn-primary setup-btn" { "Try Again" }
                }
            };

            Html(setup_layout("Setup Error", content).into_string()).into_response()
        }
    }
}

// GET handler for the /login route (display the login form)
async fn login_form(State(config_api): State<DynSetupApi>) -> impl IntoResponse {
    if config_api.our_connection_info().await.is_none() {
        return Redirect::to("/").into_response();
    }

    login_form_response().into_response()
}

// POST handler for the /login route (authenticate and set session cookie)
async fn login_submit(
    State(config_api): State<DynSetupApi>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    let auth = match config_api.auth().await {
        Some(auth) => auth,
        None => return Redirect::to("/").into_response(),
    };

    login_submit_response(auth, jar, input).into_response()
}

// GET handler for the /federation-setup route (main federation management page)
async fn federation_setup(
    State(config_api): State<DynSetupApi>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = match config_api.auth().await {
        Some(auth) => auth,
        None => return Redirect::to("/").into_response(),
    };

    if !check_auth(auth, &jar).await {
        return Redirect::to("/login").into_response();
    }

    let our_connection_info = config_api
        .our_connection_info()
        .await
        .expect("Successful authentication ensures that the local parameters have been set");

    let connected_peers = config_api.connected_peers().await;

    let content = html! {
        section class="mb-4" {
            div class="alert alert-info mb-3" {
                "Share this code with other guardians:"
            }

            div class="connection-code card p-3 mb-3" {
                code { (our_connection_info) }
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
            h4 class="mb-3" { "Connect with Other Guardians" }

            @if !connected_peers.is_empty() {
                div class="text-center" {
                    form method="post" action="/reset-connection-info" {
                        button type="submit" class="btn btn-warning setup-btn" {
                            "Reset Guardian Connections"
                        }
                    }
                }

                ul class="list-group mb-4" {
                    @for peer in connected_peers {
                        li class="list-group-item" { (peer) }
                    }
                }
            }

            form method="post" action="/add-connection-info" {
                div class="mb-3" {
                    input type="text" class="form-control mb-2" id="peer_info" name="peer_info"
                        placeholder="Paste connection info from another guardian" required;
                }

                div class="text-center" {
                    button type="submit" class="btn btn-primary setup-btn" { "Add Guardian" }
                }
            }
        }

        hr class="my-4" {}

        section class="mb-4" {
            h4 class="mb-3" { "Launch Federation" }

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
    State(config_api): State<DynSetupApi>,
    jar: CookieJar,
    Form(input): Form<PeerInfoInput>,
) -> impl IntoResponse {
    let auth = match config_api.auth().await {
        Some(auth) => auth,
        None => return Redirect::to("/").into_response(),
    };

    if !check_auth(auth, &jar).await {
        return Redirect::to("/login").into_response();
    }

    match config_api.add_peer_connection_info(input.peer_info).await {
        Ok(..) => Redirect::to("/federation-setup").into_response(),
        Err(e) => {
            let content = html! {
                h2 class="mb-4 text-center" { "Error Adding Guardian" }
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href="/federation-setup" class="btn btn-primary setup-btn" { "Back to Setup" }
                }
            };

            Html(setup_layout("Error", content).into_string()).into_response()
        }
    }
}

// POST handler for starting the DKG process
async fn start_dkg_handler(
    State(config_api): State<DynSetupApi>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = match config_api.auth().await {
        Some(auth) => auth,
        None => return Redirect::to("/").into_response(),
    };

    if !check_auth(auth, &jar).await {
        return Redirect::to("/login").into_response();
    }

    match config_api.start_dkg().await {
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
                        "Go to Guardian Dashboard"
                    }
                }
            };

            Html(setup_layout("DKG Started", content).into_string()).into_response()
        }
        Err(e) => {
            let content = html! {
                h2 class="mb-4 text-center" { "Error Starting Federation" }
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href="/federation-setup" class="btn btn-primary setup-btn" { "Back to Setup" }
                }
            };

            Html(setup_layout("Error", content).into_string()).into_response()
        }
    }
}

// POST handler for resetting peer connection info
async fn reset_peers_handler(
    State(config_api): State<DynSetupApi>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = match config_api.auth().await {
        Some(auth) => auth,
        None => return Redirect::to("/").into_response(),
    };

    if !check_auth(auth, &jar).await {
        return Redirect::to("/login").into_response();
    }

    config_api.reset_connection_info().await;

    Redirect::to("/federation-setup").into_response()
}

pub fn start(
    config_api: DynSetupApi,
    ui_bind: SocketAddr,
    task_handle: TaskHandle,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let app = Router::new()
        .route("/", get(setup_form).post(setup_submit))
        .route("/login", get(login_form).post(login_submit))
        .route("/federation-setup", get(federation_setup))
        .route("/add-connection-info", post(add_peer_handler))
        .route("/reset-connection-info", post(reset_peers_handler))
        .route("/start-dkg", post(start_dkg_handler))
        .with_state(config_api);

    Box::pin(async move {
        let listener = TcpListener::bind(ui_bind)
            .await
            .expect("Failed to bind setup UI");

        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(task_handle.make_shutdown_rx())
            .await
            .expect("Failed to serve setup UI");
    })
}
