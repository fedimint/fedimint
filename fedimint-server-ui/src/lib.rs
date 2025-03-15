use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use fedimint_core::module::ApiAuth;
use fedimint_server_core::config_gen::ConfigGenApiInterface;
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Debug, Deserialize)]
struct SetupInput {
    password: String,
    name: String,
    federation_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginInput {
    password: String,
}

#[derive(Debug, Deserialize)]
struct PeerInfoInput {
    peer_info: String,
}

fn base_layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { (title) }
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous";
                style {
                    r#"
                    body {
                        background-color: #f8f9fa;
                        padding-top: 2rem;
                        padding-bottom: 2rem;
                    }
                    
                    .header-title {
                        color: #0d6efd;
                        margin-bottom: 2rem;
                    }
                    
                    .card {
                        border: none;
                        box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
                        border-radius: 0.5rem;
                        margin-bottom: 2rem;
                    }
                    
                    .card-header {
                        background-color: #fff;
                        border-bottom: 1px solid rgba(0, 0, 0, 0.125);
                        padding: 1.5rem;
                    }
                    
                    .card-body {
                        padding: 2rem;
                    }
                    
                    .form-label {
                        font-weight: 500;
                    }
                    
                    .field-description {
                        color: #6c757d;
                        font-size: 0.875rem;
                        margin-top: 0.25rem;
                    }
                    
                    .form-control {
                        max-width: 100%;
                    }
                    
                    .form-group {
                        margin: 0 auto;
                        max-width: 400px;
                    }
                    
                    .btn {
                        min-width: 200px; /* Make all buttons wider */
                        padding: 0.6rem 2rem;
                    }
                    
                    .button-container {
                        text-align: center;
                        margin-top: 2rem;
                    }
                    
                    /* For the dashboard buttons that appear side by side */
                    .protected-area .button-container .btn {
                        min-width: 160px;
                        margin-bottom: 0.5rem;
                    }
                    
                    .error-message {
                        color: #dc3545;
                        margin-top: 1rem;
                        font-weight: 500;
                    }
                    
                    .alert-info {
                        background-color: #e8f4f8;
                        border-color: #bee5eb;
                    }
                    
                    .connection-code {
                        background-color: #f8f9fa;
                        border: 1px solid #dee2e6;
                        border-radius: 0.25rem;
                        padding: 1rem;
                        overflow-x: auto;
                        font-family: monospace;
                        margin-bottom: 1rem;
                        word-break: break-all;
                        color: #000; /* Set text color explicitly to black */
                    }
                    
                    /* Explicitly set code element color */
                    .connection-code code {
                        color: #000 !important; /* Force black color with !important */
                    }
                    
                    /* Consistent button width for the setup UI */
                    .setup-btn {
                        width: 75%;
                        max-width: 300px;
                        margin: 0 auto;
                    }
                    
                    @media (min-width: 992px) {
                        .narrow-container {
                            max-width: 500px;
                        }
                    }
                    "#
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
async fn setup_form<T: ConfigGenApiInterface>(
    State(config_api): State<Arc<T>>,
) -> impl IntoResponse {
    if config_api.our_connection_info().await.is_some() {
        return Redirect::to("/federation-setup").into_response();
    }

    let content = html! {
        h2 class="mb-4 text-center" { "Set Guardian Parameters" }
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

    Html(base_layout("Setup Fedimint Guardian", content).into_string()).into_response()
}

// POST handler for the /setup route (process the password setup form)
async fn setup_submit<T: ConfigGenApiInterface>(
    State(config_api): State<Arc<T>>,
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
                h2 class="mb-4 text-center" { "Setup Failed" }
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href="/" class="btn btn-primary setup-btn" { "Try Again" }
                }
            };

            Html(base_layout("Setup Error", content).into_string()).into_response()
        }
    }
}

// GET handler for the /login route (display the login form)
async fn login_form<T: ConfigGenApiInterface>(
    State(config_api): State<Arc<T>>,
) -> impl IntoResponse {
    if config_api.our_connection_info().await.is_none() {
        return Redirect::to("/").into_response();
    }

    let content = html! {
        h2 class="mb-4 text-center" { "Guardian Login" }
        form method="post" action="/login" {
            div class="form-group mb-4" {
                label for="password" class="form-label" { "Enter your guardian password" }
                input type="password" class="form-control" id="password" name="password" placeholder="Your password" required;
            }
            div class="button-container" {
                button type="submit" class="btn btn-primary setup-btn" { "Log In" }
            }
        }
    };

    Html(base_layout("Fedimint Guardian Login", content).into_string()).into_response()
}

// POST handler for the /login route (authenticate and set session cookie)
async fn login_submit<T: ConfigGenApiInterface>(
    State(config_api): State<Arc<T>>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    let auth = match config_api.auth().await {
        Some(auth) => auth,
        None => return Redirect::to("/").into_response(),
    };

    if auth.0 == input.password {
        let mut cookie = Cookie::new("guardian_api_auth", input.password);
        cookie.set_http_only(true);
        cookie.set_same_site(Some(SameSite::Lax));

        return (jar.add(cookie), Redirect::to("/federation-setup")).into_response();
    }

    let content = html! {
        h2 class="mb-4 text-center" { "Guardian Login" }
        div class="alert alert-danger" role="alert" {
            "Invalid password. Please try again."
        }
        form method="post" action="/login" {
            div class="form-group mb-4" {
                label for="password" class="form-label" { "Enter your guardian password" }
                input type="password" class="form-control" id="password" name="password" placeholder="Your password" required;
            }
            div class="button-container" {
                button type="submit" class="btn btn-primary setup-btn" { "Log In" }
            }
        }
    };

    Html(base_layout("Login Failed", content).into_string()).into_response()
}

async fn check_auth<T: ConfigGenApiInterface>(
    config_api: &Arc<T>,
    jar: &CookieJar,
) -> Option<Redirect> {
    let session_password = match jar.get("guardian_api_auth") {
        Some(cookie) => cookie.value().to_string(),
        None => return Some(Redirect::to("/login")),
    };

    let auth = match config_api.auth().await {
        Some(auth) => auth,
        None => return Some(Redirect::to("/")),
    };

    if auth.0 != session_password {
        return Some(Redirect::to("/login"));
    }

    None
}

// GET handler for the /federation-setup route (main federation management page)
async fn federation_setup<T: ConfigGenApiInterface>(
    State(config_api): State<Arc<T>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if let Some(redirect) = check_auth(&config_api, &jar).await {
        return redirect.into_response();
    }

    let our_connection_info = config_api
        .our_connection_info()
        .await
        .expect("Successful authentication ensures that the local parameters have been set");

    let connected_peers = config_api.connected_peers().await;

    let content = html! {
        h2 class="text-center mb-4" { "Federation Setup" }

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
                div class="mb-4" {
                    ul class="list-group mb-4" {
                        @for peer in connected_peers {
                            li class="list-group-item" { (peer) }
                        }

                        div class="text-center" {
                            form method="post" action="/reset-connection-info" {
                                button type="submit" class="btn btn-warning setup-btn" {
                                    "Reset Guardian Connections"
                                }
                            }
                        }
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

    Html(base_layout("Federation Setup", content).into_string()).into_response()
}

// POST handler for adding peer connection info
async fn add_peer_handler<T: ConfigGenApiInterface>(
    State(config_api): State<Arc<T>>,
    jar: CookieJar,
    Form(input): Form<PeerInfoInput>,
) -> impl IntoResponse {
    if let Some(redirect) = check_auth(&config_api, &jar).await {
        return redirect.into_response();
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

            Html(base_layout("Error", content).into_string()).into_response()
        }
    }
}

// POST handler for starting the DKG process
async fn start_dkg_handler<T: ConfigGenApiInterface>(
    State(config_api): State<Arc<T>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if let Some(redirect) = check_auth(&config_api, &jar).await {
        return redirect.into_response();
    }

    match config_api.start_dkg().await {
        Ok(()) => {
            // Show simple DKG success page
            let content = html! {
                h2 class="text-center" { "Federation Initialization Started" }
                div class="alert alert-success my-4" {
                    "The distributed key generation has been started successfully."
                }
                p class="text-center" {
                    "The federation is now being initialized. You can monitor the progress in your server logs."
                }
                p class="text-center mt-3" {
                    "This interface will be available until the DKG process completes."
                }
            };

            Html(base_layout("DKG Started", content).into_string()).into_response()
        }
        Err(e) => {
            let content = html! {
                h2 class="mb-4 text-center" { "Error Starting Federation" }
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href="/federation-setup" class="btn btn-primary setup-btn" { "Back to Setup" }
                }
            };

            Html(base_layout("Error", content).into_string()).into_response()
        }
    }
}

// POST handler for resetting peer connection info
async fn reset_peers_handler<T: ConfigGenApiInterface>(
    State(config_api): State<Arc<T>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if let Some(redirect) = check_auth(&config_api, &jar).await {
        return redirect.into_response();
    }

    config_api.reset_connection_info().await;

    Redirect::to("/federation-setup").into_response()
}

/// Main function to start the web UI with any implementation of ConfigGenApiInterface
pub async fn start_web_ui<T: ConfigGenApiInterface>(config_api: T, ui_bind: SocketAddr) {
    let app = Router::new()
        .route("/", get(setup_form::<T>).post(setup_submit::<T>))
        .route("/login", get(login_form::<T>).post(login_submit::<T>))
        .route("/federation-setup", get(federation_setup::<T>))
        .route("/add-connection-info", post(add_peer_handler::<T>))
        .route("/reset-connection-info", post(reset_peers_handler::<T>))
        .route("/start-dkg", post(start_dkg_handler::<T>))
        .with_state(Arc::new(config_api));

    println!("Federation setup UI running at http://{ui_bind} 🚀");

    let listener = TcpListener::bind(ui_bind)
        .await
        .expect("Failed to bind to port");

    axum::serve(listener, app.into_make_service())
        .await
        .expect("Failed to start server");
}
