pub mod assets;

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use fedimint_core::hex::ToHex;
use fedimint_core::secp256k1::rand::{Rng, thread_rng};
use fedimint_gateway_common::GatewayInfo;
use maud::{Markup, html};

use crate::assets::WithStaticRoutesExt;

pub type DynGatewayApi<E> = Arc<dyn IAdminGateway<Error = E> + Send + Sync + 'static>;

#[async_trait]
pub trait IAdminGateway {
    type Error;

    async fn handle_get_info(&self) -> Result<GatewayInfo, Self::Error>;

    async fn get_password_hash(&self) -> String;
}

pub fn common_head(title: &str) -> Markup {
    html! {
        meta charset="utf-8";
        meta name="viewport" content="width=device-width, initial-scale=1.0";
        title { "Gateway Dashboard"}
        link rel="stylesheet" href="/assets/bootstrap.min.css" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous";
        link rel="stylesheet" type="text/css" href="/assets/style.css";
        link rel="icon" type="image/png" href="/assets/logo.png";

        // Note: this needs to be included in the header, so that web-page does not
        // get in a state where htmx is not yet loaded. `deref` helps with blocking the load.
        // Learned the hard way. --dpc
        script defer src="/assets/htmx.org-2.0.4.min.js" {}

        title { (title) }
    }
}

pub fn router<E: Clone + Send + Sync + 'static>(api: DynGatewayApi<E>) -> Router {
    let mut app = Router::new()
        //.route("/ui/login", get(login_form).post(login_submit))
        .with_static_routes();

    app
}

#[derive(Clone)]
pub struct UiState<E> {
    pub(crate) api: DynGatewayApi<E>,
    pub(crate) auth_cookie_name: String,
    pub(crate) auth_cookie_value: String,
}

impl<E> UiState<E> {
    pub fn new(api: DynGatewayApi<E>) -> Self {
        Self {
            api,
            auth_cookie_name: thread_rng().r#gen::<[u8; 4]>().encode_hex(),
            auth_cookie_value: thread_rng().r#gen::<[u8; 32]>().encode_hex(),
        }
    }
}
