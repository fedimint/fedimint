use std::{ffi, iter};

use clap::Parser;
use fedimint_core::api::FederationApiExt;
use fedimint_core::endpoint_constants::{
    ADD_GATEWAY_ENDPOINT, GATEWAYS_ENDPOINT, REMOVE_GATEWAY_ENDPOINT,
};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::util::SafeUrl;
use serde::Serialize;
use serde_json::Value;

use crate::LightningClientModule;

#[derive(Parser, Serialize)]
enum Opts {
    /// Add a vetted gateway
    Add { gateway: SafeUrl },
    /// Remove a vetted gateway
    Remove { gateway: SafeUrl },
    /// List our own vetted gateways
    List,
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2")).chain(args.iter()));

    match opts {
        Opts::Add { gateway } => {
            let auth = lightning
                .admin_auth
                .clone()
                .ok_or(anyhow::anyhow!("Admin auth not set"))?;

            let is_new_entry = lightning
                .module_api
                .request_admin(ADD_GATEWAY_ENDPOINT, ApiRequestErased::new(gateway), auth)
                .await?;

            Ok(Value::Bool(is_new_entry))
        }
        Opts::Remove { gateway } => {
            let auth = lightning
                .admin_auth
                .clone()
                .ok_or(anyhow::anyhow!("Admin auth not set"))?;

            let entry_existed = lightning
                .module_api
                .request_admin(
                    REMOVE_GATEWAY_ENDPOINT,
                    ApiRequestErased::new(gateway),
                    auth,
                )
                .await?;

            Ok(Value::Bool(entry_existed))
        }
        Opts::List => {
            let gateways = lightning
                .module_api
                .request_admin_no_auth::<Vec<SafeUrl>>(
                    GATEWAYS_ENDPOINT,
                    ApiRequestErased::default(),
                )
                .await?
                .iter()
                .map(|gateway| Value::String(gateway.to_string()))
                .collect::<Vec<Value>>();

            Ok(Value::Array(gateways))
        }
    }
}
