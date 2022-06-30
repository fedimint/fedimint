use crate::consensus::MinimintConsensus;
use minimint_api::module::http;
use minimint_api::module::http::{Method, Response};
use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::FederationModule;
use rand::CryptoRng;
use secp256k1_zkp::rand::RngCore;
use serde_json::Value;

pub struct MinimintInterconnect<'a, R: RngCore + CryptoRng> {
    pub minimint: &'a MinimintConsensus<R>,
}

impl<'a, R> ModuleInterconect for MinimintInterconnect<'a, R>
where
    R: RngCore + CryptoRng,
{
    fn call(
        &self,
        module: &'static str,
        path: String,
        method: Method,
        data: Value,
    ) -> http::Result<Response> {
        match module {
            "wallet" => call_internal(&self.minimint.wallet, path, method, data),
            "mint" => call_internal(&self.minimint.mint, path, method, data),
            "ln" => call_internal(&self.minimint.ln, path, method, data),
            _ => Ok(http::StatusCode::NOT_FOUND.into()),
        }
    }
}

fn call_internal<M: FederationModule + 'static>(
    module: &M,
    path: String,
    method: Method,
    data: Value,
) -> http::Result<Response> {
    let endpoint = match module
        .api_endpoints()
        .iter()
        .find(|endpoint| endpoint.method == method && endpoint.path_spec == path)
    {
        Some(e) => e,
        None => return Ok(http::StatusCode::NOT_FOUND.into()),
    };

    // FIXME: implement parameter handling
    assert!(
        endpoint.params.is_empty(),
        "Interconnect does not support parameter parsing yet!"
    );

    (endpoint.handler)(module, Default::default(), data)
}
