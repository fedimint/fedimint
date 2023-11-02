use std::collections::HashMap;

use fedimint_core::api::{FederationApiExt, FederationResult, IModuleFederationApi, JsonRpcResult};
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, PeerId};

use crate::UnsignedEvent;

#[apply(async_trait_maybe_send!)]
pub trait NostrmintFederationApi {
    async fn request_sign_event(
        &self,
        unsigned_event: UnsignedEvent,
        peer_id: PeerId,
        auth: ApiAuth,
    ) -> JsonRpcResult<()>;
    async fn get_npub(&self) -> FederationResult<nostr_sdk::key::XOnlyPublicKey>;
    async fn list_note_requests(&self)
        -> FederationResult<HashMap<String, (UnsignedEvent, usize)>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> NostrmintFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn request_sign_event(
        &self,
        unsigned_event: UnsignedEvent,
        peer_id: PeerId,
        auth: ApiAuth,
    ) -> JsonRpcResult<()> {
        self.request_single_peer(
            None,
            "sign_event".to_string(),
            ApiRequestErased::new(unsigned_event).with_auth(auth),
            peer_id,
        )
        .await?;
        Ok(())
    }

    async fn get_npub(&self) -> FederationResult<nostr_sdk::key::XOnlyPublicKey> {
        self.request_current_consensus("npub".to_string(), ApiRequestErased::default())
            .await
    }

    async fn list_note_requests(
        &self,
    ) -> FederationResult<HashMap<String, (UnsignedEvent, usize)>> {
        self.request_current_consensus(
            "list_note_requests".to_string(),
            ApiRequestErased::default(),
        )
        .await
    }
}
