use async_trait::async_trait;
use hbbft::{NodeIdT, Target};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod api;
pub mod connect;
pub mod framed;

#[async_trait]
pub trait PeerConnections<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send,
{
    type Id: NodeIdT;

    async fn send(&mut self, target: Target<Self::Id>, msg: T);
    async fn receive(&mut self) -> (Self::Id, T);
}
