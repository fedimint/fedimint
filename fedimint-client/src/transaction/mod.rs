mod builder;
mod sm;

use std::any::Any;
use std::fmt::{Debug, Display, Formatter, Pointer, Write};
use std::io::Error;

pub use builder::*;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, DynEncodable, Encodable};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{KeyPair, Message, Secp256k1};
use fedimint_core::task::{MaybeSend, MaybeSync};
use secp256k1_zkp::All;
pub use sm::*;

pub trait SchnorrSigner: Clone + MaybeSend + MaybeSync {
    fn sign_schnorr(&self, secp_ctx: &Secp256k1<All>, msg: &Message) -> Signature;
}

pub struct DynSchnorrSigner(pub Box<dyn ISchnorrSigner>);

impl Clone for DynSchnorrSigner {
    fn clone(&self) -> Self {
        self.0.clone()
    }
}
pub trait ISchnorrSigner: MaybeSend + MaybeSync + Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self) -> DynSchnorrSigner;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynSchnorrSigner) -> bool;
    fn sign_schnorr(&self, secp_ctx: &Secp256k1<All>, msg: &Message) -> Signature;
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct SimpleSchnorrSigner(pub KeyPair);

impl SchnorrSigner for SimpleSchnorrSigner {
    fn sign_schnorr(&self, secp_ctx: &Secp256k1<All>, msg: &Message) -> Signature {
        secp_ctx.sign_schnorr(msg, &self.0)
    }
}

impl From<KeyPair> for SimpleSchnorrSigner {
    fn from(keypair: KeyPair) -> Self {
        Self(keypair)
    }
}

impl Display for SimpleSchnorrSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SimpleSchnorrSigner")
    }
}

impl Debug for DynSchnorrSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Display for DynSchnorrSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl DynEncodable for DynSchnorrSigner {
    fn consensus_encode_dyn(&self, writer: &mut dyn std::io::Write) -> Result<usize, Error> {
        todo!()
    }
}

impl ISchnorrSigner for SimpleSchnorrSigner {
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn clone(&self) -> DynSchnorrSigner {
        DynSchnorrSigner(Box::new(Clone::clone(self)))
    }

    fn dyn_hash(&self) -> u64 {
        use std::hash::Hash;
        let mut s = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut s);
        std::hash::Hasher::finish(&s)
    }

    fn erased_eq_no_instance_id(&self, other: &DynSchnorrSigner) -> bool {
        // todo
        // let other: &Self = other
        //     .as_any()
        //     .downcast_ref()
        //     .expect("Type is ensured in previous step");
        //
        // self == other

        false
    }

    fn sign_schnorr(&self, secp_ctx: &Secp256k1<All>, msg: &Message) -> Signature {
        secp_ctx.sign_schnorr(msg, &self.0)
    }
}

impl IntoDynInstance for SimpleSchnorrSigner {
    type DynType = DynSchnorrSigner;

    fn into_dyn(self, _instance_id: ModuleInstanceId) -> Self::DynType {
        DynSchnorrSigner(Box::new(self))
    }
}
