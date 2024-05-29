#![warn(clippy::pedantic)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]

use std::fmt;

use fedimint_core::encoding::{self, Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::CommonModuleInit;
use fedimint_meta_common::MetaCommonInit;
use fedimint_mint_common::MintCommonInit;
use fedimint_wallet_common::WalletCommonInit;

pub fn all_standard_modules() -> fedimint_core::module::registry::ModuleRegistry<
    fedimint_core::core::Decoder,
    fedimint_core::module::registry::DecodingMode,
> {
    ModuleDecoderRegistry::new([
        (0, WalletCommonInit::KIND, WalletCommonInit::decoder()),
        (1, MintCommonInit::KIND, MintCommonInit::decoder()),
        (
            2,
            fedimint_ln_common::LightningCommonInit::KIND,
            fedimint_ln_common::LightningCommonInit::decoder(),
        ),
        (
            2,
            fedimint_lnv2_common::LightningCommonInit::KIND,
            fedimint_lnv2_common::LightningCommonInit::decoder(),
        ),
        (3, MetaCommonInit::KIND, MetaCommonInit::decoder()),
        (4, MetaCommonInit::KIND, MetaCommonInit::decoder()),
    ])
}

pub fn test_decodable<T>(data: &[u8])
where
    T: Decodable + Encodable,
{
    test_decodable_with_decoders::<T>(data, &Default::default());
}

pub fn test_decodable_with_decoders<T>(data: &[u8], decoders: &ModuleDecoderRegistry)
where
    T: Decodable + Encodable,
{
    if let Ok(v) = T::consensus_decode(&mut &data[..], decoders) {
        assert!(data.len() <= encoding::MAX_DECODE_SIZE);

        let encoded_vec = v.consensus_encode_to_vec();
        // helps debugging to have it standalone
        let encoded = encoded_vec.as_slice();

        assert_eq!(&data[..encoded.len()], encoded);
    }
}

/// This can be used to verify correspondence of decoding `data` using
/// `decoders` vs using default empty decoders (no module-specific decoders)
/// with fallback mode on.
pub fn test_decodable_with_decoders_vs_defaults<T>(data: &[u8], decoders: &ModuleDecoderRegistry)
where
    T: Decodable + Encodable + fmt::Debug,
{
    match (
        T::consensus_decode(&mut &data[..], decoders),
        T::consensus_decode(
            &mut &data[..],
            &ModuleDecoderRegistry::default().with_fallback(),
        ),
    ) {
        (Ok(v1), Ok(v2)) => {
            assert!(data.len() <= encoding::MAX_DECODE_SIZE);

            let encoded_vec1 = v1.consensus_encode_to_vec();
            let encoded_vec2 = v2.consensus_encode_to_vec();

            // helps debugging to have it standalone
            let encoded1 = encoded_vec1.as_slice();
            let encoded2 = encoded_vec2.as_slice();

            assert_eq!(&data[..encoded1.len()], encoded1);
            // if both decoders worked, they should re-encode to same value
            assert_eq!(encoded1, encoded2);
        }

        (Err(_e1), Err(_e2)) => {}
        (Ok(ok), Err(e)) => panic!("ok vs err; {ok:?} vs {e:?}"),
        (Err(_ok), Ok(_e)) => {
            // it's OK if real decoders are more strict, defaults with fallback
            // are not doing all the parsing
        }
    }
}
