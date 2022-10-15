#![cfg_attr(feature = "diagnostics", feature(proc_macro_diagnostic))]

use heck::ToSnakeCase;
use proc_macro::{self, TokenStream};
use quote::{format_ident, quote};
use syn::{parse_macro_input, Data, DataEnum, DataStruct, DeriveInput, Index};

#[proc_macro_derive(UnzipConsensus)]
pub fn derive_unzip_consensus(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);

    let variants = match data {
        syn::Data::Enum(DataEnum { variants, .. }) => variants
            .iter()
            .map(|variant| {
                let fields = variant.fields.iter().collect::<Vec<_>>();

                if fields.len() != 1 || fields[0].ident.is_some() {
                    return Err("UnzipConsensus only supports 1-tuple variants");
                }

                Ok((variant.ident.clone(), fields[0].ty.clone()))
            })
            .collect::<std::result::Result<Vec<_>, _>>(),
        _ => Err("UnzipConsensus can only be derived for enums"),
    };

    #[allow(unreachable_code)]
    let variants = match variants {
        Ok(variants) => variants,
        Err(e) => {
            #[cfg(feature = "diagnostics")]
            ident.span().unstable().error(e).emit();
            #[cfg(not(feature = "diagnostics"))]
            panic!("Error: {}", e);
            return TokenStream::new();
        }
    };

    let unzip_struct_ident = format_ident!("Unzip{}", ident);
    let (unzip_s_ident, unzip_s_type): (Vec<_>, Vec<_>) = variants
        .iter()
        .map(|(ident, ty)| (format_ident!("{}", ident.to_string().to_snake_case()), ty))
        .unzip();
    let unzip_e_ident = variants.iter().map(|(ident, _)| ident).collect::<Vec<_>>();
    let unzip_fn_ident = format_ident!("unzip_{}", ident.to_string().to_snake_case());
    let unzip_trait_ident = format_ident!("IterUnzip{}", ident);

    let output = quote! {
        pub trait #unzip_trait_ident {
            fn #unzip_fn_ident(self) -> #unzip_struct_ident;
        }

        pub struct #unzip_struct_ident {
            #(pub #unzip_s_ident: Vec<(PeerId, #unzip_s_type)>),*
        }

        impl<I> #unzip_trait_ident for I
        where
            I: Iterator<Item = (PeerId, #ident)>,
        {
            fn #unzip_fn_ident(mut self) -> #unzip_struct_ident {
                #(let mut #unzip_s_ident = Vec::new();)*

                while let Some((peer, consensus_item)) = self.next() {
                    match consensus_item {
                        #(#ident::#unzip_e_ident(item) => {
                            #unzip_s_ident.push((peer, item));
                        })*
                    }
                }

                #unzip_struct_ident {
                    #(#unzip_s_ident),*
                }
            }
        }

    };

    output.into()
}

#[proc_macro_derive(Encodable)]
pub fn derive_encodable(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);

    let output = match data {
        Data::Struct(DataStruct { fields, .. }) => {
            if fields.iter().any(|field| field.ident.is_none()) {
                // Tuple struct
                let field_names = fields
                    .iter()
                    .enumerate()
                    .map(|(idx, _)| Index::from(idx))
                    .collect::<Vec<_>>();
                quote! {
                    impl ::fedimint_api::encoding::Encodable for #ident {
                        fn consensus_encode<W: std::io::Write>(&self, mut writer: &mut W) -> std::result::Result<usize, std::io::Error> {
                            let mut len = 0;
                            #(len += ::fedimint_api::encoding::Encodable::consensus_encode(&self.#field_names, writer)?;)*
                            Ok(len)
                        }
                    }
                }
            } else {
                // Tuple struct
                let field_names = fields
                    .iter()
                    .map(|field| field.ident.clone().unwrap())
                    .collect::<Vec<_>>();
                quote! {
                    impl ::fedimint_api::encoding::Encodable for #ident {
                        fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::result::Result<usize, std::io::Error> {
                            let mut len = 0;
                            #(len += ::fedimint_api::encoding::Encodable::consensus_encode(&self.#field_names, writer)?;)*
                            Ok(len)
                        }
                    }
                }
            }
        }
        syn::Data::Enum(DataEnum { variants, .. }) => {
            let match_arms = variants.iter().enumerate().map(|(variant_idx, variant)| {
                let variant_ident = variant.ident.clone();

                if variant.fields.iter().any(|field| field.ident.is_none()) {
                    let variant_fields = variant
                        .fields
                        .iter()
                        .enumerate()
                        .map(|(idx, _)| format_ident!("bound_{}", idx))
                        .collect::<Vec<_>>();
                    quote! {
                        #ident::#variant_ident(#(#variant_fields,)*) => {
                            len += ::fedimint_api::encoding::Encodable::consensus_encode(&(#variant_idx as u64), writer)?;
                            #(len += ::fedimint_api::encoding::Encodable::consensus_encode(#variant_fields, writer)?;)*
                        }
                    }
                } else {
                    let variant_fields = variant
                        .fields
                        .iter()
                        .map(|field| field.ident.clone().unwrap())
                        .collect::<Vec<_>>();
                    quote! {
                        #ident::#variant_ident { #(#variant_fields,)*} => {
                            len += ::fedimint_api::encoding::Encodable::consensus_encode(&(#variant_idx as u64), writer)?;
                            #(len += ::fedimint_api::encoding::Encodable::consensus_encode(#variant_fields, writer)?;)*
                        }
                    }
                }
            });

            quote! {
                impl Encodable for #ident {
                    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::result::Result<usize, std::io::Error> {
                        let mut len = 0;
                        match self {
                            #(#match_arms)*
                        }
                        Ok(len)
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        syn::Data::Union(_) => {
            #[cfg(feature = "diagnostics")]
            ident
                .span()
                .unstable()
                .error("Encodable can't be derived for unions")
                .emit();
            #[cfg(not(feature = "diagnostics"))]
            panic!("Error: Encodable can't be derived for unions");
            return TokenStream::new();
        }
    };

    output.into()
}

#[proc_macro_derive(Decodable)]
pub fn derive_decodable(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);

    let output = match data {
        Data::Struct(DataStruct { fields, .. }) => {
            if fields.iter().any(|field| field.ident.is_none()) {
                // Tuple struct
                let field_names = fields
                    .iter()
                    .enumerate()
                    .map(|(idx, _)| format_ident!("field_{}", idx))
                    .collect::<Vec<_>>();
                quote! {
                    impl<M> ::fedimint_api::encoding::Decodable<M> for #ident {
                        fn consensus_decode<D: std::io::Read>(d: &mut D, modules: &::fedimint_api::encoding::ModuleRegistry<M>) -> std::result::Result<Self, ::fedimint_api::encoding::DecodeError> {
                            let mut len = 0;
                            #(let #field_names = ::fedimint_api::encoding::Decodable::consensus_decode(d, modules)?;)*
                            Ok(#ident(#(#field_names,)*))
                        }
                    }
                }
            } else {
                // Tuple struct
                let field_names = fields
                    .iter()
                    .map(|field| field.ident.clone().unwrap())
                    .collect::<Vec<_>>();
                quote! {
                    impl<M> ::fedimint_api::encoding::Decodable<M> for #ident {
                        fn consensus_decode<D: std::io::Read>(d: &mut D, modules: &::fedimint_api::encoding::ModuleRegistry<M>) -> std::result::Result<Self, ::fedimint_api::encoding::DecodeError> {
                            let mut len = 0;
                            #(let #field_names = ::fedimint_api::encoding::Decodable::consensus_decode(d, modules)?;)*
                            Ok(#ident{
                                #(#field_names,)*
                            })
                        }
                    }
                }
            }
        }
        syn::Data::Enum(DataEnum { variants, .. }) => {
            let match_arms = variants.iter().enumerate().map(|(variant_idx, variant)| {
                let variant_ident = variant.ident.clone();

                if variant.fields.iter().any(|field| field.ident.is_none()) {
                    let variant_fields = variant
                        .fields
                        .iter()
                        .enumerate()
                        .map(|(idx, _)| format_ident!("bound_{}", idx))
                        .collect::<Vec<_>>();
                    quote! {
                        #variant_idx => {
                            #(let #variant_fields = ::fedimint_api::encoding::Decodable::consensus_decode(d, modules)?;)*
                            #ident::#variant_ident(#(#variant_fields,)*)
                        }
                    }
                } else {
                    let variant_fields = variant
                        .fields
                        .iter()
                        .map(|field| field.ident.clone().unwrap())
                        .collect::<Vec<_>>();
                    quote! {
                        #variant_idx => {
                            #(let #variant_fields = ::fedimint_api::encoding::Decodable::consensus_decode(d, modules)?;)*
                            #ident::#variant_ident{
                                #(#variant_fields,)*
                            }
                        }
                    }
                }
            });

            quote! {
                impl<M> ::fedimint_api::encoding::Decodable<M> for #ident {
                    fn consensus_decode<D: std::io::Read>(d: &mut D, modules: &::fedimint_api::encoding::ModuleRegistry<M>) -> std::result::Result<Self, ::fedimint_api::encoding::DecodeError> {
                        let variant = <u64 as ::fedimint_api::encoding::Decodable<M>>::consensus_decode(d, modules)? as usize;
                        let decoded = match variant {
                            #(#match_arms)*
                            _ => {
                                return Err(::fedimint_api::encoding::DecodeError::from_str("invalid enum variant"));
                            }
                        };
                        Ok(decoded)
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        syn::Data::Union(_) => {
            #[cfg(feature = "diagnostics")]
            ident
                .span()
                .unstable()
                .error("Encodable can't be derived for unions")
                .emit();
            #[cfg(not(feature = "diagnostics"))]
            panic!("Error: Encodable can't be derived for unions");

            return TokenStream::new();
        }
    };

    output.into()
}
