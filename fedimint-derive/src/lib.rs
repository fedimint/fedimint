#![cfg_attr(feature = "diagnostics", feature(proc_macro_diagnostic))]

use heck::ToSnakeCase;
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::{format_ident, quote};
use syn::__private::TokenStream2;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{
    parse_macro_input, Data, DataEnum, DataStruct, DeriveInput, Field, Fields, Index, Variant,
};

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
            panic!("Error: {e}");
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

fn do_not_ignore(field: &Field) -> bool {
    !field.attrs.iter().any(|attr| {
        attr.path
            .segments
            .iter()
            .any(|segment| segment.ident == *"encodable_ignore")
    })
}

fn panic_if_ignored(field: &Field) -> bool {
    if !do_not_ignore(field) {
        panic!("Trying to derive decodable from a struct with ignored fields");
    }
    true
}

#[proc_macro_derive(Encodable, attributes(encodable_ignore))]
pub fn derive_encodable(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);

    let encode_inner = match data {
        Data::Struct(DataStruct { fields, .. }) => derive_struct_encode(&fields),
        Data::Enum(DataEnum { variants, .. }) => derive_enum_encode(&ident, &variants),
        Data::Union(_) => error(&ident, "Encodable can't be derived for unions"),
    };

    let output = quote! {
        impl ::fedimint_core::encoding::Encodable for #ident {
            fn consensus_encode<W: std::io::Write>(&self, mut writer: &mut W) -> std::result::Result<usize, std::io::Error> {
                #encode_inner
            }
        }
    };

    output.into()
}

fn derive_struct_encode(fields: &Fields) -> TokenStream2 {
    if is_tuple_struct(fields) {
        // Tuple struct
        let field_names = fields
            .iter()
            .filter(|f| do_not_ignore(f))
            .enumerate()
            .map(|(idx, _)| Index::from(idx))
            .collect::<Vec<_>>();
        quote! {
            let mut len = 0;
            #(len += ::fedimint_core::encoding::Encodable::consensus_encode(&self.#field_names, writer)?;)*
            Ok(len)
        }
    } else {
        // Named struct
        let field_names = fields
            .iter()
            .filter(|f| do_not_ignore(f))
            .map(|field| field.ident.clone().unwrap())
            .collect::<Vec<_>>();
        quote! {
            let mut len = 0;
            #(len += ::fedimint_core::encoding::Encodable::consensus_encode(&self.#field_names, writer)?;)*
            Ok(len)
        }
    }
}

fn derive_enum_encode(ident: &Ident, variants: &Punctuated<Variant, Comma>) -> TokenStream2 {
    if variants.is_empty() {
        return quote! {
            match *self {}
        };
    }

    let match_arms = variants.iter().enumerate().map(|(variant_idx, variant)| {
        let variant_ident = variant.ident.clone();

        if is_tuple_struct(&variant.fields) {
            let variant_fields = variant
                .fields
                .iter()
                .filter(|f| do_not_ignore(f))
                .enumerate()
                .map(|(idx, _)| format_ident!("bound_{}", idx))
                .collect::<Vec<_>>();
            let variant_encode_block =
                derive_enum_variant_encode_block(variant_idx, &variant_fields);
            quote! {
                #ident::#variant_ident(#(#variant_fields,)*) => {
                    #variant_encode_block
                }
            }
        } else {
            let variant_fields = variant
                .fields
                .iter()
                .filter(|f| do_not_ignore(f))
                .map(|field| field.ident.clone().unwrap())
                .collect::<Vec<_>>();
            let variant_encode_block =
                derive_enum_variant_encode_block(variant_idx, &variant_fields);
            quote! {
                #ident::#variant_ident { #(#variant_fields,)*} => {
                    #variant_encode_block
                }
            }
        }
    });
    quote! {
        let mut len = 0;
        match self {
            #(#match_arms)*
        }
        Ok(len)
    }
}

fn derive_enum_variant_encode_block(idx: usize, fields: &[Ident]) -> TokenStream2 {
    quote! {
        len += ::fedimint_core::encoding::Encodable::consensus_encode(&(#idx as u64), writer)?;
        #(len += ::fedimint_core::encoding::Encodable::consensus_encode(#fields, writer)?;)*
    }
}

#[proc_macro_derive(Decodable)]
pub fn derive_decodable(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);

    let decode_inner = match data {
        Data::Struct(DataStruct { fields, .. }) => derive_struct_decode(&ident, &fields),
        syn::Data::Enum(DataEnum { variants, .. }) => derive_enum_decode(&ident, &variants),
        syn::Data::Union(_) => error(&ident, "Encodable can't be derived for unions"),
    };

    let output = quote! {
        impl ::fedimint_core::encoding::Decodable for #ident {
            fn consensus_decode<D: std::io::Read>(d: &mut D, modules: &::fedimint_core::module::registry::ModuleDecoderRegistry) -> std::result::Result<Self, ::fedimint_core::encoding::DecodeError> {
                #decode_inner
            }
        }
    };

    output.into()
}

#[allow(unused_variables, unreachable_code)]
fn error(ident: &Ident, message: &str) -> TokenStream2 {
    #[cfg(feature = "diagnostics")]
    ident.span().unstable().error(message).emit();
    #[cfg(not(feature = "diagnostics"))]
    panic!("{message}");

    TokenStream2::new()
}

fn derive_struct_decode(ident: &Ident, fields: &Fields) -> TokenStream2 {
    let decode_block = derive_tuple_or_named_decode_block(quote! { #ident }, &fields);

    quote! {
        Ok(#decode_block)
    }
}

fn derive_enum_decode(ident: &Ident, variants: &Punctuated<Variant, Comma>) -> TokenStream2 {
    if variants.is_empty() {
        return quote! {
            Err(::fedimint_core::encoding::DecodeError::new_custom(anyhow::anyhow!("Enum without variants can't be instantiated")))
        };
    }

    let match_arms = variants.iter().enumerate().map(|(variant_idx, variant)| {
        let variant_ident = variant.ident.clone();
        let decode_block =
            derive_tuple_or_named_decode_block(quote! { #ident::#variant_ident }, &variant.fields);

        quote! {
            #variant_idx => {
                #decode_block
            }
        }
    });

    quote! {
        let variant = <u64 as ::fedimint_core::encoding::Decodable>::consensus_decode(d, modules)? as usize;
        let decoded = match variant {
            #(#match_arms)*
            _ => {
                return Err(::fedimint_core::encoding::DecodeError::from_str("invalid enum variant"));
            }
        };
        Ok(decoded)
    }
}

fn is_tuple_struct(fields: &Fields) -> bool {
    fields.iter().any(|field| field.ident.is_none())
}

// TODO: how not to use token stream for constructor, but still support both:
//   * Enum::Variant
//   * Struct
// as idents
fn derive_tuple_or_named_decode_block(constructor: TokenStream2, fields: &Fields) -> TokenStream2 {
    if is_tuple_struct(fields) {
        derive_tuple_decode_block(constructor, fields)
    } else {
        derive_named_decode_block(constructor, fields)
    }
}

fn derive_tuple_decode_block(constructor: TokenStream2, fields: &Fields) -> TokenStream2 {
    let field_names = fields
        .iter()
        .filter(|f| panic_if_ignored(f))
        .enumerate()
        .map(|(idx, _)| format_ident!("field_{}", idx))
        .collect::<Vec<_>>();
    quote! {
        {
            #(let #field_names = ::fedimint_core::encoding::Decodable::consensus_decode(d, modules)?;)*
            #constructor(#(#field_names,)*)
        }
    }
}

fn derive_named_decode_block(constructor: TokenStream2, fields: &Fields) -> TokenStream2 {
    let variant_fields = fields
        .iter()
        .filter(|f| panic_if_ignored(f))
        .map(|field| field.ident.clone().unwrap())
        .collect::<Vec<_>>();
    quote! {
        {
            #(let #variant_fields = ::fedimint_core::encoding::Decodable::consensus_decode(d, modules)?;)*
            #constructor{
                #(#variant_fields,)*
            }
        }
    }
}
