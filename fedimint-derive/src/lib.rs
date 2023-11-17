#![cfg_attr(feature = "diagnostics", feature(proc_macro_diagnostic))]

use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::{Ident, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{
    parse_macro_input, Data, DataEnum, DataStruct, DeriveInput, Field, Fields, Index, Variant,
};

fn do_not_ignore(field: &Field) -> bool {
    !field
        .attrs
        .iter()
        .any(|attr| attr.path.is_ident("encodable_ignore"))
}

fn panic_if_ignored(field: &Field) -> bool {
    if !do_not_ignore(field) {
        panic!("Trying to derive decodable from a struct with ignored fields");
    }
    true
}

fn is_default_variant_enforce_valid(variant: &Variant) -> bool {
    let is_default = variant
        .attrs
        .iter()
        .any(|attr| attr.path.is_ident("encodable_default"));

    if is_default {
        assert_eq!(
            variant.ident.to_string(),
            "Default",
            "Default variant should be called `Default`"
        );
        let two_fields = variant.fields.len() == 2;
        let field_names = variant
            .fields
            .iter()
            .filter_map(|field| field.ident.as_ref().map(|ident| ident.to_string()))
            .sorted()
            .collect::<Vec<_>>();
        let correct_fields = field_names == vec!["bytes".to_string(), "variant".to_string()];

        assert!(two_fields && correct_fields, "The default variant should have exactly two field: `variant: u64` and `bytes: Vec<u8>`");
    }

    is_default
}

#[proc_macro_derive(Encodable, attributes(encodable_ignore, encodable_default))]
pub fn derive_encodable(input: TokenStream) -> TokenStream {
    let DeriveInput {
        ident,
        data,
        generics,
        ..
    } = parse_macro_input!(input);

    let encode_inner = match data {
        Data::Struct(DataStruct { fields, .. }) => derive_struct_encode(&fields),
        Data::Enum(DataEnum { variants, .. }) => derive_enum_encode(&ident, &variants),
        Data::Union(_) => error(&ident, "Encodable can't be derived for unions"),
    };
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let output = quote! {
        impl #impl_generics ::fedimint_core::encoding::Encodable for #ident #ty_generics #where_clause {
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
            .enumerate()
            .filter(|(_, f)| do_not_ignore(f))
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

    let non_default_match_arms = variants
        .iter()
        .filter(|variant| !is_default_variant_enforce_valid(variant))
        .enumerate()
        .map(|(variant_idx, variant)| {
            let variant_ident = variant.ident.clone();

            if is_tuple_struct(&variant.fields) {
                let variant_fields = variant
                    .fields
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| do_not_ignore(f))
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

    let default_match_arm = variants
        .iter()
        .find(|variant| is_default_variant_enforce_valid(variant))
        .map(|_variant| {
            quote! {
                #ident::Default { variant, bytes } => {
                    len += ::fedimint_core::encoding::Encodable::consensus_encode(variant, writer)?;
                    len += ::fedimint_core::encoding::Encodable::consensus_encode(bytes, writer)?;
                }
            }
        });

    let match_arms = non_default_match_arms.chain(default_match_arm);

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

        let mut bytes = Vec::<u8>::new();
        #(::fedimint_core::encoding::Encodable::consensus_encode(#fields, &mut bytes)?;)*

        len += ::fedimint_core::encoding::Encodable::consensus_encode(&bytes, writer)?;
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
    let decode_block = derive_tuple_or_named_decode_block(quote! { #ident }, quote! { d }, fields);

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

    let non_default_match_arms = variants.iter()
        .filter(|variant| !is_default_variant_enforce_valid(variant))
        .enumerate()
        .map(|(variant_idx, variant)| {
            let variant_idx = variant_idx as u64;
            let variant_ident = variant.ident.clone();
            let decode_block = derive_tuple_or_named_decode_block(
                quote! { #ident::#variant_ident },
                quote! { &mut cursor },
                &variant.fields,
            );

            // FIXME: make sure we read all bytes
            quote! {
                #variant_idx => {
                    let bytes: Vec<u8> = ::fedimint_core::encoding::Decodable::consensus_decode(d, modules)?;
                    let mut cursor = std::io::Cursor::new(&bytes);

                    let decoded = #decode_block;

                    let read_bytes = cursor.position();
                    let total_bytes = bytes.len() as u64;
                    if read_bytes != total_bytes {
                        return Err(::fedimint_core::encoding::DecodeError::new_custom(anyhow::anyhow!(
                            "Partial read: got {total_bytes} bytes but only read {read_bytes}"
                        )));
                    }

                    decoded
                }
            }
        });

    let default_match_arm = if variants.iter().any(is_default_variant_enforce_valid) {
        quote! {
            variant => {
                let bytes: Vec<u8> = ::fedimint_core::encoding::Decodable::consensus_decode(d, modules)?;
                #ident::Default {
                    variant,
                    bytes
                }
            }
        }
    } else {
        quote! {
            _ => {
                return Err(::fedimint_core::encoding::DecodeError::from_str("invalid enum variant"));
            }
        }
    };

    quote! {
        let variant = <u64 as ::fedimint_core::encoding::Decodable>::consensus_decode(d, modules)?;
        let decoded = match variant {
            #(#non_default_match_arms)*
            #default_match_arm
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
fn derive_tuple_or_named_decode_block(
    constructor: TokenStream2,
    reader: TokenStream2,
    fields: &Fields,
) -> TokenStream2 {
    if is_tuple_struct(fields) {
        derive_tuple_decode_block(constructor, reader, fields)
    } else {
        derive_named_decode_block(constructor, reader, fields)
    }
}

fn derive_tuple_decode_block(
    constructor: TokenStream2,
    reader: TokenStream2,
    fields: &Fields,
) -> TokenStream2 {
    let field_names = fields
        .iter()
        .filter(|f| panic_if_ignored(f))
        .enumerate()
        .map(|(idx, _)| format_ident!("field_{}", idx))
        .collect::<Vec<_>>();
    quote! {
        {
            #(let #field_names = ::fedimint_core::encoding::Decodable::consensus_decode(#reader, modules)?;)*
            #constructor(#(#field_names,)*)
        }
    }
}

fn derive_named_decode_block(
    constructor: TokenStream2,
    reader: TokenStream2,
    fields: &Fields,
) -> TokenStream2 {
    let variant_fields = fields
        .iter()
        .filter(|f| panic_if_ignored(f))
        .map(|field| field.ident.clone().unwrap())
        .collect::<Vec<_>>();
    quote! {
        {
            #(let #variant_fields = ::fedimint_core::encoding::Decodable::consensus_decode(#reader, modules)?;)*
            #constructor{
                #(#variant_fields,)*
            }
        }
    }
}
