#![feature(proc_macro_diagnostic)]

use heck::SnakeCase;
use proc_macro::{self, TokenStream};
use quote::{format_ident, quote};
use syn::{parse_macro_input, DataEnum, DeriveInput};

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
            .collect::<Result<Vec<_>, _>>(),
        _ => Err("UnzipConsensus can only be derived for enums"),
    };

    let variants = match variants {
        Ok(variants) => variants,
        Err(e) => {
            ident.span().unstable().error(e).emit();
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
            #(#unzip_s_ident: Vec<(u16, #unzip_s_type)>),*
        }

        impl<I> #unzip_trait_ident for I
        where
            I: Iterator<Item = (u16, #ident)>,
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
