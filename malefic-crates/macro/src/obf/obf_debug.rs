use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Index};

/// Entry point for `#[derive(ObfDebug)]`.
///
/// Generates:
/// - **Debug builds** (`cfg(debug_assertions)`): standard `impl Debug`
/// - **Release builds** (`cfg(not(debug_assertions))`): `unsafe impl Obfuscatable`
///   via `derive_inplace_obf` (always available, no feature gate needed)
pub fn derive_obf_debug_impl(input: DeriveInput) -> TokenStream {
    let debug_impl = gen_debug_impl(&input);

    #[cfg(feature = "inplace_obf")]
    {
        let obf_tokens = super::derive_inplace_obf::derive_impl(input);
        return quote! {
            #[cfg(debug_assertions)]
            #debug_impl
            #[cfg(not(debug_assertions))]
            #obf_tokens
        };
    }

    #[cfg(not(feature = "inplace_obf"))]
    {
        let _ = input;
        return debug_impl;
    }
}

/// Generate a standard `impl Debug` equivalent to `#[derive(Debug)]`.
fn gen_debug_impl(input: &DeriveInput) -> TokenStream {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => gen_debug_struct(&name.to_string(), &data.fields),
        Data::Enum(data) => gen_debug_enum(data),
        Data::Union(_) => {
            return syn::Error::new_spanned(name, "ObfDebug does not support unions")
                .to_compile_error();
        }
    };

    quote! {
        impl #impl_generics ::core::fmt::Debug for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #body
            }
        }
    }
}

/// Debug impl body for structs (named, tuple, unit).
fn gen_debug_struct(name_str: &str, fields: &Fields) -> TokenStream {
    match fields {
        Fields::Named(named) => {
            let field_calls: Vec<TokenStream> = named
                .named
                .iter()
                .filter_map(|f| {
                    let ident = f.ident.as_ref()?;
                    let ident_str = ident.to_string();
                    Some(quote! { .field(#ident_str, &self.#ident) })
                })
                .collect();
            quote! {
                f.debug_struct(#name_str)
                    #(#field_calls)*
                    .finish()
            }
        }
        Fields::Unnamed(unnamed) => {
            let field_calls: Vec<TokenStream> = unnamed
                .unnamed
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    let idx = Index::from(i);
                    quote! { .field(&self.#idx) }
                })
                .collect();
            quote! {
                f.debug_tuple(#name_str)
                    #(#field_calls)*
                    .finish()
            }
        }
        Fields::Unit => {
            quote! {
                f.debug_struct(#name_str).finish()
            }
        }
    }
}

/// Debug impl body for enums.
fn gen_debug_enum(data: &syn::DataEnum) -> TokenStream {
    let arms: Vec<TokenStream> = data
        .variants
        .iter()
        .map(|v| {
            let variant = &v.ident;
            let variant_str = variant.to_string();
            match &v.fields {
                Fields::Named(named) => {
                    let field_idents: Vec<_> = named
                        .named
                        .iter()
                        .filter_map(|f| f.ident.as_ref())
                        .collect();
                    let field_strs: Vec<String> =
                        field_idents.iter().map(|i| i.to_string()).collect();
                    quote! {
                        Self::#variant { #(ref #field_idents),* } => {
                            f.debug_struct(#variant_str)
                                #(.field(#field_strs, #field_idents))*
                                .finish()
                        }
                    }
                }
                Fields::Unnamed(unnamed) => {
                    let bindings: Vec<syn::Ident> = (0..unnamed.unnamed.len())
                        .map(|i| {
                            syn::Ident::new(
                                &format!("__field{}", i),
                                proc_macro2::Span::call_site(),
                            )
                        })
                        .collect();
                    quote! {
                        Self::#variant(#(ref #bindings),*) => {
                            f.debug_tuple(#variant_str)
                                #(.field(#bindings))*
                                .finish()
                        }
                    }
                }
                Fields::Unit => {
                    quote! {
                        Self::#variant => {
                            f.write_str(#variant_str)
                        }
                    }
                }
            }
        })
        .collect();

    quote! {
        match self {
            #(#arms)*
        }
    }
}
