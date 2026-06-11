use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{Attribute, Expr, Ident, Token, Type, Visibility};

#[cfg(feature = "literal_obf")]
use syn::visit_mut::VisitMut;

#[cfg(feature = "literal_obf")]
use crate::obf::util::LiteralObfuscator;

/// A single `static ref NAME: TYPE = EXPR;` entry.
struct LazyStaticEntry {
    attrs: Vec<Attribute>,
    vis: Visibility,
    name: Ident,
    ty: Type,
    init: Expr,
}

/// The full `lazy_static! { ... }` body: one or more entries.
struct LazyStaticInput {
    entries: Vec<LazyStaticEntry>,
}

impl Parse for LazyStaticEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let vis: Visibility = input.parse()?;
        input.parse::<Token![static]>()?;
        input.parse::<Token![ref]>()?;
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty: Type = input.parse()?;
        input.parse::<Token![=]>()?;
        let init: Expr = input.parse()?;
        input.parse::<Token![;]>()?;
        Ok(LazyStaticEntry {
            attrs,
            vis,
            name,
            ty,
            init,
        })
    }
}

impl Parse for LazyStaticInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut entries = Vec::new();
        while !input.is_empty() {
            entries.push(input.parse()?);
        }
        Ok(LazyStaticInput { entries })
    }
}

pub fn lazy_static_impl(input: TokenStream) -> TokenStream {
    let parsed: LazyStaticInput = match syn::parse2(input) {
        Ok(v) => v,
        Err(e) => return e.to_compile_error(),
    };

    let mut output = TokenStream::new();

    for entry in parsed.entries {
        let LazyStaticEntry {
            attrs,
            vis,
            name,
            ty,
            mut init,
        } = entry;

        // Apply literal obfuscation to the initializer expression (if enabled).
        #[cfg(feature = "literal_obf")]
        LiteralObfuscator.visit_expr_mut(&mut init);

        let expanded = quote! {
            #[allow(non_camel_case_types)]
            #[allow(dead_code)]
            #(#attrs)*
            #vis struct #name { __private_field: () }

            #[allow(non_upper_case_globals)]
            #vis static #name: #name = #name { __private_field: () };

            impl ::core::ops::Deref for #name {
                type Target = #ty;
                fn deref(&self) -> &#ty {
                    static __LAZY: ::std::sync::OnceLock<#ty> = ::std::sync::OnceLock::new();
                    __LAZY.get_or_init(|| { #init })
                }
            }
        };

        output.extend(expanded);
    }

    output
}
