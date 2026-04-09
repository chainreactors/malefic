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

#[cfg(test)]
mod tests {
    use super::lazy_static_impl;
    use quote::quote;

    /// Helper: expand lazy_static and return the generated code as a string.
    fn expand(input: proc_macro2::TokenStream) -> String {
        lazy_static_impl(input).to_string()
    }

    #[test]
    fn test_generates_oncelock_deref() {
        let out = expand(quote! {
            static ref FOO: u32 = 42;
        });
        assert!(out.contains("OnceLock"), "must use OnceLock backend");
        assert!(out.contains("Deref"), "must generate Deref impl");
        assert!(out.contains("get_or_init"), "must use get_or_init");
    }

    #[test]
    fn test_struct_and_static_generated() {
        let out = expand(quote! {
            pub static ref MY_VAL: String = String::from("hello");
        });
        assert!(out.contains("struct MY_VAL"), "must generate struct");
        assert!(out.contains("static MY_VAL"), "must generate static");
        assert!(out.contains("__private_field"), "must have private field");
    }

    #[test]
    fn test_string_from_is_obfuscated() {
        let out = expand(quote! {
            static ref S: String = String::from("secret");
        });
        #[cfg(feature = "literal_obf")]
        assert!(
            out.contains("obf_string"),
            "String::from(\"...\") argument must be replaced with obf_string!, got:\n{}",
            out
        );
        #[cfg(not(feature = "literal_obf"))]
        assert!(
            !out.contains("obf_string"),
            "literal_obf disabled: should not obfuscate, got:\n{}",
            out
        );
    }

    #[test]
    fn test_typed_integer_is_obfuscated() {
        let out = expand(quote! {
            static ref N: u32 = 42u32;
        });
        #[cfg(feature = "literal_obf")]
        assert!(
            out.contains("obf_int"),
            "typed integer 42u32 must be replaced with obf_int!, got:\n{}",
            out
        );
    }

    #[test]
    fn test_untyped_integer_is_not_obfuscated() {
        let out = expand(quote! {
            static ref N: u32 = 42;
        });
        assert!(
            !out.contains("obf_int"),
            "untyped integer 42 should NOT be obfuscated"
        );
    }

    #[test]
    fn test_multiple_entries() {
        let out = expand(quote! {
            pub static ref A: u32 = 1;
            pub static ref B: String = String::from("two");
        });
        // Both structs generated
        assert!(out.contains("struct A"));
        assert!(out.contains("struct B"));
        // String obfuscated (when literal_obf enabled)
        #[cfg(feature = "literal_obf")]
        assert!(out.contains("obf_string"));
    }

    #[test]
    fn test_macro_bodies_not_double_obfuscated() {
        let out = expand(quote! {
            static ref V: Vec<u8> = vec![1u8, 2u8, 3u8];
        });
        // vec! is a macro invocation — LiteralObfuscator skips macro bodies,
        // so 1u8/2u8/3u8 inside vec![] must NOT be replaced.
        assert!(
            !out.contains("obf_int"),
            "literals inside macro invocations must not be obfuscated"
        );
    }

    #[test]
    fn test_visibility_preserved() {
        let out_pub = expand(quote! {
            pub static ref X: u32 = 1;
        });
        assert!(out_pub.contains("pub struct X"));
        assert!(out_pub.contains("pub static X"));

        let out_priv = expand(quote! {
            static ref Y: u32 = 1;
        });
        // No `pub` before struct/static
        assert!(!out_priv.contains("pub struct Y"));
        assert!(!out_priv.contains("pub static Y"));
    }

    #[test]
    fn test_attributes_preserved() {
        let out = expand(quote! {
            #[doc = "documentation"]
            pub static ref D: u32 = 1;
        });
        assert!(out.contains("doc"));
    }

    // ================================================================
    // Regression: patterns matching real codebase usage
    // ================================================================

    #[test]
    fn test_pattern_arc_mutex_hashmap() {
        // Pattern from pipe.rs, execute_armory.rs, pty/mod.rs
        let out = expand(quote! {
            static ref SESSIONS: Arc<Mutex<HashMap<String, PtySession>>> =
                Arc::new(Mutex::new(HashMap::new()));
        });
        assert!(out.contains("OnceLock"));
        assert!(out.contains("struct SESSIONS"));
    }

    #[test]
    fn test_pattern_cross_ref_deref() {
        // Pattern from config: CRON reads from RUNTIME_CONFIG
        let out = expand(quote! {
            pub static ref RUNTIME_CONFIG: RuntimeConfig = load_runtime_config(default_runtime_config());
            pub static ref CRON: String = RUNTIME_CONFIG.cron.clone();
        });
        assert!(out.contains("struct RUNTIME_CONFIG"));
        assert!(out.contains("struct CRON"));
    }

    #[test]
    fn test_pattern_codegen_import_style() {
        let out = expand(quote! {
            pub static ref NAME: String = String::from("implant_name");
            pub static ref KEY: Vec<u8> = vec![1, 2, 3];
        });
        #[cfg(feature = "literal_obf")]
        assert!(
            out.contains("obf_string"),
            "String::from must be auto-obfuscated"
        );
        assert!(out.contains("struct NAME"));
        assert!(out.contains("struct KEY"));
    }

    // ================================================================
    // Plan A: "lit".to_string() pattern
    // ================================================================

    #[test]
    fn test_to_string_literal_is_obfuscated() {
        let out = expand(quote! {
            static ref S: String = "hello".to_string();
        });
        #[cfg(feature = "literal_obf")]
        {
            assert!(
                out.contains("obf_string"),
                "\"lit\".to_string() must be replaced with obf_string!, got:\n{}",
                out
            );
            // The redundant .to_string() should be collapsed
            assert!(
                !out.contains("to_string"),
                "redundant .to_string() on obf_string! should be collapsed, got:\n{}",
                out
            );
        }
    }

    #[test]
    fn test_to_string_in_block() {
        let out = expand(quote! {
            static ref MAP: HashMap<String, String> = {
                let mut m = HashMap::new();
                m.insert("key".to_string(), "value".to_string());
                m
            };
        });
        #[cfg(feature = "literal_obf")]
        {
            // Both string literals should be obfuscated
            let count = out.matches("obf_string").count();
            assert!(
                count >= 2,
                "both \"key\".to_string() and \"value\".to_string() must be obfuscated, got {} occurrences:\n{}",
                count, out
            );
        }
    }

    #[test]
    fn test_to_string_on_non_literal_not_touched() {
        let out = expand(quote! {
            static ref S: String = some_var.to_string();
        });
        assert!(
            !out.contains("obf_string"),
            "non-literal .to_string() must NOT be obfuscated"
        );
    }

    #[test]
    fn test_to_string_codegen_pattern() {
        // Exact pattern that mutant codegen emits with use_obfstr=false
        let out = expand(quote! {
            pub static ref RUNTIME_CONFIG: RuntimeConfig = load_runtime_config(RuntimeConfig {
                cron: "*/5 * * * * * *".to_string(),
                name: "malefic".to_string(),
                proxy_url: "".to_string(),
            });
        });
        #[cfg(feature = "literal_obf")]
        {
            // All three .to_string() literals should be obfuscated
            let count = out.matches("obf_string").count();
            assert!(
                count >= 3,
                "all string literals in struct init must be obfuscated, got {} occurrences",
                count
            );
        }
    }

    // ================================================================
    // Byte string literal obfuscation
    // ================================================================

    #[test]
    fn test_byte_str_to_vec_is_obfuscated() {
        let out = expand(quote! {
            static ref K: Vec<u8> = b"secret".to_vec();
        });
        #[cfg(feature = "literal_obf")]
        assert!(
            out.contains("obf_bytes"),
            "b\"...\".to_vec() must be replaced with obf_bytes!, got:\n{}",
            out
        );
    }

    #[test]
    fn test_bare_byte_str_is_obfuscated() {
        let out = expand(quote! {
            static ref K: &'static [u8] = b"secret";
        });
        #[cfg(feature = "literal_obf")]
        assert!(
            out.contains("obf_bytes"),
            "bare b\"...\" must be replaced with obf_bytes!, got:\n{}",
            out
        );
    }

    #[test]
    fn test_byte_str_to_vec_collapsed() {
        let out = expand(quote! {
            static ref K: Vec<u8> = b"data".to_vec();
        });
        #[cfg(feature = "literal_obf")]
        {
            // obf_bytes! already returns Vec<u8>, so .to_vec() should be collapsed
            assert!(
                !out.contains("to_vec"),
                "redundant .to_vec() on obf_bytes! should be collapsed, got:\n{}",
                out
            );
        }
    }
}
