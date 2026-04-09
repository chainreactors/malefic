use rand::rngs::{OsRng, SmallRng};
use rand::{Rng, SeedableRng};

/// Create a SmallRng seeded from OS randomness.
/// Fallback to const-random seed only when OS RNG is unavailable.
pub fn seeded_rng() -> SmallRng {
    SmallRng::from_rng(OsRng).unwrap_or_else(|_| {
        #[cfg(any(
            feature = "literal_obf",
            feature = "control_flow",
            feature = "junk_insertion",
            feature = "embed_encrypt"
        ))]
        {
            let seed: u64 = const_random::const_random!(u64);
            return SmallRng::seed_from_u64(seed);
        }
        #[cfg(not(any(
            feature = "literal_obf",
            feature = "control_flow",
            feature = "junk_insertion",
            feature = "embed_encrypt"
        )))]
        {
            SmallRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE)
        }
    })
}

/// Generate a random u8 array of given length.
pub fn random_bytes(rng: &mut SmallRng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

/// Generate a random u32.
pub fn random_u32(rng: &mut SmallRng) -> u32 {
    rng.gen()
}

/// Generate a random identifier name.
pub fn random_ident(rng: &mut SmallRng) -> syn::Ident {
    let name: String = (0..12)
        .map(|i| {
            if i == 0 {
                (b'a' + rng.gen_range(0..26)) as char
            } else {
                let c = rng.gen_range(0..36);
                if c < 26 {
                    (b'a' + c) as char
                } else {
                    (b'0' + (c - 26)) as char
                }
            }
        })
        .collect();
    syn::Ident::new(&name, proc_macro2::Span::call_site())
}

/// XOR two byte slices (same length).
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "xor_bytes length mismatch");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// AST visitor that replaces selected literals with obfuscated forms.
///
/// - `String::from("...")` → `::malefic_gateway::obf_string!(...)`
/// - `"...".to_string()` → `::malefic_gateway::obf_string!(...)`
/// - `b"..."` → `::malefic_gateway::obf_bytes!(...)`
/// - `b"...".to_vec()` → `::malefic_gateway::obf_bytes!(...)`
/// - Integer literals with type suffix → `::malefic_gateway::obf_int!(...)`
/// - Skips macro bodies to avoid double-obfuscation
pub struct LiteralObfuscator;

impl syn::visit_mut::VisitMut for LiteralObfuscator {
    fn visit_expr_call_mut(&mut self, node: &mut syn::ExprCall) {
        syn::visit_mut::visit_expr_call_mut(self, node);

        // String::from("...") -> obfuscated String builder.
        // After bare-str handling, the arg may already be obfstr!("..."), so
        // we also collapse String::from(obfstr!("...")) → obf_string!("...").
        if let syn::Expr::Path(path) = node.func.as_ref() {
            let segs: Vec<_> = path.path.segments.iter().collect();
            if segs.len() >= 2
                && segs[segs.len() - 2].ident == "String"
                && segs[segs.len() - 1].ident == "from"
                && node.args.len() == 1
            {
                if let Some(arg0) = node.args.first_mut() {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(lit_str),
                        ..
                    }) = arg0
                    {
                        let s = lit_str.value();
                        use quote::quote;
                        *arg0 = syn::parse2(quote! {{
                            ::malefic_gateway::obf_string!(#s)
                        }})
                        .expect("failed to parse String::from obfuscation");
                    } else if let syn::Expr::Macro(mac_expr) = arg0 {
                        let last_seg = mac_expr.mac.path.segments.last();
                        if last_seg.map_or(false, |s| s.ident == "obfstr") {
                            let tokens = &mac_expr.mac.tokens;
                            use quote::quote;
                            *arg0 = syn::parse2(quote! {{
                                ::malefic_gateway::obf_string!(#tokens)
                            }})
                            .expect("failed to collapse String::from(obfstr!(...))");
                        }
                    }
                }
            }
        }
    }

    fn visit_expr_method_call_mut(&mut self, node: &mut syn::ExprMethodCall) {
        syn::visit_mut::visit_expr_method_call_mut(self, node);

        // "literal".to_string() -> obf_string!("literal")
        // Also: obfstr!("literal").to_string() -> obf_string!("literal")
        if node.method == "to_string" && node.args.is_empty() {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(lit_str),
                ..
            }) = node.receiver.as_ref()
            {
                let s = lit_str.value();
                use quote::quote;
                let replacement: syn::Expr = syn::parse2(quote! {
                    ::malefic_gateway::obf_string!(#s)
                })
                .expect("failed to parse to_string obfuscation");
                *node.receiver = replacement;
            } else if let syn::Expr::Macro(mac_expr) = node.receiver.as_ref() {
                let last_seg = mac_expr.mac.path.segments.last();
                if last_seg.map_or(false, |s| s.ident == "obfstr") {
                    let tokens = mac_expr.mac.tokens.clone();
                    use quote::quote;
                    let replacement: syn::Expr = syn::parse2(quote! {
                        ::malefic_gateway::obf_string!(#tokens)
                    })
                    .expect("failed to collapse obfstr.to_string to obf_string");
                    *node.receiver = replacement;
                }
            }
        }

        // b"literal".to_vec() -> obf_bytes!(b"literal")
        if node.method == "to_vec" && node.args.is_empty() {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::ByteStr(lit_bytes),
                ..
            }) = node.receiver.as_ref()
            {
                let bytes = lit_bytes.value();
                use quote::quote;
                let byte_lit = syn::LitByteStr::new(&bytes, lit_bytes.span());
                let replacement: syn::Expr = syn::parse2(quote! {
                    ::malefic_gateway::obf_bytes!(#byte_lit)
                })
                .expect("failed to parse to_vec bytes obfuscation");
                *node.receiver = replacement;
            }
        }
    }

    fn visit_expr_mut(&mut self, expr: &mut syn::Expr) {
        syn::visit_mut::visit_expr_mut(self, expr);

        // After visit_expr_method_call_mut has run, we may have
        // "obf_string!(...).to_string()" — collapse the redundant .to_string()
        if let syn::Expr::MethodCall(ref method_call) = expr {
            if method_call.method == "to_string" && method_call.args.is_empty() {
                if let syn::Expr::Macro(ref mac_expr) = *method_call.receiver {
                    let path = &mac_expr.mac.path;
                    let last_seg = path.segments.last();
                    if last_seg.map_or(false, |s| s.ident == "obf_string" || s.ident == "obfstr") {
                        // Replace `obf_string!("...").to_string()` → `obf_string!("...")`
                        // Also: `obfstr!("...").to_string()` → `obf_string!("...")`
                        // Normalize obfstr → obf_string since .to_string() means caller wants String
                        if last_seg.map_or(false, |s| s.ident == "obfstr") {
                            // Rewrite obfstr!("...").to_string() → obf_string!("...")
                            let tokens = &mac_expr.mac.tokens;
                            use quote::quote;
                            let new_expr: syn::Expr = syn::parse2(quote! {
                                ::malefic_gateway::obf_string!(#tokens)
                            })
                            .expect("failed to rewrite obfstr.to_string to obf_string");
                            *expr = new_expr;
                        } else {
                            let replacement = method_call.receiver.clone();
                            *expr = (*replacement).clone();
                        }
                        return;
                    }
                }
            }
        }

        // Collapse redundant `obf_bytes!(...).to_vec()` — obf_bytes! already returns Vec<u8>
        if let syn::Expr::MethodCall(ref method_call) = expr {
            if method_call.method == "to_vec" && method_call.args.is_empty() {
                if let syn::Expr::Macro(ref mac_expr) = *method_call.receiver {
                    let path = &mac_expr.mac.path;
                    let last_seg = path.segments.last();
                    if last_seg.map_or(false, |s| s.ident == "obf_bytes") {
                        let replacement = method_call.receiver.clone();
                        *expr = (*replacement).clone();
                        return;
                    }
                }
            }
        }

        // Bare byte string literal: b"..." → obf_bytes!(b"...")
        if let syn::Expr::Lit(lit_expr) = expr {
            if let syn::Lit::ByteStr(lit_bytes) = &lit_expr.lit {
                let bytes = lit_bytes.value();
                use quote::quote;
                let byte_lit = syn::LitByteStr::new(&bytes, lit_bytes.span());
                let new_expr: syn::Expr = syn::parse2(quote! {
                    ::malefic_gateway::obf_bytes!(#byte_lit)
                })
                .expect("failed to parse obf_bytes replacement");
                *expr = new_expr;
                return;
            }
        }

        // Bare string literal: "..." → obfstr!("...")
        // This handles cases like method args: contains_key("key"), Error::msg("msg"), etc.
        if let syn::Expr::Lit(lit_expr) = expr {
            if let syn::Lit::Str(lit_str) = &lit_expr.lit {
                let s = lit_str.value();
                use quote::quote;
                let new_expr: syn::Expr = syn::parse2(quote! {
                    ::malefic_gateway::obfstr!(#s)
                })
                .expect("failed to parse obfstr replacement");
                *expr = new_expr;
                return;
            }
        }

        if let syn::Expr::Lit(lit_expr) = expr {
            if let syn::Lit::Int(lit_int) = &lit_expr.lit {
                let suffix = lit_int.suffix();
                if !suffix.is_empty() {
                    let token = lit_int.token();
                    use quote::quote;
                    let new_expr: syn::Expr = syn::parse2(quote! {
                        ::malefic_gateway::obf_int!(#token)
                    })
                    .expect("failed to parse obf_int replacement");
                    *expr = new_expr;
                }
            }
        }
    }

    // Visit macro bodies for custom macros (to_error!, check_request!, etc.)
    // but skip Rust built-in format/assertion macros whose first argument is a format string.
    fn visit_macro_mut(&mut self, mac: &mut syn::Macro) {
        let last_seg = mac.path.segments.last();
        let name = last_seg.map(|s| s.ident.to_string()).unwrap_or_default();

        // Skip macros whose arguments include format strings or compile-time patterns
        const SKIP_MACROS: &[&str] = &[
            "format",
            "format_args",
            "println",
            "print",
            "eprintln",
            "eprint",
            "write",
            "writeln",
            "panic",
            "todo",
            "unimplemented",
            "unreachable",
            "assert",
            "assert_eq",
            "assert_ne",
            "debug_assert",
            "debug_assert_eq",
            "debug_assert_ne",
            "vec",
            "concat",
            "stringify",
            "env",
            "include",
            "include_str",
            "include_bytes",
            "cfg",
            "compile_error",
            "debug",
            "log",
            "info",
            "warn",
            "error",
            "trace",
            "anyhow",
            // Our own obfuscation macros — never recurse into them
            "obf_string",
            "obf_bytes",
            "obf_int",
            "obfstr",
            "obf_stmts",
            "flow",
            "lazy_static",
        ];

        if SKIP_MACROS.contains(&name.as_str()) {
            return;
        }

        // For custom macros, try to parse their token body as expressions and visit them.
        // This handles macros like to_error!(Err("...".to_string())) where the body is
        // a valid Rust expression tree.
        let tokens = mac.tokens.clone();
        if let Ok(mut expr) = syn::parse2::<syn::Expr>(tokens) {
            self.visit_expr_mut(&mut expr);
            mac.tokens = quote::quote!(#expr);
        }
    }
}
