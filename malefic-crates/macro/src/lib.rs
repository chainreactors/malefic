extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse::Parse, parse::ParseStream, parse_macro_input, ItemImpl, LitStr};

// Pro obfuscation module — only compiled when any obf feature is enabled.
// The entire obf/ directory can be deleted for community builds.
#[cfg(feature = "_obf_impl")]
mod obf;

// Community: lazy_static is always available (OnceLock wrapper).
// LiteralObfuscator integration is gated by literal_obf inside.
mod lazy_static_impl;

struct MacroArgs {
    module_name: LitStr,
}

impl Parse for MacroArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let module_name = input.parse()?;
        Ok(MacroArgs { module_name })
    }
}

#[proc_macro_attribute]
pub fn module_impl(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as MacroArgs);
    let module_name = &args.module_name;
    let mut input = parse_macro_input!(item as ItemImpl);

    let struct_ty = &input.self_ty;

    let name_method = quote! {
        fn name() -> &'static str {
            ::malefic_gateway::obfstr!(#module_name)
        }
    };
    let new_method = quote! {
        fn new() -> Self {
            Self {}
        }
    };
    let new_instance_method = quote! {
        fn new_instance(&self) -> Box<dyn Module + Send + Sync + 'static> {
            Box::new(Self::new())
        }
    };

    input.items.push(syn::parse2(new_instance_method).unwrap());
    input.items.push(syn::parse2(new_method).unwrap());
    input.items.push(syn::parse2(name_method).unwrap());

    // Generate rt_run() — sync bridge that drives ModuleImpl::run() via noop_waker.
    // This is injected into the `impl Module` block.
    // Takes the same Input/Output channels as ModuleImpl::run(), but blocks.
    let rt_run_method = quote! {
        fn rt_run(
            &mut self,
            id: u32,
            recv_channel: &mut ::malefic_module::Input,
            send_channel: &mut ::malefic_module::Output,
        ) -> ::malefic_module::ModuleResult {
            use ::core::future::Future;
            use ::core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

            fn noop_raw_waker() -> RawWaker {
                fn no_op(_: *const ()) {}
                fn clone(p: *const ()) -> RawWaker { RawWaker::new(p, &VTABLE) }
                static VTABLE: RawWakerVTable =
                    RawWakerVTable::new(clone, no_op, no_op, no_op);
                RawWaker::new(::core::ptr::null(), &VTABLE)
            }
            let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
            let mut cx = Context::from_waker(&waker);

            let fut = ::malefic_module::ModuleImpl::run(
                self, id, recv_channel, send_channel,
            );
            ::futures::pin_mut!(fut);

            loop {
                match fut.as_mut().poll(&mut cx) {
                    Poll::Ready(result) => return result,
                    Poll::Pending => {
                        ::std::thread::sleep(::std::time::Duration::from_millis(1));
                    }
                }
            }
        }
    };
    input.items.push(syn::parse2(rt_run_method).unwrap());

    // Auto-generate `impl RtModule` for DLL export compatibility.
    // Only compiled when the crate has malefic-runtime available (e.g. as_module_dll).
    // RtModule::run() bridges RtChannel I/O ↔ futures channels, then delegates to ModuleImpl.
    let rt_module_impl = quote! {
        #[cfg(feature = "as_module_dll")]
        const _: () = {
            impl ::malefic_module::module_sdk::RtModule for #struct_ty {
                fn name() -> &'static str {
                    ::malefic_gateway::obfstr!(#module_name)
                }
                fn new() -> Self {
                    Self {}
                }
                fn run(
                    &mut self,
                    task_id: u32,
                    channel: &::malefic_module::module_sdk::RtChannel,
                ) -> ::malefic_module::module_sdk::RtResult {
                    use ::malefic_module::module_sdk::RtResult;

                    let (input_tx, mut input_rx) =
                        ::futures::channel::mpsc::unbounded::<
                            ::malefic_proto::proto::implantpb::spite::Body
                        >();
                    let (mut output_tx, mut output_rx) =
                        ::futures::channel::mpsc::unbounded::<::malefic_module::TaskResult>();

                    let mut input_tx = Some(input_tx);

                    // Interleave I/O polling with rt_run progress.
                    // rt_run blocks, so we need a thread for I/O.
                    // But rt_run internally polls the future — we can't call it
                    // directly because we need to pump RtChannel I/O.
                    //
                    // Instead, inline the same poll loop but with RtChannel I/O.
                    use ::core::future::Future;
                    use ::core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

                    fn noop_raw_waker() -> RawWaker {
                        fn no_op(_: *const ()) {}
                        fn clone(p: *const ()) -> RawWaker { RawWaker::new(p, &VTABLE) }
                        static VTABLE: RawWakerVTable =
                            RawWakerVTable::new(clone, no_op, no_op, no_op);
                        RawWaker::new(::core::ptr::null(), &VTABLE)
                    }
                    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
                    let mut cx = Context::from_waker(&waker);

                    let fut = ::malefic_module::ModuleImpl::run(
                        self, task_id, &mut input_rx, &mut output_tx,
                    );
                    ::futures::pin_mut!(fut);

                    loop {
                        match fut.as_mut().poll(&mut cx) {
                            Poll::Ready(result) => {
                                {
                                    use ::futures::stream::TryStreamExt;
                                    while let Ok(Some(tr)) = output_rx.try_next() {
                                        let _ = channel.send(tr.body);
                                    }
                                }
                                return match result {
                                    Ok(tr) => RtResult::Done(tr.body),
                                    Err(e) => RtResult::Error(::std::format!("{}", e)),
                                };
                            }
                            Poll::Pending => {}
                        }

                        if let Some(ref tx) = input_tx {
                            match channel.try_recv() {
                                Ok(Some(body)) => { let _ = tx.unbounded_send(body); }
                                Ok(None) => {}
                                Err(_) => { input_tx = None; }
                            }
                        }

                        {
                            use ::futures::stream::TryStreamExt;
                            while let Ok(Some(tr)) = output_rx.try_next() {
                                let _ = channel.send(tr.body);
                            }
                        }

                        ::std::thread::sleep(::std::time::Duration::from_millis(1));
                    }
                }
            }
        };
    };

    let expanded = quote! {
        #input
        #rt_module_impl
    };

    TokenStream::from(expanded)
}

// ============================================================================
// Proc macros — each has a pro branch (uses obf/) and a community no-op branch
// ============================================================================

/// AES-256-CTR string encryption at compile time, decrypted at runtime.
/// Returns `String`. Usage: `obf_string!("sensitive string")`
#[proc_macro]
pub fn obf_string(input: TokenStream) -> TokenStream {
    #[cfg(feature = "literal_obf")]
    {
        let parsed = parse_macro_input!(input as obf::strings::ObfStringInput);
        return TokenStream::from(obf::strings::obf_string_impl(parsed));
    }
    #[cfg(not(feature = "literal_obf"))]
    {
        let lit = parse_macro_input!(input as LitStr);
        return TokenStream::from(quote! { String::from(#lit) });
    }
}

/// Drop-in replacement for `obfstr::obfstr!` — returns `&'static str`.
/// Usage: `obfstr!("sensitive string")`
#[proc_macro]
pub fn obfstr(input: TokenStream) -> TokenStream {
    #[cfg(feature = "literal_obf")]
    {
        let parsed = parse_macro_input!(input as obf::strings::ObfStringInput);
        return TokenStream::from(obf::strings::obfstr_impl(parsed));
    }
    #[cfg(not(feature = "literal_obf"))]
    {
        let lit = parse_macro_input!(input as LitStr);
        return TokenStream::from(quote! { #lit });
    }
}

/// AES-256-CTR byte string encryption at compile time, decrypted at runtime.
/// Usage: `obf_bytes!(b"sensitive bytes")`
#[proc_macro]
pub fn obf_bytes(input: TokenStream) -> TokenStream {
    #[cfg(feature = "literal_obf")]
    {
        let parsed = parse_macro_input!(input as obf::strings::ObfBytesInput);
        return TokenStream::from(obf::strings::obf_bytes_impl(parsed));
    }
    #[cfg(not(feature = "literal_obf"))]
    {
        let lit = parse_macro_input!(input as syn::LitByteStr);
        return TokenStream::from(quote! { (#lit).to_vec() });
    }
}

/// Lightweight control-flow obfuscation with dummy loops and black_box.
/// Usage: `flow!{ real_code_here; }`
#[proc_macro]
pub fn flow(input: TokenStream) -> TokenStream {
    #[cfg(feature = "control_flow")]
    {
        return TokenStream::from(obf::flow::flow_impl(input.into()));
    }
    #[cfg(not(feature = "control_flow"))]
    {
        let input2: proc_macro2::TokenStream = input.into();
        let block: syn::Block = syn::parse2(input2).expect("flow! expects a block { ... }");
        return TokenStream::from(quote! { #block });
    }
}

/// XOR-chain state machine obfuscation (goldberg style).
/// Usage: `obf_stmts!{ stmt1; stmt2; stmt3; }`
#[proc_macro]
pub fn obf_stmts(input: TokenStream) -> TokenStream {
    #[cfg(feature = "control_flow")]
    {
        return TokenStream::from(obf::stmts::obf_stmts_impl(input.into()));
    }
    #[cfg(not(feature = "control_flow"))]
    {
        let input2: proc_macro2::TokenStream = input.into();
        let block: syn::Block = syn::parse2(input2).expect("obf_stmts! expects a block { ... }");
        return TokenStream::from(quote! { #block });
    }
}

/// Integer obfuscation with reversible operation chains.
/// Usage: `obf_int!(42u32)`
#[proc_macro]
pub fn obf_int(input: TokenStream) -> TokenStream {
    #[cfg(feature = "literal_obf")]
    {
        let parsed = parse_macro_input!(input as obf::integer::ObfIntInput);
        return TokenStream::from(obf::integer::obf_int_impl(parsed));
    }
    #[cfg(not(feature = "literal_obf"))]
    {
        // Input is a typed integer literal (e.g., 42u32) — pass through as-is
        return input;
    }
}

/// Encrypted file embedding at compile time, decrypted at runtime.
/// Usage: `include_encrypted!("path/to/file.bin")`
/// AES mode: `include_encrypted!(aes, "path/to/file.bin")`
#[proc_macro]
pub fn include_encrypted(input: TokenStream) -> TokenStream {
    #[cfg(feature = "embed_encrypt")]
    {
        let parsed = parse_macro_input!(input as obf::embed::EmbedInput);
        return TokenStream::from(obf::embed::include_encrypted_impl(parsed));
    }
    #[cfg(not(feature = "embed_encrypt"))]
    {
        let input2: proc_macro2::TokenStream = input.into();
        let path = noop_parse_embed_path(input2);
        return TokenStream::from(quote! { include_bytes!(#path).to_vec() });
    }
}

/// Junk code injection attribute macro.
/// Usage: `#[junk]` or `#[junk(density = 3)]`
#[proc_macro_attribute]
pub fn junk(args: TokenStream, item: TokenStream) -> TokenStream {
    #[cfg(feature = "junk_insertion")]
    {
        return TokenStream::from(obf::junk::junk_impl(args.into(), item.into()));
    }
    #[cfg(not(feature = "junk_insertion"))]
    {
        let _ = args;
        return item;
    }
}

/// Derive macro for struct field obfuscation (AES-256-CTR shadow struct).
/// Usage: `#[derive(ObfuscateBox)]`
#[proc_macro_derive(ObfuscateBox)]
pub fn derive_obfuscate_box(input: TokenStream) -> TokenStream {
    #[cfg(feature = "struct_obf")]
    {
        let parsed = parse_macro_input!(input as syn::DeriveInput);
        return TokenStream::from(obf::derive_obf::derive_obfuscate_impl(parsed));
    }
    #[cfg(not(feature = "struct_obf"))]
    {
        let _ = input;
        return TokenStream::new();
    }
}

/// Drop-in replacement for `lazy_static!` using `OnceLock`.
/// Automatically applies literal obfuscation to initializer expressions.
/// Usage: `lazy_static! { static ref NAME: Type = expr; }`
#[proc_macro]
pub fn lazy_static(input: TokenStream) -> TokenStream {
    TokenStream::from(lazy_static_impl::lazy_static_impl(input.into()))
}

/// In-place XOR struct obfuscation derive macro.
/// Usage: `#[derive(Obfuscate)]`
#[proc_macro_derive(Obfuscate, attributes(obf))]
pub fn derive_obfuscate(input: TokenStream) -> TokenStream {
    #[cfg(feature = "inplace_obf")]
    {
        let parsed = parse_macro_input!(input as syn::DeriveInput);
        return TokenStream::from(obf::derive_inplace_obf::derive_impl(parsed));
    }
    #[cfg(not(feature = "inplace_obf"))]
    {
        let _ = input;
        return TokenStream::new();
    }
}

/// Conditional Debug/Obfuscate derive macro.
/// - **Debug builds**: generates standard `impl Debug`
/// - **Release builds** (with obf features): generates `unsafe impl Obfuscatable`
/// Usage: `#[derive(ObfDebug)]`
#[proc_macro_derive(ObfDebug, attributes(obf))]
pub fn derive_obf_debug(input: TokenStream) -> TokenStream {
    #[cfg(feature = "_obf_impl")]
    {
        let parsed = parse_macro_input!(input as syn::DeriveInput);
        return TokenStream::from(obf::obf_debug::derive_obf_debug_impl(parsed));
    }
    #[cfg(not(feature = "_obf_impl"))]
    {
        // Community: generate a basic Debug impl
        let parsed = parse_macro_input!(input as syn::DeriveInput);
        return TokenStream::from(noop_debug_impl(parsed));
    }
}

/// Function/impl-level attribute macro for automatic literal obfuscation.
/// Usage: `#[obfuscate]`, `#[obfuscate(flow)]`, `#[obfuscate(junk = N)]`
#[proc_macro_attribute]
pub fn obfuscate(args: TokenStream, item: TokenStream) -> TokenStream {
    #[cfg(feature = "_obf_impl")]
    {
        return TokenStream::from(obf::obfuscate_attr::obfuscate_attr_impl(
            args.into(),
            item.into(),
        ));
    }
    #[cfg(not(feature = "_obf_impl"))]
    {
        let _ = args;
        return item;
    }
}

// ============================================================================
// Community no-op helpers (no dependency on obf/)
// ============================================================================

/// Parse the path from `include_encrypted!` input without the obf/ module.
/// Handles both `include_encrypted!("path")` and `include_encrypted!(aes, "path")`.
#[cfg(not(feature = "embed_encrypt"))]
fn noop_parse_embed_path(input: proc_macro2::TokenStream) -> LitStr {
    syn::parse2::<LitStr>(input.clone()).unwrap_or_else(|_| {
        // Has mode prefix (aes/xor) — skip ident and comma
        let mut iter = input.into_iter();
        iter.next(); // skip ident
        iter.next(); // skip comma
        let rest: proc_macro2::TokenStream = iter.collect();
        syn::parse2::<LitStr>(rest).expect("include_encrypted! expects a string path")
    })
}

/// Generate a basic `impl Debug` for community mode (no obfuscation).
#[cfg(not(feature = "_obf_impl"))]
fn noop_debug_impl(input: syn::DeriveInput) -> proc_macro2::TokenStream {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    quote! {
        impl #impl_generics ::core::fmt::Debug for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!(#name)).finish()
            }
        }
    }
}
