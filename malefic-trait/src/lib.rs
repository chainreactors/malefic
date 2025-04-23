extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse::Parse, parse::ParseStream, parse_macro_input, ItemImpl, LitStr};

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

    let name_method = quote! {
        fn name() -> &'static str {
            static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            NAME.get_or_init(|| obfstr::obfstr!(#module_name).to_string()).as_str()
        }
    };
    let new_method = quote! {
        fn new() -> Self {
            // let (sender, receiver) = tokio::sync::mpsc::channel(2);
            Self {
                // channel: Channel {
                //     sender,
                //     receiver,
                // }
            }
        }
    };
    let new_instance_method = quote! {
        fn new_instance(&self) -> Box<dyn Module + Send + Sync + 'static> {
            Box::new(Self::new())
        }
    };
    // let sender_method = quote! {
    //     fn sender(&self) -> tokio::sync::mpsc::Sender<Body> {
    //         self.channel.sender.clone()
    //     }
    // };

    // input.items.push(syn::parse2(sender_method).unwrap());
    input.items.push(syn::parse2(new_instance_method).unwrap());
    input.items.push(syn::parse2(new_method).unwrap());
    input.items.push(syn::parse2(name_method).unwrap());

    let expanded = quote! {
        #input
    };

    TokenStream::from(expanded)
}
