extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr, ItemImpl, parse::Parse, parse::ParseStream};

// 定义一个用于解析宏参数的辅助结构
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
    // 解析宏参数和输入项
    let args = parse_macro_input!(args as MacroArgs);
    let module_name = &args.module_name;
    let mut input = parse_macro_input!(item as ItemImpl);

    // 创建新的方法实现
    let name_method = quote! {
        fn name() -> &'static str {
            #module_name
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

    // 将新方法及name方法添加到impl块中

    // input.items.push(syn::parse2(sender_method).unwrap());
    input.items.push(syn::parse2(new_instance_method).unwrap());
    input.items.push(syn::parse2(new_method).unwrap());
    input.items.push(syn::parse2(name_method).unwrap());

    let expanded = quote! {
        #input
    };

    TokenStream::from(expanded)
}