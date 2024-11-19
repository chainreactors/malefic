use std::fs;

use toml_edit::DocumentMut;

lazy_static!(
    static ref CONFIG_MODULE_TOML_PATH: String = "malefic-modules/Cargo.toml".to_string();
);
pub fn update_module_toml(modules: &[String]) {
    let module_toml_content = fs::read_to_string(CONFIG_MODULE_TOML_PATH.clone())
        .expect("Failed to read Cargo.toml file");

    let mut module_toml: DocumentMut = module_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");

    if let Some(features) = module_toml["features"].as_table_mut() {
        let mut new_default = toml_edit::Array::new();

        for module in modules {
            new_default.push(module);
        }

        features["default"] = toml_edit::Item::Value(new_default.into());
    } else {
        panic!("Failed to find 'features' in Cargo.toml.");
    }

    fs::write(CONFIG_MODULE_TOML_PATH.clone(), module_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");

    println!("{:#?} has been successfully updated.", CONFIG_MODULE_TOML_PATH.clone());
}
