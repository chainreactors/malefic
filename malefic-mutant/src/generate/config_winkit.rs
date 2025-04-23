use std::fs;

use crate::{
    log_success, ImplantConfig, Version, CONFIG_INNER_TEMPLATE, CONFIG_PROFESSIONAL_TEMPLATE,
    DEFAULT, FEATURES,
};
use toml_edit::{Array, DocumentMut, Item};

lazy_static! {
    static ref ALLOCTOR: String = "Alloctor".to_string();
    static ref ALLOCTOR_EX: String = "AlloctorEx".to_string();
    static ref NORMAL: String = "NORMAL".to_string();
    static ref DYNAMIC: String = "DYNAMIC".to_string();
    static ref SYSCALLS: String = "SYSCALLS".to_string();
    static ref CONFIG_WINKIT_TOML_PATH: String = "malefic-win-kit/Cargo.toml".to_string();
    static ref CONFIG_FFI: String = "ffi".to_string();
    static ref CONFIG_FFI_APIS: String = "ffi_apis".to_string();
}

pub fn update_winkit_toml(implant_config: &ImplantConfig, version: &Version, source: bool) {
    let cargo_toml_content = fs::read_to_string(CONFIG_WINKIT_TOML_PATH.clone())
        .expect("Failed to read winkit Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content
        .parse()
        .expect("Failed to parse winkit Cargo.toml file");

    let mut default_array: toml_edit::Array = Array::default();
    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        if source {
            default_array.retain(|x| x.as_str().unwrap() != &CONFIG_FFI.clone());
            default_array.retain(|x| x.as_str().unwrap() != &CONFIG_FFI_APIS.clone());
        } else {
            if default_array
                .iter()
                .find(|x| x.as_str().unwrap() == &CONFIG_FFI.clone())
                .is_none()
            {
                default_array.push(CONFIG_FFI.clone());
            }
            if default_array
                .iter()
                .find(|x| x.as_str().unwrap() == &CONFIG_FFI_APIS.clone())
                .is_none()
            {
                default_array.push(CONFIG_FFI_APIS.clone());
            }
        }
        match version {
            Version::Community => {
                if default_array
                    .iter()
                    .find(|x| x.as_str().unwrap() == Version::Community.to_string())
                    .is_none()
                {
                    default_array.push(Version::Community.to_string());
                }
            }
            Version::Professional => {
                if default_array
                    .iter()
                    .find(|x| x.as_str().unwrap() == &Version::Professional.to_string())
                    .is_none()
                {
                    default_array.push(Version::Professional.to_string());
                }
                let template = features[&CONFIG_PROFESSIONAL_TEMPLATE]
                    .as_array_mut()
                    .unwrap();
                let mut real_config = template.clone();
                let real_config_len = real_config.len();
                for i in 0..6 {
                    real_config.remove(real_config_len - 1 - i);
                }
                real_config.push(ALLOCTOR.to_owned() + &implant_config.alloctor.inprocess.clone());
                real_config
                    .push(ALLOCTOR_EX.to_owned() + &implant_config.alloctor.crossprocess.clone());
                real_config.push(implant_config.apis.level.to_uppercase());
                if implant_config.apis.priority.normal.enable {
                    real_config.push(NORMAL.to_owned());
                    real_config.push(
                        implant_config
                            .apis
                            .priority
                            .normal
                            .r#type
                            .to_uppercase()
                            .clone(),
                    );
                } else if implant_config.apis.priority.dynamic.enable {
                    real_config.push(DYNAMIC.to_owned());
                    real_config.push(
                        implant_config
                            .apis
                            .priority
                            .dynamic
                            .r#type
                            .to_uppercase()
                            .clone(),
                    );
                } else if implant_config.apis.priority.syscalls.enable {
                    real_config.push(SYSCALLS.to_owned());
                    real_config.push(
                        implant_config
                            .apis
                            .priority
                            .syscalls
                            .r#type
                            .to_uppercase()
                            .clone(),
                    );
                }
                features[&Version::Community.to_string()] = Item::Value(real_config.into());
            }
            Version::Inner => {
                default_array.push(Version::Inner.to_string());
                let template = features[&CONFIG_INNER_TEMPLATE].as_array_mut().unwrap();
                let mut real_config = template.clone();
                let real_config_len = real_config.len();
                for i in 0..6 {
                    real_config.remove(real_config_len - 1 - i);
                }
                real_config.push(ALLOCTOR.to_owned() + &implant_config.alloctor.inprocess.clone());
                real_config
                    .push(ALLOCTOR_EX.to_owned() + &implant_config.alloctor.crossprocess.clone());
                real_config.push(implant_config.apis.level.to_uppercase());
                if implant_config.apis.priority.normal.enable {
                    real_config.push(NORMAL.to_owned());
                    real_config.push(
                        implant_config
                            .apis
                            .priority
                            .normal
                            .r#type
                            .to_uppercase()
                            .clone(),
                    );
                } else if implant_config.apis.priority.dynamic.enable {
                    real_config.push(DYNAMIC.to_owned());
                    real_config.push(
                        implant_config
                            .apis
                            .priority
                            .dynamic
                            .r#type
                            .to_uppercase()
                            .clone(),
                    );
                } else if implant_config.apis.priority.syscalls.enable {
                    real_config.push(SYSCALLS.to_owned());
                    real_config.push(
                        implant_config
                            .apis
                            .priority
                            .syscalls
                            .r#type
                            .to_uppercase()
                            .clone(),
                    );
                }
                features[&Version::Inner.to_string()] = Item::Value(real_config.into());
            }
        }
        features[&DEFAULT] = Item::Value(default_array.into());
    }

    fs::write(CONFIG_WINKIT_TOML_PATH.clone(), cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");

    log_success!(
        "Cargo.toml file {} has been updated",
        CONFIG_WINKIT_TOML_PATH.clone()
    );
}
