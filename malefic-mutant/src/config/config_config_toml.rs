use std::fs;
use std::io::{self, Write};
use std::path::Path;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use toml_edit::{DocumentMut, Array, Item, Value, Table};

fn find_rs_files(dir: &Path, rustflags: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().unwrap_or_default() == "rs" {
            let relative_path = path.strip_prefix(std::env::current_dir()?).unwrap().to_path_buf();
            let remapped_path = remap_path_with_random(&relative_path);
            rustflags.push(remapped_path);
        } else if path.is_dir() {
            find_rs_files(&path, rustflags)?;
        }
    }
    Ok(())
}
fn find_rs_files_in_malefic_dirs(dir: &Path, rustflags: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with("malefic") && file_name != "malefic-mutant" {
                    find_rs_files(&path, rustflags)?;
                }
            }
        }
    }
    Ok(())
}
fn remap_path_with_random(path: &Path) -> String {
    let random_str: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let relative_path_str = path.to_str().unwrap_or("").replace("\\", "\\");
    if relative_path_str.ends_with(".rs") {
        format!("--remap-path-prefix={}={}.rs", relative_path_str, random_str)
    } else{
        format!("--remap-path-prefix={}={}", relative_path_str, random_str)
    }
}

fn remap_cargo_home(rustflags: &mut Vec<String>) {
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        let remap_flag = remap_path_with_random(Path::new(&cargo_home));
        rustflags.push(remap_flag);
    }
}

pub fn update_config_toml() {
    // init rustflags
    let mut rustflags = vec![];

    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    find_rs_files_in_malefic_dirs(&current_dir, &mut rustflags).expect("Failed to find rs files");
    remap_cargo_home(&mut rustflags);
    // create new array to store rustflags
    let mut rustflags_array = Array::new();
    for flag in &rustflags {
        rustflags_array.push(Value::from(flag.clone()));
    }

    let config_path = Path::new(".cargo/config.toml");
    let mut existing_content = String::new();

    if config_path.exists() {
        existing_content = fs::read_to_string(config_path).expect("Failed to read config.toml file");
    }


    let mut doc = existing_content.parse::<DocumentMut>().unwrap_or_default();
    // target.'cfg(any(target_family = "windows", target_family = "unix", target_family="wasm"))'
    let target_key = "target";
    let cfg_any_key = "cfg(any(target_family = \"windows\", target_family = \"unix\", target_family=\"wasm\"))";

    if ! doc[target_key].as_table_mut().unwrap().contains_key(cfg_any_key) {
        doc[target_key][cfg_any_key] = Item::Table(Table::new());
    }

    doc[target_key][cfg_any_key]["rustflags"] = Item::Value(Value::Array(rustflags_array.clone()));

    if let Ok(mut file) = fs::File::create(config_path) {
        if let Err(e) = file.write_all(doc.to_string().as_bytes()) {
            eprintln!("Failed to write updated content to config.toml: {:?}", e);
        } else {
            println!("config.toml file at \".cargo/config.toml\" has been updated successfully.");
        }
    } else {
        eprintln!("Failed to create config.toml file at \".cargo/config.toml\"");
    }

    // println!("Final config.toml content:\n{}", doc.to_string());
}
