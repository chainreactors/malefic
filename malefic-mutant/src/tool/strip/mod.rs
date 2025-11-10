use regex::bytes::Regex;
use std::fs::{read, write};

pub fn strip_paths_from_binary(
    input_path: &str,
    output_path: &str,
    custom_paths: &[String],
) -> anyhow::Result<()> {
    let contents = read(input_path)?;

    let mut patterns = vec![
        Regex::new(r"[A-Za-z]:\\[A-Za-z0-9_\\./\\-]*?\.rs")
            .expect("Invalid Windows .rs path regex"),
        Regex::new(r"/[A-Za-z0-9_\\./\\-]*?\.rs").expect("Invalid unix path regex"),
        Regex::new(r"malefic[A-Za-z0-9_\\./\\-]*?\.rs").expect("Invalid relative path regex"),
        Regex::new(r"[A-Za-z_-]*\\[A-Za-z0-9_\\./\\-]*?\.rs").expect("Invalid relative path regex"),
    ];

    for custom_path in custom_paths {
        patterns.push(Regex::new(&regex::escape(custom_path)).expect("Invalid custom path regex"));
    }

    let mut modified_bytes = contents.clone();
    let mut _total_replacements = 0;

    for pattern in patterns {
        // println!("Checking pattern: {}", pattern);

        let matches: Vec<_> = pattern.find_iter(&contents).collect();

        if !matches.is_empty() {
            // println!("  Found {} matches:", matches.len());
            // for (i, mat) in matches.iter().enumerate().take(5) {
            //     let match_str = String::from_utf8_lossy(mat.as_bytes());
            //     println!("    [{}] Replacing path: '{}'", i + 1, match_str);
            // }
            // if matches.len() > 5 {
            //     println!("    ... and {} more matches", matches.len() - 5);
            // }
            _total_replacements += matches.len();

            for mat in matches.iter().rev() {
                // 从后往前替换，避免位置偏移问题
                let start_byte = mat.start();
                let end_byte = mat.end();

                // 确保字节位置在有效范围内
                if end_byte <= modified_bytes.len() {
                    for i in start_byte..end_byte {
                        modified_bytes[i] = 0;
                    }
                }
            }
        } else {
            // println!("No matches found");
        }
    }

    // println!("\nTotal paths replaced: {}", total_replacements);

    // 写入输出文件
    write(output_path, &modified_bytes)?;
    println!("Successfully strip {} to {}", input_path, output_path);
    Ok(())
}
