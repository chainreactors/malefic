use crate::config::MetaData;
use crate::RESOURCES_DIR;
use crate::{log_info, log_step, log_success};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub fn update_resources(metadata: &MetaData) {
    log_step!("Updating resource configuration...");
    let base_filepath = Path::new(RESOURCES_DIR);
    let resource_filepath = base_filepath.join("malefic.rc");

    // 生成RC文件内容
    let mut rc_content = String::new();

    // 如果需要权限，先生成manifest
    if metadata.require_admin || metadata.require_uac {
        log_info!("Generating manifest file for elevated privileges");
        let mut manifest = String::new();
        manifest.push_str(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
"#,
        );

        if metadata.require_admin {
            manifest.push_str(r#"            <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>"#);
            log_info!("Setting requireAdministrator privilege level");
        } else if metadata.require_uac {
            manifest.push_str(r#"            <requestedExecutionLevel level="highestAvailable" uiAccess="false"/>"#);
            log_info!("Setting highestAvailable privilege level");
        }

        manifest.push_str(
            r#"
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
"#,
        );

        // 将manifest写入文件
        let manifest_path = base_filepath.join("app.manifest");
        fs::write(&manifest_path, manifest).expect("Failed to write manifest file");
        log_success!(
            "Manifest file has been created at: {}",
            manifest_path.display()
        );

        rc_content.push_str("1 24 \"app.manifest\"\n\n");
    }

    // 添加图标
    if !metadata.icon.is_empty() {
        rc_content.push_str(&format!("1 ICON \"{}\"\n", metadata.icon));
    }

    // 添加版本信息
    rc_content.push_str("#define VER_FILEVERSION 1,0,0,0\n");
    rc_content.push_str("#define VER_FILEVERSION_STR \"1.0.0.0\"\n");
    rc_content.push_str("#define VER_PRODUCTVERSION 1,0,0,0\n");
    rc_content.push_str("#define VER_PRODUCTVERSION_STR \"1.0.0.0\"\n\n");

    rc_content.push_str("1 VERSIONINFO\n");
    rc_content.push_str("FILEVERSION VER_FILEVERSION\n");
    rc_content.push_str("PRODUCTVERSION VER_PRODUCTVERSION\n");
    rc_content.push_str("FILEFLAGSMASK 0x3fL\n");
    rc_content.push_str("FILEFLAGS 0x0L\n");
    rc_content.push_str("FILEOS 0x40004L\n");
    rc_content.push_str("FILETYPE 0x1L\n");
    rc_content.push_str("FILESUBTYPE 0x0L\n");
    rc_content.push_str("BEGIN\n");
    rc_content.push_str("    BLOCK \"StringFileInfo\"\n");
    rc_content.push_str("    BEGIN\n");
    rc_content.push_str("        BLOCK \"040904E4\"\n");
    rc_content.push_str("        BEGIN\n");

    // 定义所有可能的版本信息字段
    let version_fields = if !metadata.compile_time.is_empty() {
        vec![
            ("Comments", metadata.compile_time.clone()),
            ("CompileDate", metadata.compile_time.clone()),
            ("FileVersion", metadata.file_version.clone()),
            ("ProductVersion", metadata.product_version.clone()),
            ("CompanyName", metadata.company_name.clone()),
            ("ProductName", metadata.product_name.clone()),
            ("OriginalFilename", metadata.original_filename.clone()),
            ("FileDescription", metadata.file_description.clone()),
            ("InternalName", metadata.internal_name.clone()),
            (
                "LegalCopyright",
                format!(
                    "Copyright {} {}",
                    metadata.company_name,
                    metadata
                        .compile_time
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                ),
            ),
        ]
    } else {
        vec![
            ("FileVersion", metadata.file_version.clone()),
            ("ProductVersion", metadata.product_version.clone()),
            ("CompanyName", metadata.company_name.clone()),
            ("ProductName", metadata.product_name.clone()),
            ("OriginalFilename", metadata.original_filename.clone()),
            ("FileDescription", metadata.file_description.clone()),
            ("InternalName", metadata.internal_name.clone()),
        ]
    };

    // 添加非空的字段
    for (field_name, field_value) in version_fields.iter() {
        if !field_value.is_empty() {
            rc_content.push_str(&format!(
                "            VALUE \"{}\", \"{}\"\n",
                field_name, field_value
            ));
        }
    }

    rc_content.push_str("        END\n");
    rc_content.push_str("    END\n");
    rc_content.push_str("    BLOCK \"VarFileInfo\"\n");
    rc_content.push_str("    BEGIN\n");
    rc_content.push_str("        VALUE \"Translation\", 0x409, 1252\n");
    rc_content.push_str("    END\n");
    rc_content.push_str("END\n");

    // 写入RC文件
    let mut file = File::create(&resource_filepath).expect("Failed to create resource file");
    file.write_all(rc_content.as_bytes())
        .expect("Failed to write resource file");

    log_success!(
        "Resource file has been created at: {}",
        resource_filepath.display()
    );
}
