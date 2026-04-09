use core::ffi::c_void;

use crate::types::{
    BuildThreshold, WinVer, WIN32_WIN_NT_VISTA, WIN32_WIN_NT_WIN10, WIN32_WIN_NT_WIN7,
    WIN32_WIN_NT_WIN8, WIN32_WIN_NT_WINBLUE, WIN32_WIN_NT_WINXP,
};

#[macro_export]
macro_rules! ENUM {
    {enum $name:ident { $($variant:ident = $value:expr,)+ }} => {
        pub type $name = u32;
        $(pub const $variant: $name = $value;)+
    };
    {enum $name:ident { $variant:ident = $value:expr, $($rest:tt)* }} => {
        pub type $name = u32;
        pub const $variant: $name = $value;
        ENUM!{@gen $name $variant, $($rest)*}
    };
    {enum $name:ident { $variant:ident, $($rest:tt)* }} => {
        ENUM!{enum $name { $variant = 0, $($rest)* }}
    };
    {@gen $name:ident $base:ident,} => {};
    {@gen $name:ident $base:ident,
          $variant:ident = $value:expr, $($rest:tt)*} => {
        pub const $variant: $name = $value;
        ENUM!{@gen $name $variant, $($rest)*}
    };
    {@gen $name:ident $base:ident, $variant:ident, $($rest:tt)*} => {
        pub const $variant: $name = $base + 1u32;
        ENUM!{@gen $name $variant, $($rest)*}
    };
}

#[macro_export]
macro_rules! STRUCT {
    ($(#[$attrs:meta])* struct $name:ident {
        $($field:ident: $ftype:ty,)+
    }) => (
        #[repr(C)] #[derive(Copy)] $(#[$attrs])*
        pub struct $name {
            $(pub $field: $ftype,)+
        }
        impl Clone for $name {
            #[inline]
            fn clone(&self) -> $name { *self }
        }
    );
}

#[macro_export]
macro_rules! get_nt_header {
    ($base_addr: expr) => {{
        let dos_header = $base_addr as *mut winapi::um::winnt::IMAGE_DOS_HEADER;
        pointer_add($base_addr, (*dos_header).e_lfanew as _)
            as *mut winapi::um::winnt::IMAGE_NT_HEADERS
    }};
}

pub fn get_cstr_len(pointer: *const u8) -> usize {
    unsafe {
        (0..)
            .take_while(|&i| *(((pointer as usize) + i) as *const u8) != 0)
            .count()
    }
}

pub fn get_wcstr_len(pointer: *const u16) -> usize {
    unsafe {
        (0..)
            .take_while(|&i| *(((pointer as usize) + i) as *const u16) != 0)
            .count()
    }
}

pub unsafe fn srdi_memcpy(dest: *mut u8, src: *const u8, n: usize) {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
}

pub unsafe fn srdi_memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        if *s1.add(i) != *s2.add(i) {
            return *s1.add(i) as i32 - *s2.add(i) as i32;
        }
        i += 1;
    }
    0
}

pub unsafe fn srdi_memcpy_usize(dest: *mut c_void, src: usize) {
    *(dest as *mut usize) = src;
}

pub unsafe fn pointer_add<T>(base_point: *const T, offset: usize) -> *const c_void {
    return ((base_point as *const c_void) as usize + offset) as *const c_void;
}

pub unsafe fn pointer_sub<T>(base_point: *const T, offset: usize) -> *const c_void {
    return ((base_point as *const c_void) as usize - offset) as *const c_void;
}

pub unsafe fn srdi_memset(dest: *mut u8, value: u8, n: usize) {
    let mut i = 0;
    while i < n {
        *dest.add(i) = value;
        i += 1;
    }
}

#[inline]
pub fn LOBYTE(l: u16) -> u8 {
    (l & 0xff) as u8
}
#[inline]
pub fn HIBYTE(l: u16) -> u8 {
    ((l >> 8) & 0xff) as u8
}

pub fn dbj2_str_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter.lt(&buffer.len()) {
        cur = buffer[iter];

        if cur.eq(&0) {
            iter += 1;
            continue;
        }

        if cur.ge(&('a' as u8)) {
            cur -= 0x20;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }

    return hsh;
}

pub fn dbj2_hash(buffer: &[u16]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u16;

    while iter.lt(&buffer.len()) {
        cur = buffer[iter];

        if cur.eq(&0) {
            iter += 1;
            continue;
        }

        if cur.ge(&('a' as u16)) {
            cur -= 0x20;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
}

pub unsafe fn IsWindowsVersionOrGrearter(
    win_ver: &WinVer,
    major_version: u16,
    minor_version: u16,
    service_pack_major: u16,
    build_number: u16,
) -> bool {
    if win_ver.native.dwMajorVersion.eq(&0) {
        return false;
    }
    if win_ver.native.dwMajorVersion > major_version as _ {
        return true;
    }
    if win_ver.native.dwMajorVersion < major_version as _ {
        return false;
    }
    if win_ver.native.dwMinorVersion > minor_version as _ {
        return true;
    }
    if win_ver.native.dwMinorVersion < minor_version as _ {
        return false;
    }
    if win_ver.native.wServicePackMajor > service_pack_major {
        return true;
    }
    if win_ver.native.wServicePackMajor < service_pack_major {
        return false;
    }
    if win_ver.native.dwBuildNumber >= build_number as _ {
        return true;
    }

    false
}

pub unsafe fn IsWindowsXPOrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WINXP as u16) as _,
        LOBYTE(WIN32_WIN_NT_WINXP as u16) as _,
        0,
        0,
    )
}

pub unsafe fn IsWindowsXPSP1OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WINXP as u16) as _,
        LOBYTE(WIN32_WIN_NT_WINXP as u16) as _,
        1,
        0,
    )
}

pub unsafe fn IsWindowsXPSP2OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WINXP as u16) as _,
        LOBYTE(WIN32_WIN_NT_WINXP as u16) as _,
        2,
        0,
    )
}

pub unsafe fn IsWindowsXPSP3OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WINXP as u16) as _,
        LOBYTE(WIN32_WIN_NT_WINXP as u16) as _,
        3,
        0,
    )
}

pub unsafe fn IsWindowsVistaOrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_VISTA as u16) as _,
        LOBYTE(WIN32_WIN_NT_VISTA as u16) as _,
        0,
        0,
    )
}

pub unsafe fn IsWindowsVistaSP1OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_VISTA as u16) as _,
        LOBYTE(WIN32_WIN_NT_VISTA as u16) as _,
        1,
        0,
    )
}

pub unsafe fn IsWindowsVistaSP2OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_VISTA as u16) as _,
        LOBYTE(WIN32_WIN_NT_VISTA as u16) as _,
        2,
        0,
    )
}

pub unsafe fn IsWindows7OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN7 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN7 as u16) as _,
        0,
        0,
    )
}

pub unsafe fn IsWindows7SP1OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN7 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN7 as u16) as _,
        1,
        0,
    )
}

pub unsafe fn IsWindows8OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN8 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN8 as u16) as _,
        0,
        0,
    )
}

pub unsafe fn IsWindows8Point1OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WINBLUE as u16) as _,
        LOBYTE(WIN32_WIN_NT_WINBLUE as u16) as _,
        0,
        0,
    )
}

pub unsafe fn IsWindows10OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        0,
    )
}

pub unsafe fn IsWindows10RS1OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_RS1 as u16,
    )
}

pub unsafe fn IsWindows10RS2OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_RS2 as u16,
    )
}

pub unsafe fn IsWindows10RS3OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_RS3 as u16,
    )
}

pub unsafe fn IsWindows10RS4OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_RS4 as u16,
    )
}

pub unsafe fn IsWindows10RS5OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_RS5 as u16,
    )
}

pub unsafe fn IsWindows1019H1OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_19_H1 as u16,
    )
}

pub unsafe fn IsWindows1019H2OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_19_H2 as u16,
    )
}

pub unsafe fn IsWindows1020H1OrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_20_H1 as u16,
    )
}

pub unsafe fn IsWindows11BetaOrGreater(win_ver: &WinVer) -> bool {
    IsWindowsVersionOrGrearter(
        win_ver,
        HIBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        LOBYTE(WIN32_WIN_NT_WIN10 as u16) as _,
        0,
        BuildThreshold::BUILD_Win11Beta as u16,
    )
}

// #[no_mangle]
pub unsafe fn boyer_moore(
    start_addr: *const u8,
    size: usize,
    pattern: &[u8],
    search_len: usize,
) -> isize {
    if pattern.is_empty() || size == 0 || size < search_len || pattern.len() < search_len {
        return -1;
    }

    let mut bad_char_skip = [search_len; 256];
    for i in 0..search_len - 1 {
        bad_char_skip[pattern[i] as usize] = search_len - 1 - i;
    }

    let start = unsafe { core::slice::from_raw_parts(start_addr, size) };

    let mut i = 0;
    while i <= size - search_len {
        let mut j = (search_len - 1) as isize;

        while j >= 0 && pattern[j as usize] == start[i + j as usize] {
            j -= 1;
        }

        if j < 0 {
            return i as _;
        }

        let bad_char = start[i + j as usize];
        i += bad_char_skip[bad_char as usize].max(1);
    }

    -1
}
