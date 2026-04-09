#[cfg(feature = "prebuild")]
#[allow(warnings)]
pub(crate) mod binding;

/// C-compatible RawString matching both bindings::RawString and winkit ffi::RawString
#[repr(C)]
pub struct RawString {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl RawString {
    pub unsafe fn into_string(self) -> String {
        if self.data.is_null() || self.len == 0 {
            return String::new();
        }
        String::from_raw_parts(self.data, self.len, self.capacity)
    }

    pub unsafe fn into_bytes(self) -> Vec<u8> {
        self.into_string().into_bytes()
    }
}

/// Macro to generate source/prebuild dual-branch FFI dispatch.
///
/// For `prebuild`: calls `binding::$name` (bindgen-generated FFI).
/// For non-`prebuild`: calls `malefic_win_kit::ffi::$name` directly through Rust paths.
macro_rules! ffi_dispatcher {
    // Functions returning RawString (need field copy between crate-local types)
    (fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> RawString) => {
        #[allow(non_snake_case)]
        pub unsafe fn $name($($arg: $ty),*) -> $crate::kit::binding::RawString {
            #[cfg(feature = "prebuild")]
            {
                let r = $crate::kit::binding::binding::$name($($arg),*);
                $crate::kit::binding::RawString { data: r.data, len: r.len, capacity: r.capacity }
            }
            #[cfg(not(feature = "prebuild"))]
            {
                let r = malefic_win_kit::ffi::$name($($arg),*);
                $crate::kit::binding::RawString { data: r.data, len: r.len, capacity: r.capacity }
            }
        }
    };
    // Functions returning other types or void
    (fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?) => {
        #[allow(non_snake_case)]
        pub unsafe fn $name($($arg: $ty),*) $(-> $ret)? {
            #[cfg(feature = "prebuild")]
            { $crate::kit::binding::binding::$name($($arg),*) }
            #[cfg(not(feature = "prebuild"))]
            { malefic_win_kit::ffi::$name($($arg),*) }
        }
    };
}
pub(crate) use ffi_dispatcher;

// Auto-generated dispatch functions
include!(concat!(env!("OUT_DIR"), "/ffi_dispatch.rs"));
