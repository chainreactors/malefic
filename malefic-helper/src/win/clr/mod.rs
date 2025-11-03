#[cfg(feature = "clr")]
pub fn clr_version() ->  Vec<String> {

    #[cfg(feature = "source")]
    unsafe {
        return malefic_win_kit::clr::CSharpUtils::DisplayInstalledDotNetVersion();
    }
    #[cfg(feature = "prebuild")] {
        use crate::win::kit::bindings::CLRVersion;
        unsafe {
            let raw = CLRVersion();
            if raw.data.is_null() {
                return Vec::new();
            }

            let bytes = Vec::from_raw_parts(raw.data, raw.len, raw.capacity);
            let text = match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };

            return text
                .split('\n')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned())
                .collect();
        }
    }
    // return vec![];
}
#[cfg(not(feature = "clr"))]
pub fn clr_version() ->  Vec<String> {
    vec![]
}