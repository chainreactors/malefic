#![no_std]
#![no_main]

// Force-link the lib crate so that stardust (the real entry point, set via
// -estardust linker flag) and all reachable code end up in the final binary.
extern crate malefic_pulse;

// Force the linker to include the lib's rlib (extern crate alone may not suffice)
#[used]
static _FORCE_LINK: unsafe extern "C" fn(*mut core::ffi::c_void) = malefic_pulse::entry;
