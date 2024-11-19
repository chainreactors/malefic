pub mod srdi;
pub mod pulse;

static PANIC: &str = r#"
use core::panic::PanicInfo;

#[inline(never)]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
"#;