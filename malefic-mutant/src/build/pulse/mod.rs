use crate::{GenerateArch, PulseConfig, TransportProtocolType, Version};

mod tcp;
mod http;
mod utils;


pub fn pulse_generate(
    config: PulseConfig,
    arch: GenerateArch,
    version: Version,
    source: bool,
) -> anyhow::Result<()> {
    match config.protocol.parse()? {
        TransportProtocolType::Tcp => {
            tcp::generate_tcp_pulse(config, arch, &version, source)
        }
        TransportProtocolType::Http => {
            http::generate_http_pulse(config, arch, &version, source)
        }
        // _ => {
        //     anyhow::bail!("Unsupported pulse type.");
        // }
    }
}

pub fn djb2_hash(data: &String) -> u64 {
    let mut hash = 5381;
    for c in data.chars() {
        hash = ((hash << 5) + hash) + c as u64;
    }
    hash
}

static PANIC: &str = r#"
use core::panic::PanicInfo;

#[inline(never)]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
"#;