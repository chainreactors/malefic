//! Unified random API.
//!
//! Backend selection via features (mutually exclusive by convention):
//! - `random_nanorand`: fast PRNG (WyRand)
//! - `random_getrandom`: OS cryptographic RNG
//!
//! If both are enabled, `getrandom` takes priority (crypto-safe).

// ---- Fill bytes ----

#[cfg(feature = "random_getrandom")]
pub fn fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS RNG unavailable");
}

#[cfg(all(feature = "random_nanorand", not(feature = "random_getrandom")))]
pub fn fill(buf: &mut [u8]) {
    use nanorand::Rng;
    nanorand::WyRand::new().fill_bytes(buf);
}

pub fn bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    fill(&mut buf);
    buf
}

pub fn random_u8() -> u8 {
    bytes::<1>()[0]
}

// ---- Range generation ----

#[cfg(all(feature = "random_nanorand", not(feature = "random_getrandom")))]
pub fn range_u64(low: u64, high: u64) -> u64 {
    use nanorand::Rng;
    nanorand::WyRand::new().generate_range(low..high)
}

#[cfg(all(feature = "random_nanorand", not(feature = "random_getrandom")))]
pub fn range_usize(low: usize, high: usize) -> usize {
    use nanorand::Rng;
    nanorand::WyRand::new().generate_range(low..high)
}

#[cfg(feature = "random_getrandom")]
pub fn range_u64(low: u64, high: u64) -> u64 {
    let raw = u64::from_le_bytes(bytes::<8>());
    low + raw % (high - low)
}

#[cfg(feature = "random_getrandom")]
pub fn range_usize(low: usize, high: usize) -> usize {
    range_u64(low as u64, high as u64) as usize
}
