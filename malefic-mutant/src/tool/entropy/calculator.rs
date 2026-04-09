/// Shannon entropy calculation for byte sequences.

/// Calculate Shannon entropy of a byte slice.
/// Returns a value between 0.0 (perfectly uniform, e.g. all zeros) and 8.0 (perfectly random).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_zeros() {
        let data = vec![0u8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_all_same_byte() {
        let data = vec![0xAA; 512];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_uniform_distribution() {
        // All 256 byte values equally distributed
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let entropy = shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_two_values() {
        // Equal distribution of 2 values -> entropy = 1.0
        let data: Vec<u8> = (0..1000).map(|i| if i % 2 == 0 { 0 } else { 1 }).collect();
        let entropy = shannon_entropy(&data);
        assert!((entropy - 1.0).abs() < 0.01);
    }
}
