use std::io::{self};
use snap::raw::{Decoder, Encoder};

pub fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    let compressed_data = encoder.compress_vec(data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(compressed_data)
}

pub fn decompress(compressed_data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = Decoder::new();
    let decompressed_data = decoder.decompress_vec(compressed_data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(decompressed_data)
}