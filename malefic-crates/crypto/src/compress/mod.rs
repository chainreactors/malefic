use snap::raw::{Decoder, Encoder};
use std::io;

pub fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder
        .compress_vec(data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

pub fn decompress(compressed_data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = Decoder::new();
    decoder
        .decompress_vec(compressed_data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
