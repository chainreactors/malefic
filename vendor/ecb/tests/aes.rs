#[cfg(feature = "block-padding")]
#[cfg(test)]
mod tests {

    #[test]
    fn ecb_aes128() {
        use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyInit};
        use ecb::{Decryptor, Encryptor};

        let key = include_bytes!("data/aes128.key.bin");
        let plaintext = include_bytes!("data/aes128.plaintext.bin");
        let ciphertext = include_bytes!("data/ecb-aes128.ciphertext.bin");

        type Aes128EcbEnc = Encryptor<aes::Aes128>;
        type Aes128EcbDec = Decryptor<aes::Aes128>;

        let mut buf = *plaintext;
        let pt_len = buf.len();

        let mode = Aes128EcbEnc::new(key.into());

        assert_eq!(
            mode.encrypt_padded_mut::<NoPadding>(&mut buf, pt_len)
                .unwrap(),
            &ciphertext[..]
        );

        let mut buf = *ciphertext;
        let mode = Aes128EcbDec::new(key.into());

        assert_eq!(
            mode.decrypt_padded_mut::<NoPadding>(&mut buf).unwrap(),
            &plaintext[..]
        );
    }
}
