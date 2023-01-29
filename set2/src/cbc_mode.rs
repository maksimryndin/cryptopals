/// https://cryptopals.com/sets/2/challenges/10
use crate::pkcs7::pad_pkcs7;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use set1::fixed_xor::xor_inplace;
const BLOCK_SIZE: usize = 16;

pub fn cbc_inplace(data: &mut [u8], key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) {
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);
    data.chunks_mut(BLOCK_SIZE).fold(iv, |prev_block, block| {
        xor_inplace(block, &prev_block);
        let b: [u8; BLOCK_SIZE] = block.try_into().unwrap();
        let mut b = GenericArray::from(b);
        cipher.encrypt_block(&mut b);
        block.swap_with_slice(&mut b);
        block.try_into().unwrap()
    });
}

pub fn cbc_decrypt_inplace(data: &mut [u8], key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) {
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);
    data.chunks_mut(BLOCK_SIZE).fold(iv, |prev_block, block| {
        let b: [u8; BLOCK_SIZE] = block.try_into().unwrap();
        let mut b = GenericArray::from(b);
        cipher.decrypt_block(&mut b);
        xor_inplace(&mut b, &prev_block);
        block.swap_with_slice(&mut b);
        b.try_into().unwrap()
    });
}

pub fn cbc(data: &[u8], key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut buffer = pad_pkcs7(data, BLOCK_SIZE);
    cbc_inplace(&mut buffer, key, iv);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use set1::helpers::read_b64_encoded;
    use std::path::PathBuf;

    #[test]
    fn basic_cbc() {
        let mut data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 3, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 2, 2, 3,
            4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ];

        let original = data.clone();
        let key: [u8; BLOCK_SIZE] = *b"YELLOW SUBMARINE";
        let iv = [0_u8; BLOCK_SIZE];
        cbc_inplace(&mut data, key, iv);
        cbc_decrypt_inplace(&mut data, key, iv);
        assert_eq!(original, data);
    }

    #[test]
    fn challenge_file_cbc() {
        let file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "data", "aes_cbc.txt"]
            .iter()
            .collect();
        let mut data = read_b64_encoded(file);
        let key: [u8; BLOCK_SIZE] = *b"YELLOW SUBMARINE";
        let iv = [0_u8; BLOCK_SIZE];
        cbc_decrypt_inplace(&mut data, key, iv);
        assert!(String::from_utf8(data)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));
    }
}
