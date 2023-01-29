/// https://cryptopals.com/sets/2/challenges/11
use crate::cbc_mode::cbc;
use crate::pkcs7::pad_pkcs7;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

const BLOCK_SIZE: usize = 16;

#[derive(PartialEq)]
pub enum BlockMode {
    ECB,
    CBC,
}

pub fn ecb_inplace(data: &mut [u8], key: [u8; BLOCK_SIZE]) {
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);
    data.chunks_exact_mut(BLOCK_SIZE).for_each(|b| {
        let block: [u8; BLOCK_SIZE] = b.try_into().unwrap();
        let mut block = GenericArray::from(block);
        cipher.encrypt_block(&mut block);
        b.swap_with_slice(&mut block);
    });
}

pub fn encrypt_aes_ecb(plaintext: &[u8], key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut buffer = pad_pkcs7(plaintext, BLOCK_SIZE);
    ecb_inplace(&mut buffer, key);
    buffer
}

pub fn random_aes_key() -> [u8; BLOCK_SIZE] {
    let mut buf = [0u8; BLOCK_SIZE];
    getrandom::getrandom(&mut buf).expect("failed to obtain random data");
    buf
}

pub fn rand_range(start: u8, end: u8) -> u8 {
    let mut buf = [0u8; 1];
    getrandom::getrandom(&mut buf).expect("failed to obtain random data");
    start + buf[0] % (end - start)
}

pub fn flip_coin() -> bool {
    let mut buf = [0u8; 1];
    getrandom::getrandom(&mut buf).expect("failed to obtain random data");
    buf[0] % 2 != 0
}

pub fn encryption_oracle(plaintext: &[u8]) -> (BlockMode, Vec<u8>) {
    let prepend_size = rand_range(5, 11) as usize;
    let append_size = rand_range(5, 11) as usize;
    let prepend = &random_aes_key()[..prepend_size];
    let append = &random_aes_key()[..append_size];
    let plain: Vec<u8> = prepend
        .iter()
        .chain(plaintext.iter())
        .chain(append.iter())
        .cloned()
        .collect();

    let key = random_aes_key();
    if flip_coin() {
        (BlockMode::CBC, cbc(&plain, key, random_aes_key()))
    } else {
        (BlockMode::ECB, encrypt_aes_ecb(&plain, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use set1::aes_ecb_mode::aes_ecb_decrypt;
    use set1::detect_aes_ecb::detect_aes_ecb_pattern;

    #[test]
    fn range_random() {
        let n = rand_range(5, 10);
        assert!(n < 10);
        assert!(n >= 5);
    }

    #[test]
    fn aes_ecb() {
        let plaintext = b"Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.";
        let key = b"YELLOW SUBMARINE";
        let mut encrypted = encrypt_aes_ecb(plaintext, *key);
        aes_ecb_decrypt(&mut encrypted, *key);
        assert_eq!(plaintext, &encrypted[..plaintext.len()]);
    }

    #[test]
    fn oracle() {
        for _ in 0..1000 {
            // worst case - 5 random bytes and we need 11 bytes of plaintext
            // to form the first block. After the first "dirty" block we need
            // two blocks of plaintext (32 bytes). So, 43 bytes of plaintext are required
            let plaintext = "a".repeat(43);
            let (mode, encrypted) = encryption_oracle(plaintext.as_bytes());
            let is_ecb = detect_aes_ecb_pattern(&encrypted);
            assert_eq!(is_ecb, mode == BlockMode::ECB);
        }
    }
}
