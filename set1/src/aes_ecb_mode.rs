/// https://cryptopals.com/sets/1/challenges/7
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;

const BLOCK_SIZE: usize = 16;

pub fn aes_ecb_decrypt(encrypted: &mut [u8], key: [u8; BLOCK_SIZE]) {
    // data is padded properly
    assert_eq!(0, encrypted.len() % BLOCK_SIZE);
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);
    encrypted.chunks_mut(BLOCK_SIZE).for_each(|b| {
        let block: [u8; BLOCK_SIZE] = b.try_into().unwrap();
        let mut block = GenericArray::from(block);
        cipher.decrypt_block(&mut block);
        b.swap_with_slice(&mut block);
    });
}

pub fn remove_pad(decrypted: &[u8]) -> &[u8] {
    if let Some(pad_value) = decrypted.last() {
        let pad_length = decrypted.iter().rev().take_while(|&b| b == pad_value).count();
        let pad_value = *pad_value as usize;
        if pad_value == pad_length {
            &decrypted[..decrypted.len() - pad_length]
        } else {
            decrypted
        }
    } else {
        decrypted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::{filename_fullpath, read_b64_encoded};
    use std::process::Command;

    #[test]
    fn pad_remover() {
        let v = vec![3_u8, 1];
        assert_eq!(&v[..1], remove_pad(&v));
        let v = vec![3_u8, 2, 2];
        assert_eq!(&v[..1], remove_pad(&v));
        let v = vec![3_u8, 2, 3];
        assert_eq!(&v[..3], remove_pad(&v));
        let v = vec![3_u8, 2, 3];
        assert_eq!(&v[..3], remove_pad(&v));
    }

    #[test]
    fn aes_ecb_mode() {
        let file = filename_fullpath("aes_ecb.txt");
        let mut decoded = read_b64_encoded(file.clone());
        let openssl_decoded_output = Command::new("openssl")
            .arg("base64")
            .arg("-d")
            .arg("-in")
            .arg(file)
            .output()
            .expect("failed to decode b64 with openssl")
            .stdout;

        assert_eq!(openssl_decoded_output, decoded);

        aes_ecb_decrypt(&mut decoded, *b"YELLOW SUBMARINE");

        let openssl_output = Command::new("openssl")
            .arg("enc")
            .arg("-aes-128-ecb")
            .arg("-a")
            .arg("-d")
            .arg("-K")
            .arg("59454c4c4f57205355424d4152494e45")
            .arg("-in")
            .arg(filename_fullpath("aes_ecb.txt"))
            .output()
            .expect("failed to decipher with openssl")
            .stdout;

        assert_eq!(
            String::from_utf8(openssl_output).unwrap(),
            String::from_utf8(remove_pad(&decoded).to_vec()).unwrap()
        );
    }
}
