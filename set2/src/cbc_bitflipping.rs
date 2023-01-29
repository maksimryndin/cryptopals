/// https://cryptopals.com/sets/2/challenges/16
use crate::cbc_mode::{cbc, cbc_decrypt_inplace};
use crate::pkcs7_padding_validation::validate_pkcs7_padding;
pub const BLOCK_SIZE: usize = 16;

fn encrypt_userdata(userdata: &str, key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let input = userdata.replace(";", "%3B").replace("=", "%3D");
    let plaintext = format!("comment1=cooking%20MCs;userdata={input};comment2=%20like%20a%20pound%20of%20bacon");
    cbc(plaintext.as_bytes(), key, iv) 
}

fn check_admin(ciphertext: &[u8], key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) -> Result<bool, String> {
    let mut decrypted = ciphertext.to_vec();
    cbc_decrypt_inplace(&mut decrypted, key, iv);
    let without_pad = validate_pkcs7_padding(&decrypted)?;
    let plaintext = String::from_utf8_lossy(&without_pad);
    Ok(plaintext.find(";admin=true;").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecb_cbc_oracle::random_aes_key;

    #[test]
    fn check_quoting() {
        let key = random_aes_key();
        let iv = random_aes_key();
        let encrypted = encrypt_userdata("admin=true", key, iv);
        assert!(!check_admin(&encrypted, key, iv).unwrap());
    }

    #[test]
    fn flipbit() {
        println!("original `=`: {:#010b}", b'=');
        println!("flipping last bit: {:#010b}, as char {}", b'=' ^ 1, (b'=' ^ 1) as char);
        assert_eq!('<', (b'=' ^ 1) as char);
        println!("flipping second from the end bit: {:#010b}, as char {}", b'=' ^ 1 << 1, (b'=' ^ 1 << 1) as char);
        assert_eq!('?', (b'=' ^ 1 << 1) as char);
    }

    #[test]
    fn cbc_attack() {
        let key = random_aes_key();
        let iv = random_aes_key();

        fn discover_block_size() -> usize {
            let key = random_aes_key();
            let iv = random_aes_key();
            let length = encrypt_userdata("", key, iv).len();
            let mut curr_length = length;
            let mut i = 0;
            while curr_length == length {
                i += 1;
                curr_length = encrypt_userdata(&"A".repeat(i), key, iv).len();
            }
            curr_length - length
        }

        let block_size = discover_block_size();
        assert_eq!(BLOCK_SIZE, block_size);

        fn discover_prefix_len(block_size: usize) -> usize {

            fn get_common_len<'a>(first: &[u8], second: &[u8]) -> usize {
                first.iter().zip(second.iter()).take_while(|(&a, &b)| a == b).count()
            }

            let key = random_aes_key();
            let iv = random_aes_key();
            let mut max_common_len: usize = 0;
            let mut pad = 0;
            for i in 0..block_size {
                let common = "A".repeat(i);
                let left = encrypt_userdata(&format!("{common}X"), key, iv);
                let right = encrypt_userdata(&format!("{common}Y"), key, iv);
                let common_len = get_common_len(&left, &right);
                if common_len > max_common_len {
                    max_common_len = common_len;
                    pad = i;
                }
            }
            assert_eq!(max_common_len % block_size, 0);
            max_common_len - pad
        }

        let prefix_len = discover_prefix_len(block_size);
        assert_eq!(b"comment1=cooking%20MCs;userdata=".len(), prefix_len);
        println!("prefix length: {prefix_len}");
        // prefix length is 32.
        // so our input starts the third block
        // we can flip bits for corresponding bytes in the previous block which is xored
        // with the decrypted third block
        
        let input = format!("{}admin{}true", (b';' ^ 1) as char, (b'=' ^ 1) as char);
        let mut encrypted = encrypt_userdata(&input, key, iv);
        encrypted[16] = encrypted[16] ^ 1;
        encrypted[22] = encrypted[22] ^ 1;
        assert!(check_admin(&encrypted, key, iv).unwrap())
    }
}