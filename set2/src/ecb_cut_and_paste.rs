/// https://cryptopals.com/sets/2/challenges/13
use crate::ecb_cbc_oracle::encrypt_aes_ecb;
use set1::aes_ecb_mode::{aes_ecb_decrypt, remove_pad};
use std::collections::HashMap;

const BLOCK_SIZE: usize = 16;

fn parse_cookie(cookie: &str) -> HashMap<String, String> {
    cookie
        .split('&')
        .map(|kv| kv.split_once('=').unwrap())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn profile_for(email: &str) -> String {
    let email = email.replace("&", "").replace("=", "");
    format!("email={email}&uid=10&role=user")
}

fn encrypt_user(email: &str, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let profile = profile_for(email);
    encrypt_aes_ecb(profile.as_bytes(), key)
}

fn decrypt_user(encrypted: &[u8], key: [u8; BLOCK_SIZE]) -> HashMap<String, String> {
    let mut encrypted = encrypted.to_vec();
    aes_ecb_decrypt(&mut encrypted, key);
    parse_cookie(&String::from_utf8_lossy(remove_pad(&encrypted)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecb_cbc_oracle::random_aes_key;
    use crate::pkcs7::pad_pkcs7;

    #[test]
    fn cookie_parser() {
        let parsed: HashMap<String, String> = [("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(parsed, parse_cookie("foo=bar&baz=qux&zap=zazzle"));
    }

    #[test]
    fn profiler_preparator() {
        assert_eq!(
            profile_for("foo@bar.com"),
            "email=foo@bar.com&uid=10&role=user"
        );
        assert_eq!(
            profile_for("foo@bar.com&role=admin"),
            "email=foo@bar.comroleadmin&uid=10&role=user"
        );
    }

    #[test]
    fn ecnrypt_decrypt_user() {
        let key = random_aes_key();
        let encrypted = encrypt_user("foo@bar.com", key);
        let parsed: HashMap<String, String> =
            [("email", "foo@bar.com"), ("uid", "10"), ("role", "user")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        assert_eq!(decrypt_user(&encrypted, key), parsed);
    }

    #[test]
    fn make_admin() {
        // finding block size via padding
        fn discover_block_size() -> usize {
            let key = random_aes_key();
            let encrypted = encrypt_user("", key);
            let prev_len = encrypted.len();
            let mut current_len = prev_len;
            let mut i = 0;
            while prev_len == current_len {
                i += 1;
                let encrypted = encrypt_user(&"a".repeat(i), key);
                current_len = encrypted.len();
            }
            current_len - prev_len
        }

        let block_size = discover_block_size();
        assert_eq!(BLOCK_SIZE, block_size);

        let key = random_aes_key();

        let first_block_pad = "A".repeat(block_size - "email=".len());
        let replacement_block_bytes = pad_pkcs7(b"admin", block_size);
        let replacement_block = String::from_utf8_lossy(&replacement_block_bytes);
        let middle_stub = "A".repeat(block_size - "&uid=10&role=".len());

        let input = format!("{first_block_pad}{replacement_block}{middle_stub}");
        // second block with with role `admin` and padding encrypted - we will use it for replacement
        let encrypted_replacement = &encrypt_user(&input, key)[block_size..2 * block_size];

        // now we want to input as many bytes as needed to make the last block start with `user`
        let email = "A".repeat(2 * block_size - "email=".len() - "&uid=10&role=".len());
        // so the third block contains the `user`, while first two blocks contain the rest
        let mut encrypted = encrypt_user(&email, key);

        // now just replace the contents of the third block
        (&mut encrypted[2 * block_size..3 * block_size]).copy_from_slice(encrypted_replacement);
        let user = decrypt_user(&encrypted, key);

        let target: HashMap<String, String> =
            [("email", email.as_str()), ("uid", "10"), ("role", "admin")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        println!("{user:?}");

        assert_eq!(user, target);
    }
}
