/// https://cryptopals.com/sets/5/challenges/34

#[cfg(test)]
mod tests {
    use crate::diffie_hellman::*;
    use crypto_bigint::{Encoding, U1536};
    use set2::cbc_mode::{cbc, cbc_decrypt_inplace, BLOCK_SIZE};
    use set2::ecb_cbc_oracle::random_aes_key;
    use set4::sha1::Sha1;

    #[test]
    fn predictability_of_the_key() {
        // predicatbility of the session key when the public key is modulus p
        // p**a % p is 0 where a is any private key as p raised to any power is divisable by p itself
        assert_eq!(
            U1536::from(0u8),
            derive_session_key(U1536::from_be_hex(MODULUS), generate_private_key())
        );
    }

    #[test]
    fn mitm_dh_key_fixing_attack() {
        // Because the public keys used are just modulus p so the session key is 0
        let session_key = U1536::from(0u8);
        let mut hasher = Sha1::new();
        hasher.update(&session_key.to_be_bytes());
        let hash: [u8; 20] = hasher.finalize().into();
        let aes_key: [u8; BLOCK_SIZE] = hash[..BLOCK_SIZE].try_into().unwrap();
        let iv = random_aes_key();
        let msg = b"A's message";
        // A sends its ecnrypted message (via M)
        let (encrypted, iv) = (cbc(msg, aes_key, iv), iv);
        // M is able to decrypt as it knows session key
        // (see the test `predictability_of_the_key`) and
        // is able to derive aes key
        let mut decrypted = encrypted.clone();
        cbc_decrypt_inplace(&mut decrypted, aes_key, iv);
        assert!(decrypted.starts_with(msg)); // account for padding
                                             // B sends A's msg back to A (via M)
        let iv = random_aes_key();
        let (encrypted, iv) = (cbc(msg, aes_key, iv), iv);
        // M is able to decrypt as it knows session key and
        // is able to derive aes key
        let mut decrypted = encrypted.clone();
        cbc_decrypt_inplace(&mut decrypted, aes_key, iv);
    }
}
