/// https://cryptopals.com/sets/5/challenges/35

#[cfg(test)]
mod tests {
    use crate::diffie_hellman::*;
    use crypto_bigint::{Encoding, Integer, U1536};
    use set2::cbc_mode::{cbc, cbc_decrypt_inplace, BLOCK_SIZE};
    use set2::ecb_cbc_oracle::random_aes_key;
    use set4::sha1::Sha1;

    /// The attacks below assume that A uses 1, p, or p-1 as g parameter
    /// The boxed comments hints about it.
    /// Otherwise we just rely on a classic MITM attack

    #[test]
    fn predictability_of_the_key_with_g_equals_one() {
        // predicatbility of the session key when g=1
        // g**a % p is 1 where a is any private key as g=p raised to any power is 1
        assert_eq!(
            U1536::from(1u8),
            derive_public_key_with_g(generate_private_key(), U1536::from(1u8))
        );
        // that pubkey is raised to 1**b % p produces session key which is also 1
        assert_eq!(
            U1536::from(1u8),
            derive_session_key(U1536::from(1u8), generate_private_key())
        );
    }

    #[test]
    fn predictability_of_the_key_with_g_equals_p() {
        // predicatbility of the session key when g=p
        // p**a % p is 0 where a is any private key as p raised to any power is divisable by p itself
        assert_eq!(
            U1536::from(0u8),
            derive_public_key_with_g(generate_private_key(), U1536::from_be_hex(MODULUS))
        );
        // that pubkey is raised to 0**b % p produces session key which is also 0
        assert_eq!(
            U1536::from(0u8),
            derive_session_key(U1536::from(0u8), generate_private_key())
        );
    }

    #[test]
    fn predictability_of_the_key_with_g_equals_p_minus_one() {
        // predicatbility of the session key when g=p-1
        // (p-1)**a % p is either 1 or p-1
        // Proof with the binomial theorem
        // (p-1)^a = Σ (a r) p^r (-1)^(a-r)
        // The last expression is a polynomial f(p) + (-1)^a
        // all termps with p are divisable by p and so under modulo p produce just 0s
        // while the last term is either -1 (if a is odd) or 1 (if a is even)
        // so under modulo p it is respectively p-1 or 1
        let g = U1536::from_be_hex(MODULUS).wrapping_sub(&U1536::ONE); // p-1
        let b = generate_private_key();
        let b_pubkey = derive_public_key_with_g(b, g);
        if b.is_odd().into() {
            assert_eq!(g, b_pubkey);
        } else {
            assert_eq!(U1536::from(1u8), b_pubkey);
        }
        // So the session key (pub key of B which is either 1 or p-1)
        // produces session key for A which is either 1 or p-1
        let a = generate_private_key();
        let a_session_key = derive_session_key(b_pubkey, a);
        if b_pubkey == U1536::ONE {
            assert_eq!(U1536::from(1u8), a_session_key);
        } else {
            if a.is_odd().into() {
                assert_eq!(g, a_session_key);
            } else {
                assert_eq!(U1536::from(1u8), a_session_key);
            }
        }
    }

    #[test]
    fn negotiated_group_dh_key_fixing_attack_g_equals_one() {
        // When A uses g=1 and p and sends them via MITM to B
        // B derives its pubkey from g=1 and gets 1 as a pubkey and sends it to A
        // A derives session key from B's pubkey=1 and gets 1 as a session key
        // MITM knows that in case g=1 the session key is 1
        let session_key = U1536::from(1u8);
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

    #[test]
    fn negotiated_group_dh_key_fixing_attack_g_equals_p() {
        // A uses g=p and sends p and p respectively to B
        // B derives its pubkey from g=p and gets 0 as a pubkey and sends it to A
        // A derives session key from B's pubkey=0 and gets 0 as a session key
        // MITM knows that g equals p so the session key is 0
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

    #[test]
    fn negotiated_group_dh_key_fixing_attack_g_equals_p_minus_one() {
        // A sends g=p-1 and p to B
        // MITM sees g=p-1 and knows that this attack is applicable
        // A sends it pubkey to B
        // Let's consider
        // a, b - private keys for A and B
        // sa, sb - derived session keys for A and B
        // A, B - public key for A and B
        // We know that (see the test `predictability_of_the_key_with_g_equals_p_minus_one`)
        // that (p-1)^x mod p is 1 if x is even and p-1 if x is odd
        // -----------------------------------------------------
        // |        |   B=1, b is even  |   B=p-1, b is odd     |
        // -----------------------------------------------------
        // | A=1    |   sa = 1^a%p=1    |   sa = (p-1)^a%p=1    |
        // | a even |   sb = 1^b%p=1    |   sb = 1^b%p=1        |
        // -----------------------------------------------------
        // | A=p-1  |   sa = 1^a%p=1    |   sa = (p-1)^a%p=p-1  |
        // | a odd  |   sb = (p-1)^b%p=1|   sb = (p-1)^b%p=p-1  |
        // -----------------------------------------------------
        // So in any case both parties have the same session key
        // MITM check the values of pubkeys and uses the table above
        // to get the session key.
        // case with the session key 1 was already considered so let check p-1
        let session_key = U1536::from_be_hex(MODULUS).wrapping_sub(&U1536::ONE);
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
