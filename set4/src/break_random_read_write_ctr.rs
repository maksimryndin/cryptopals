/// https://cryptopals.com/sets/4/challenges/25

#[cfg(test)]
mod tests {
    use set1::aes_ecb_mode::{aes_ecb_decrypt, remove_pad};
    use set1::helpers::{filename_fullpath, read_b64_encoded};
    use set3::ctr::AESKeyStream;

    fn edit(ciphertext: &mut [u8], key: [u8; 16], offset: usize, newtext: &[u8]) {
        let keystream = AESKeyStream::new(0, 0, key);
        ciphertext
            .iter_mut()
            .zip(keystream)
            .skip(offset)
            .zip(newtext.iter())
            .for_each(|((c, k), n)| *c = *n ^ k);
    }

    #[test]
    fn aes_ctr_edit() {
        let plaintext = b"some plaintext";
        let mut aeskey = [0u8; 16];
        getrandom::getrandom(&mut aeskey).expect("failed to obtain random data");

        let keystream = AESKeyStream::new(0, 0, aeskey);
        let ciphertext: Vec<u8> = plaintext
            .into_iter()
            .zip(keystream)
            .map(|(p, k)| p ^ k)
            .collect();

        let mut modified_ciphertext = ciphertext.clone();
        edit(&mut modified_ciphertext, aeskey, 0, plaintext);
        assert_eq!(modified_ciphertext, ciphertext);

        edit(
            &mut modified_ciphertext,
            aeskey,
            0,
            &vec![0_u8; ciphertext.len()],
        );

        let discovered_plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(modified_ciphertext.into_iter())
            .map(|(c, k)| *c ^ k)
            .collect();

        println!("{}", String::from_utf8_lossy(&discovered_plaintext));
        assert_eq!(plaintext.to_vec(), discovered_plaintext);

        let mut modified_ciphertext = ciphertext.clone();
        edit(&mut modified_ciphertext, aeskey, 5, b"ciphertex");
        let keystream = AESKeyStream::new(0, 0, aeskey);

        let discovered_plaintext: Vec<u8> = modified_ciphertext
            .into_iter()
            .zip(keystream)
            .map(|(c, k)| c ^ k)
            .collect();

        println!("{}", String::from_utf8_lossy(&discovered_plaintext));
        assert_eq!(b"some ciphertex".to_vec(), discovered_plaintext);
    }

    #[test]
    fn break_aes_ctr() {
        let mut decoded = read_b64_encoded(filename_fullpath("aes_ecb.txt"));
        aes_ecb_decrypt(&mut decoded, *b"YELLOW SUBMARINE");
        let plaintext = remove_pad(&decoded);
        let mut aeskey = [0u8; 16];
        getrandom::getrandom(&mut aeskey).expect("failed to obtain random data");

        let keystream = AESKeyStream::new(0, 0, aeskey);
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(keystream)
            .map(|(p, k)| *p ^ k)
            .collect();

        let mut modified_ciphertext = ciphertext.clone();
        edit(&mut modified_ciphertext, aeskey, 0, &plaintext);
        assert_eq!(modified_ciphertext, ciphertext);

        // attacker has the ciphertext and controls offset, newtext
        edit(
            &mut modified_ciphertext,
            aeskey,
            0,
            &vec![0_u8; ciphertext.len()],
        );
        // modified_ciphertext now is the keystream

        let discovered_plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(modified_ciphertext.into_iter())
            .map(|(c, k)| *c ^ k)
            .collect();

        println!("{}", String::from_utf8_lossy(&discovered_plaintext));
        assert_eq!(plaintext, discovered_plaintext);
    }
}
