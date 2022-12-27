/// https://cryptopals.com/sets/1/challenges/5

pub fn repeated_xor_cipher_inplace(key: &[u8], buffer: &mut [u8]) {
    buffer
        .iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(plain, &k)| {
            //println!("{} ^ {} = {} ({} ^ {} = {})", *plain as char, k as char, (*plain ^ k) as char, *plain, k, *plain ^ k);
            *plain = *plain ^ k
        });
}

pub fn repeated_xor_cipher(key: &[u8], plaintext: &str) -> Vec<u8> {
    let plaintext = plaintext.as_bytes();
    let mut encrypted = Vec::from(plaintext);
    repeated_xor_cipher_inplace(key, &mut encrypted);
    encrypted
}

pub fn repeated_xor_decipher(key: &[u8], ciphertext: &[u8]) -> String {
    let mut buffer = Vec::from(ciphertext);
    repeated_xor_cipher_inplace(key, &mut buffer);
    String::from_utf8(buffer).unwrap_or("".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert_hex_to_base64::hex_str2bytes;

    #[test]
    fn repeating_xor() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(
            hex_str2bytes(ciphertext),
            repeated_xor_cipher(b"ICE", plaintext)
        );
    }
}
