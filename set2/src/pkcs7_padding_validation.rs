/// https://cryptopals.com/sets/2/challenges/15

pub fn validate_pkcs7_padding(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    // This function should take the same time (or CPU cycles) for all paths to prevent side-channel attacks
    match plaintext.last() {
        Some(&pad_value @ 0..=16) => {
            // TODO limit the iteration by pad_value
            let pad_count = plaintext
                .iter()
                .rev()
                .take_while(|&&b| b == pad_value)
                .count();
            if pad_count == pad_value as usize {
                Ok(plaintext[..plaintext.len() - pad_count].to_vec())
            } else {
                Err("incorrect padding".into())
            }
        }
        // in pkcs7 last block always contains padding
        _ => Err("incorrect padding".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_padding() {
        assert_eq!(
            Ok(b"ICE ICE BABY".to_vec()),
            validate_pkcs7_padding(b"ICE ICE BABY\x04\x04\x04\x04")
        );
    }

    #[test]
    fn incorrect_padding() {
        assert_eq!(
            Err("incorrect padding".into()),
            validate_pkcs7_padding(b"ICE ICE BABY\x05\x05\x05\x05")
        );
        assert_eq!(
            Err("incorrect padding".into()),
            validate_pkcs7_padding(b"ICE ICE BABY\x01\x02\x03\x04")
        );
        assert_eq!(
            Err("incorrect padding".into()),
            validate_pkcs7_padding(b"ICE ICE BABY\x01\x02\x03\x22")
        );
    }
}
