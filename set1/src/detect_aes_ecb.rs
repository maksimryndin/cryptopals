/// https://cryptopals.com/sets/1/challenges/8
use std::collections::HashSet;

const BLOCK_SIZE: usize = 16;

pub fn detect_aes_ecb_pattern(data: &[u8]) -> bool {
    let mut set = HashSet::with_capacity(data.len() / BLOCK_SIZE);
    (0..data.len())
        .step_by(BLOCK_SIZE)
        .fold(false, |is_detected, i| {
            is_detected || !set.insert(&data[i..i + BLOCK_SIZE])
        })
}

pub fn detect_aes_ecb<'a>(data: &'a Vec<Vec<u8>>) -> &'a [u8] {
    for row in data {
        if detect_aes_ecb_pattern(&row) {
            return row;
        }
    }
    panic!("aes ecb encrypted line is not found!");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert_hex_to_base64::hex_str2bytes;
    use crate::helpers::filename_fullpath;
    use std::fs::read_to_string;

    #[test]
    fn block_detector() {
        let data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 2, 2, 3,
            4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ];
        assert!(detect_aes_ecb_pattern(&data));

        let data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 3, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 2, 2, 3,
            4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ];
        assert!(!detect_aes_ecb_pattern(&data));
    }

    #[test]
    fn aes_ecb_file_detection() {
        let texts: Vec<Vec<u8>> = read_to_string(filename_fullpath("detect_aes_ecb.txt"))
            .unwrap()
            .split_whitespace()
            .map(|s| hex_str2bytes(s))
            .collect();

        let line = detect_aes_ecb(&texts);
        println!("{:02x?}", line);
    }
}
