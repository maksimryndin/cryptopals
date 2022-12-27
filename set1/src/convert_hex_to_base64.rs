/// https://cryptopals.com/sets/1/challenges/1

const SELECT_18_12: u32 = (2_u32.pow(6) - 1) << 12;
const SELECT_12_6: u32 = (2_u32.pow(6) - 1) << 6;
const SELECT_6_0: u32 = 2_u32.pow(6) - 1;
const SELECT_16_8: u32 = (2_u32.pow(8) - 1) << 8;
const SELECT_8_0: u32 = 2_u32.pow(8) - 1;
const SELECT_10_2: u32 = (2_u32.pow(8) - 1) << 2;

pub fn hex_digit_to_integer(h: char) -> u8 {
    h.to_digit(16).expect(
        format!(
            "hex string should contain digits [0-9] and [A-Fa-f]: `{}`",
            h
        )
        .as_str(),
    ) as u8
}

pub fn hex_str2bytes(hex_str: &str) -> Vec<u8> {
    let mut result = vec![0_u8; hex_str.len() / 2];
    hex_str2bytes_inplace(hex_str, &mut result);
    result
}

pub fn hex_str2bytes_inplace(hex_str: &str, buffer: &mut [u8]) {
    if hex_str.len() % 2 != 0 {
        panic!("hex string should contain even number of digits");
    }
    if buffer.len() < hex_str.len() / 2 {
        panic!("result buffer should have size ({}) greater or equal than half of the number of digits ({}) in the hex string", buffer.len(), hex_str.len());
    }
    hex_str
        .chars()
        .step_by(2)
        .zip(hex_str.chars().skip(1).step_by(2))
        .enumerate()
        .for_each(|(i, (big, little))| {
            buffer[i] = hex_digit_to_integer(big) * 16 + hex_digit_to_integer(little);
        });
}

fn chunk_data(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    (0..data.len()).step_by(3).map(|i| {
        if i + 3 > data.len() {
            &data[i..]
        } else {
            &data[i..i + 3]
        }
    })
}

fn encode_chunk(chunk: &[u8]) -> [Option<u8>; 4] {
    match chunk.len() {
        3 => {
            let united = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
            [
                Some((united >> 18) as u8),
                Some(((united & SELECT_18_12) >> 12) as u8),
                Some(((united & SELECT_12_6) >> 6) as u8),
                Some((united & SELECT_6_0) as u8),
            ]
        }
        2 => {
            let united = ((chunk[0] as u32) << 10) | ((chunk[1] as u32) << 2);
            [
                Some((united >> 12) as u8),
                Some(((united & SELECT_12_6) >> 6) as u8),
                Some((united & SELECT_6_0) as u8),
                None,
            ]
        }
        1 => {
            let united = (chunk[0] as u32) << 4;
            [
                Some((united >> 6) as u8),
                Some((united & SELECT_6_0) as u8),
                None,
                None,
            ]
        }
        _ => panic!("wrong encoding implementation"),
    }
}

pub fn base64(data: &[u8]) -> Vec<u8> {
    chunk_data(data)
        .map(|chunk| encode_chunk(chunk).into_iter())
        .flatten()
        .map(|b| b64_lookup(b))
        .collect()
}

// https://en.wikipedia.org/wiki/Base64#Base64_table_from_RFC_4648
fn b64_lookup(byte: Option<u8>) -> u8 {
    match byte {
        None => b'=',
        Some(b @ 0..=25) => b + b'A',
        Some(b @ 26..=51) => (b - 26) + b'a',
        Some(b @ 52..=61) => (b - 52) + b'0',
        Some(62) => b'+',
        Some(63) => b'/',
        _ => panic!("wrong mapping implementation"),
    }
}

pub fn base64decode(data: &[u8]) -> Vec<u8> {
    let mut buf = [0_u8; 4];
    (0..data.len())
        .into_iter()
        .step_by(4)
        .map(|i| {
            if i + 4 > data.len() {
                &data[i..]
            } else {
                &data[i..i + 4]
            }
        })
        .map(|chunk| {
            let mut i = 0;
            chunk
                .iter()
                .filter_map(|&b| b64_reverse_lookup(b))
                .for_each(|ch| {
                    buf[i] = ch;
                    i += 1;
                });
            decode_chunk(&buf[..i]).into_iter().filter_map(|opt| opt)
        })
        .flatten()
        .collect()
}

fn decode_chunk(chunk: &[u8]) -> [Option<u8>; 3] {
    match chunk.len() {
        4 => {
            let result = ((chunk[0] as u32) << 18)
                | ((chunk[1] as u32) << 12)
                | ((chunk[2] as u32) << 6)
                | chunk[3] as u32;
            [
                Some((result >> 16) as u8),
                Some(((result & SELECT_16_8) >> 8) as u8),
                Some((result & SELECT_8_0) as u8),
            ]
        }
        3 => {
            let result = ((chunk[0] as u32) << 12) | ((chunk[1] as u32) << 6) | chunk[2] as u32;
            [
                Some((result >> 10) as u8),
                Some(((result & SELECT_10_2) >> 2) as u8),
                None,
            ]
        }
        2 => {
            let result = ((chunk[0] as u32) << 6) | chunk[1] as u32;
            [Some((result >> 4) as u8), None, None]
        }
        _ => panic!("wrong decoding implementation"),
    }
}

// https://en.wikipedia.org/wiki/Base64#Base64_table_from_RFC_4648
fn b64_reverse_lookup(byte: u8) -> Option<u8> {
    match byte {
        b'=' => None,
        b @ b'A'..=b'Z' => Some(b - b'A'),
        b @ b'a'..=b'z' => Some(b - b'a' + 26),
        b @ b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => panic!("wrong mapping implementation for character: {}", byte),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let data = hex_str2bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let base_64 =
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();
        assert_eq!(base_64, String::from_utf8(base64(&data)).unwrap());
    }

    #[test]
    fn basic_padding() {
        let data = b"hello world";
        assert_eq!(
            "aGVsbG8gd29ybGQ=".to_string(),
            String::from_utf8(base64(data)).unwrap()
        );
    }

    #[test]
    fn chunk_b64_encoding() {
        assert_eq!(
            [Some(19_u8), Some(22_u8), Some(5_u8), Some(46_u8)],
            encode_chunk(b"Man")
        );
        assert_eq!(
            [Some(19_u8), Some(22_u8), Some(4_u8), None],
            encode_chunk(b"Ma")
        );
        assert_eq!([Some(19_u8), Some(16_u8), None, None], encode_chunk(b"M"));
    }

    #[test]
    fn chunker() {
        let data = vec![73, 15, 13, 45, 64];
        let result: Vec<&[u8]> = chunk_data(&data[..]).collect();
        assert_eq!(vec![&[73, 15, 13][..], &[45, 64][..]], result);
    }

    #[test]
    fn hex_conversions() {
        assert_eq!(vec![73], hex_str2bytes("49"));
        assert_eq!(vec![73, 109], hex_str2bytes("496d"));
    }

    #[test]
    fn hex_conversions_case_insensitive() {
        assert_eq!(vec![73, 109], hex_str2bytes("496D"));
    }

    #[test]
    #[should_panic(expected = "hex string should contain even number of digits")]
    fn hex_odd_number_of_digits() {
        hex_str2bytes("495");
    }

    #[test]
    #[should_panic(expected = "hex string should contain digits [0-9] and [A-Fa-f]")]
    fn hex_wrong_digits() {
        hex_str2bytes("496g");
    }

    #[test]
    fn b64_decoding() {
        assert_eq!(
            "light w".to_string().into_bytes(),
            base64decode(b"bGlnaHQgdw")
        );
        assert_eq!(
            "light wo".to_string().into_bytes(),
            base64decode(b"bGlnaHQgd28")
        );
        assert_eq!(
            "light wor".to_string().into_bytes(),
            base64decode(b"bGlnaHQgd29y")
        );
    }
}
