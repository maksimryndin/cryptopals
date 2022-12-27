/// https://cryptopals.com/sets/1/challenges/2

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("buffers should have equal length");
    }
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert_hex_to_base64::hex_str2bytes;

    #[test]
    fn basic() {
        let first = hex_str2bytes("1c0111001f010100061a024b53535009181c");
        let second = hex_str2bytes("686974207468652062756c6c277320657965");
        assert_eq!(
            hex_str2bytes("746865206b696420646f6e277420706c6179"),
            xor(&first, &second)
        );
    }
}
