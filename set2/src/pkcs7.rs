/// https://cryptopals.com/sets/2/challenges/9

#[inline]
fn calculate_pad(data_len: usize, block_size: usize) -> usize {
    (data_len / block_size + 1) * block_size - data_len
}

pub fn pad_pkcs7_buffer(data: &[u8], block_size: usize, buffer: &mut [u8]) {
    let pad = calculate_pad(data.len(), block_size);
    if buffer.len() - pad < data.len() {
        panic!("buffer is less than data and pad");
    }
    (0..data.len()).for_each(|i| buffer[i] = data[i]);
    (data.len()..data.len() + pad).for_each(|i| buffer[i] = pad as u8);
}

pub fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad = calculate_pad(data.len(), block_size);
    let mut buffer = vec![0_u8; data.len() + pad];
    pad_pkcs7_buffer(data, block_size, &mut buffer);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_length() {
        assert_eq!(4, calculate_pad(16, 20));
        assert_eq!(4, calculate_pad(36, 20));
        assert_eq!(16, calculate_pad(16, 16));
    }

    #[test]
    fn check_pkcs7_pad() {
        let mut v = vec![];
        v.extend_from_slice(b"YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!(v, pad_pkcs7(b"YELLOW SUBMARINE", 20));
    }
}
