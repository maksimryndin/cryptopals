use std::thread;
use std::time::Duration;

fn compare_hashes(original: &[u8], hash: &[u8]) -> bool {
    for (o, h) in original.into_iter().zip(hash.into_iter()) {
        if o != h {
            return false;
        }
        thread::sleep(Duration::from_millis(2))
    }
    true
}

#[cfg(test)]
/// https://cryptopals.com/sets/4/challenges/32

mod tests {
    use super::*;
    use crate::hmac_sha1_artificial_timing_leak::{
        bytes_to_hex, make_request, measured_response, run_server,
    };

    const SAMPLE_ROUNDS: usize = 9; // odd number for easy median

    fn sample_byte(mut signature: [u8; 20], pos: usize, port: u16, file: &str) -> u8 {
        let mut samples = [[0_u64; SAMPLE_ROUNDS]; 256];
        for s in 0..SAMPLE_ROUNDS {
            for b in 0..=255 {
                signature[pos] = b;
                let (duration, _) = measured_response(port, file, &bytes_to_hex(&signature));
                samples[b as usize][s] = duration.as_micros() as u64;
            }
        }
        samples
            .into_iter()
            .map(|mut sample| {
                sample.as_mut_slice().sort_unstable();
                sample[(SAMPLE_ROUNDS + 1) / 2]
            })
            .enumerate()
            .max_by_key(|byte_duration| byte_duration.1)
            .unwrap()
            .0 as u8
    }

    #[test]
    fn less_artificial_timing_attack() {
        let port = 43212;
        let file = "some string";
        thread::spawn(move || run_server(port, &compare_hashes));
        thread::sleep(Duration::from_secs(1));
        let (network_duration, _) =
            measured_response(port, file, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
        println!(
            "request-response round-trip duration {:?}",
            network_duration
        ); // less that 1 ms at the start
        let mut signature = [0_u8; 20];
        // 20 bytes of sha1_hmac output
        for pos in 0..20 {
            let best_byte = sample_byte(signature, pos, port, file);
            signature[pos] = best_byte;
            println!("position: {pos}, byte: {best_byte:x?}");
        }
        let resp = make_request(port, file, &bytes_to_hex(&signature));
        assert_eq!(resp, "true".to_string());
        // true hash [88, d6, 9f, 9e, 75, c7, c6, c9, 13, 2d, ff, d, 22, c0, 63, ab, 2d, 8d, 2b, 3b]
    }
}
