/// https://cryptopals.com/sets/4/challenges/31
/// https://en.wikipedia.org/wiki/HMAC
use crate::sha1_keyed_mac::Sha1Mac;
use set1::convert_hex_to_base64::hex_str2bytes;
use set2::ecb_cut_and_paste::parse_cookie;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};

const SHA1_BLOCK_SIZE: usize = 64;

pub fn bytes_to_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(2 * data.len());
    for byte in data {
        s.push_str(format!("{:02x}", byte).as_str());
    }
    s
}

fn pad_key(key: &[u8]) -> [u8; 64] {
    if key.len() == SHA1_BLOCK_SIZE {
        return key.try_into().unwrap();
    }

    // On all other cases allocate memory
    let mut modified_key = [0_u8; 64];

    // Keys longer than blockSize are shortened by hashing them
    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if key.len() > 64 {
        let key_hash = Sha1Mac::new(b"").digest(key);
        modified_key[..key_hash.len()].copy_from_slice(&key_hash);
    } else {
        modified_key[..key.len()].copy_from_slice(key);
    }

    modified_key
}

fn xor_key(mut key: [u8; 64], p: u8) -> [u8; 64] {
    key.iter_mut().for_each(|b| {
        *b = *b ^ p;
    });
    key
}

pub fn sha1_hmac(key: &[u8], message: &[u8]) -> [u8; 20] {
    let key = pad_key(key);

    let outer_key = xor_key(key, 0x5c);
    let inner_key = xor_key(key, 0x36);
    let inner = Sha1Mac::new(&inner_key).digest(message);
    Sha1Mac::new(&outer_key).digest(&inner)
}

fn handle_connection(
    mut stream: TcpStream,
    comparator: Arc<&(dyn Fn(&[u8], &[u8]) -> bool + Sync)>,
) {
    let buf_reader = BufReader::new(&mut stream);
    let request_line = buf_reader.lines().next().unwrap().unwrap();
    //println!("request: {request_line}");

    let response = if request_line.starts_with("GET /test?") {
        let query_string =
            &request_line.strip_suffix(" HTTP/1.1").unwrap()[request_line.find('?').unwrap() + 1..];
        let query = parse_cookie(query_string);
        let file = query.get("file").unwrap();
        let signature = query.get("signature").unwrap();
        let signature = hex_str2bytes(signature);
        let hash = sha1_hmac(b"secret key", file.as_bytes());
        let status_line = "HTTP/1.1 200 OK\r\n";
        format!("{status_line}\r\n{:?}", comparator(&hash, &signature))
    } else {
        "HTTP/1.1 404 NOT FOUND\r\n\r\n".to_string()
    };

    stream.write_all(response.as_bytes()).unwrap();
}

fn compare_hashes(original: &[u8], hash: &[u8]) -> bool {
    for (o, h) in original.into_iter().zip(hash.into_iter()) {
        if o != h {
            return false;
        }
        thread::sleep(Duration::from_millis(5))
    }
    true
}

pub fn run_server(port: u16, comparator: &'static (dyn Fn(&[u8], &[u8]) -> bool + Sync)) {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
    let comparator = Arc::new(comparator);
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let comparator = comparator.clone();
        handle_connection(stream, comparator);
    }
}

pub fn make_request(port: u16, file: &str, signature: &str) -> String {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream
        .write_all(
            format!(
                "GET /test?file={file}&signature={signature} HTTP/1.1\r\nHost: localhost:{port}"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response.split_once("\r\n\r\n").unwrap().1.to_string()
}

pub fn measured_response(port: u16, file: &str, signature: &str) -> (Duration, String) {
    let now = Instant::now();
    let resp = make_request(port, file, signature);
    (now.elapsed(), resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use set1::convert_hex_to_base64::hex_str2bytes;

    #[test]
    fn bytes_2_hex() {
        assert_eq!("01c805".to_string(), bytes_to_hex(&[1_u8, 200, 5]));
    }

    #[test]
    fn basic_sha1_hmac() {
        // from https://en.wikipedia.org/wiki/HMAC
        let bench: [u8; 20] = hex_str2bytes("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
            .try_into()
            .unwrap();
        assert_eq!(
            bench,
            sha1_hmac(b"key", b"The quick brown fox jumps over the lazy dog")
        );
    }

    #[test]
    fn basic_server_test() {
        let port = 43210;
        thread::spawn(move || run_server(port, &compare_hashes));
        thread::sleep(Duration::from_secs(1));
        let resp = make_request(port, "file", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
        assert_eq!(resp, "false".to_string())
    }

    #[test]
    fn artificial_timing_attack() {
        let port = 43211;
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
        let mut response = String::new();
        for pos in 0..20 {
            for b in 0..=255 {
                signature[pos] = b;
                let (duration, resp) = measured_response(port, file, &bytes_to_hex(&signature));
                if duration > Duration::from_millis((pos as u64 + 1) * 5) {
                    println!("duration {duration:?}, position: {pos}, byte: {b:x?}");
                    response = resp;
                    break;
                }
            }
        }
        assert_eq!(response, "true".to_string());
    }
}
