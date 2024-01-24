/// https://cryptopals.com/sets/5/challenges/36
use crate::diffie_hellman::*;
use crypto_bigint::{
    const_residue, modular::constant_mod::ResidueParams, rand_core::OsRng, Encoding, Random, U1536,
    U256,
};
use set2::ecb_cut_and_paste::parse_cookie;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

const SHA256_BLOCK_SIZE: usize = 64;

fn generate_salt() -> U256 {
    U256::random(&mut OsRng)
}

fn pad_key(key: &[u8]) -> [u8; SHA256_BLOCK_SIZE] {
    if key.len() == SHA256_BLOCK_SIZE {
        return key.try_into().unwrap();
    }

    // On all other cases allocate memory
    let mut modified_key = [0_u8; SHA256_BLOCK_SIZE];

    // Keys longer than blockSize are shortened by hashing them
    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if key.len() > SHA256_BLOCK_SIZE {
        let key_hash = sha256_mac(b"", key);
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

pub fn sha256_hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let key = pad_key(key);

    let outer_key = xor_key(key, 0x5c);
    let inner_key = xor_key(key, 0x36);
    let inner = sha256_mac(&inner_key, message);
    sha256_mac(&outer_key, &inner)
}

fn sha256_mac(secret: &[u8], message: &[u8]) -> [u8; 32] {
    let data: Vec<u8> = secret
        .into_iter()
        .chain(message.into_iter())
        .copied()
        .collect();
    sha256(&data)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn salt_password(salt: &U256, password: &str) -> U256 {
    let hash = sha256_mac(&salt.to_be_bytes(), password.as_bytes());
    U256::from_be_slice(&hash)
}

pub fn create_password_verifier(password: &str) -> (U256, U1536) {
    let salt = generate_salt();
    let salted = salt_password(&salt, password);
    let salted = convert_u256_to_u1536(&salted);
    let verifier = derive_public_key(salted);
    (salt, verifier)
}

pub fn convert_u256_to_u1536(n: &U256) -> U1536 {
    let mut arr = [0u8; 192];
    (&mut arr[160..]).copy_from_slice(&n.to_be_bytes());
    U1536::from_be_slice(&arr)
}

pub fn client_session(
    password: &str,
    salt: U256,
    pubkey: U1536,
    private_key: U1536,
    server_key: U1536,
    k: U1536, // parametrization for other challenges
) -> [u8; 32] {
    let k = const_residue!(k, Modulus);
    let g = U1536::from(2u8);
    let g = const_residue!(g, Modulus);
    let uh = sha256_mac(&pubkey.to_be_bytes(), &server_key.to_be_bytes());
    let u = convert_u256_to_u1536(&U256::from_be_bytes(uh));
    let x = salt_password(&salt, password);
    let x_ext = convert_u256_to_u1536(&x);
    let gx = g.pow(&x_ext);
    let base = const_residue!(server_key, Modulus).sub(&k.mul(&gx));
    let x_ext = const_residue!(x_ext, Modulus);
    let pow = const_residue!(private_key, Modulus).add(&const_residue!(u, Modulus).mul(&x_ext));
    let shared = base.pow(&pow.retrieve()).retrieve();
    let session_key = sha256(&shared.to_be_bytes());
    sha256_hmac(&session_key, &salt.to_be_bytes())
}

fn handle_connection(mut stream: TcpStream, storage: &mut ServerState) {
    let buf_reader = BufReader::new(&mut stream);
    let request_line = buf_reader.lines().next().unwrap().unwrap();
    let (path, mut query) = parse_request(&request_line);
    let response = match path.as_str() {
        "/register" => {
            let identifier = query.remove("identifier").unwrap();
            let verifier = U1536::from_be_hex(&query.remove("verifier").unwrap());
            let salt = U256::from_be_hex(&query.remove("salt").unwrap());
            storage.identifier = Some(identifier);
            storage.verifier = Some(verifier);
            storage.salt = Some(salt);
            format!("HTTP/1.1 200 OK\r\n\r\nstatus=ok")
        }
        "/exchange-keys" => {
            let identifier = query.remove("identifier").unwrap(); // I
            let client_key = query.remove("key").unwrap(); // A
            if storage.identifier.as_ref() != Some(&identifier) {
                format!("HTTP/1.1 401 Unauthorized\r\n\r\nstatus=unregistered user")
            } else {
                storage.client_key = Some(U1536::from_be_hex(&client_key));
                let private_key = generate_private_key();
                let k = storage.k;
                let k = const_residue!(k, Modulus);
                let g = U1536::from(2u8);
                let g = const_residue!(g, Modulus);
                let v = storage.verifier.unwrap();
                let v = const_residue!(v, Modulus);
                let pubkey = k.mul(&v).add(&g.pow(&private_key)).retrieve();
                storage.private_key = Some(private_key);
                storage.pubkey = Some(pubkey);
                format!(
                    "HTTP/1.1 200 OK\r\n\r\nsalt={}&key={}",
                    storage.salt.unwrap(),
                    storage.pubkey.unwrap()
                )
            }
        }
        "/verify" => {
            let client_session = query.remove("session").unwrap();
            let client_session = U256::from_be_hex(&client_session).to_be_bytes();

            let uh = sha256_mac(
                &storage.client_key.unwrap().to_be_bytes(),
                &storage.pubkey.unwrap().to_be_bytes(),
            );
            let u = convert_u256_to_u1536(&U256::from_be_bytes(uh));
            let v = storage.verifier.unwrap();
            let v = const_residue!(v, Modulus);
            let client_key = storage.client_key.unwrap();
            let shared = const_residue!(client_key, Modulus)
                .mul(&v.pow(&u))
                .pow(&storage.private_key.unwrap())
                .retrieve();
            let session_key = sha256(&shared.to_be_bytes());
            let session_key = sha256_hmac(&session_key, &storage.salt.unwrap().to_be_bytes());
            if client_session != session_key {
                format!("HTTP/1.1 401 Unauthorized\r\n\r\nstatus=invalid session key")
            } else {
                format!("HTTP/1.1 200 OK\r\n\r\nstatus=ok")
            }
        }
        // for purposes of other challenges
        "/state" => {
            let uh = sha256_mac(
                &storage.client_key.unwrap().to_be_bytes(),
                &storage.pubkey.unwrap().to_be_bytes(),
            );
            let u = convert_u256_to_u1536(&U256::from_be_bytes(uh));
            format!(
                "HTTP/1.1 200 OK\r\n\r\nsalt={}&private_key={}&client_key={}&u={}",
                storage.salt.unwrap(),
                storage.private_key.unwrap(),
                storage.client_key.unwrap(),
                u
            )
        }
        _ => "HTTP/1.1 404 NOT FOUND\r\n\r\n".to_string(),
    };

    stream.write_all(response.as_bytes()).unwrap();
}

fn parse_request(request_line: &str) -> (String, HashMap<String, String>) {
    let query_index = request_line.find('?').unwrap();
    let request_line = request_line.strip_suffix(" HTTP/1.1").unwrap();
    let query_string = &request_line[query_index + 1..];
    let query = if query_string == "" {
        HashMap::new()
    } else {
        parse_cookie(query_string)
    };
    let path = request_line[..query_index]
        .strip_prefix("GET ")
        .unwrap()
        .to_string();
    (path, query)
}

#[derive(Default)]
struct ServerState {
    k: U1536,
    verifier: Option<U1536>,
    identifier: Option<String>,
    salt: Option<U256>,
    pubkey: Option<U1536>,
    private_key: Option<U1536>,
    client_key: Option<U1536>,
}

pub fn run_server(port: u16, k: U1536) {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
    let mut state = ServerState {
        k,
        ..ServerState::default()
    };
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream, &mut state);
    }
}

pub fn make_request(port: u16, path: &str, query: &str) -> HashMap<String, String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream
        .write_all(format!("GET {path}?{query} HTTP/1.1\r\nHost: localhost:{port}").as_bytes())
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (status, body) = response.split_once("\r\n\r\n").unwrap();
    if !status.starts_with("HTTP/1.1 200 OK") {
        panic!("server replied with {} and body {}", status, body);
    }
    parse_cookie(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn uint_conversion() {
        assert_eq!(U1536::from(3u8), convert_u256_to_u1536(&U256::from(3u8)));
    }

    #[test]
    fn basic_srp_flow() {
        // C & S
        // C & S agree on N=[NIST Prime], g=2, k=3, I (email@email.com), P (my_secret
        let k = U1536::from(3u8);
        let k = const_residue!(k, Modulus);
        let g = U1536::from(2u8);
        let g = const_residue!(g, Modulus);

        // S
        // Generate salt as random integer
        // Generate string xH=SHA256(salt|password)
        // Convert xH to integer x somehow (put 0x on hexdigest)
        // Generate v=g**x % N
        // Save everything but x, xH
        let (server_salt, server_verifier) = create_password_verifier("my_secret");

        // C->S
        // Send I, A=g**a % N (a la Diffie Hellman)
        let client_private_key = generate_private_key();
        let (_client_identifier, client_pubkey) =
            ("email@email.com", derive_public_key(client_private_key));

        // S->C
        // Send salt, B=kv + g**b % N
        let server_private_key = generate_private_key();
        let v = const_residue!(server_verifier, Modulus);
        let server_pubkey_like = k.mul(&v).add(&g.pow(&server_private_key)).retrieve();

        // S, C
        // Compute string uH = SHA256(A|B), u = integer of uH
        let uh = sha256_mac(
            &client_pubkey.to_be_bytes(),
            &server_pubkey_like.to_be_bytes(),
        );
        let u = convert_u256_to_u1536(&U256::from_be_bytes(uh));

        // C
        // Generate string xH=SHA256(salt|password)
        // Convert xH to integer x somehow (put 0x on hexdigest)
        let x = salt_password(&server_salt, "my_secret");
        // Generate S = (B - k * g**x)**(a + u * x) % N
        // g**x
        let x_ext = convert_u256_to_u1536(&x);
        let gx = g.pow(&x_ext);
        // B - k * g**x
        let base = const_residue!(server_pubkey_like, Modulus).sub(&k.mul(&gx));
        // a + u * x
        let x_ext = const_residue!(x_ext, Modulus);
        let pow = const_residue!(client_private_key, Modulus)
            .add(&const_residue!(u, Modulus).mul(&x_ext));
        // S
        let sc = base.pow(&pow.retrieve()).retrieve();
        let kc = sha256(&sc.to_be_bytes());

        // S
        // Generate S = (A * v**u) ** b % N
        let ss = const_residue!(client_pubkey, Modulus)
            .mul(&v.pow(&u))
            .pow(&server_private_key)
            .retrieve();
        let ks = sha256(&ss.to_be_bytes());
        assert_eq!(sc, ss);

        // C->S
        // Send HMAC-SHA256(K, salt)
        let client_challenge = sha256_hmac(&kc, &server_salt.to_be_bytes());

        // S->C
        // Send "OK" if HMAC-SHA256(K, salt) validates
        let server_verification = sha256_hmac(&ks, &server_salt.to_be_bytes());
        assert_eq!(client_challenge, server_verification);
    }

    #[test]
    fn srp_client_server_flow() {
        // SRP from https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
        // has a little bit different flow (more pragmatic)
        // but the underlying math is the same
        // For purposes of future challenges we skip
        // checks for keys values
        let port = 43213;
        std::thread::spawn(move || run_server(port, U1536::from(3u8)));
        std::thread::sleep(Duration::from_secs(1));

        let identifier = "email@email.com";

        // registration
        println!("== REGISTRATION");
        let (salt, password_verifier) = create_password_verifier("my_secret");
        // Send I, s, v to server for initial registration
        make_request(
            port,
            "/register",
            format!("identifier={identifier}&verifier={password_verifier}&salt={salt}").as_str(),
        );

        // Usage

        // Exchange keys
        println!("== KEYS EXCHANGE");
        let private_key = generate_private_key(); // a
        let pubkey = derive_public_key(private_key); // A
        let server_data = make_request(
            port,
            "/exchange-keys",
            format!("identifier={identifier}&key={pubkey}").as_str(),
        );
        let salt = U256::from_be_hex(server_data.get("salt").unwrap()); // s
        let server_key = U1536::from_be_hex(server_data.get("key").unwrap()); // B

        // Create session key and verify
        println!("== VERIFICATION ");
        let session_key = client_session(
            "my_secret",
            salt,
            pubkey,
            private_key,
            server_key,
            U1536::from(3u8),
        );
        let server_data = make_request(
            port,
            "/verify",
            format!("session={}", U256::from_be_slice(&session_key)).as_str(),
        );
        assert_eq!("ok", server_data.get("status").unwrap());
    }
}
