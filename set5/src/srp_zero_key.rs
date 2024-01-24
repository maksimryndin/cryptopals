/// https://cryptopals.com/sets/5/challenges/37

#[cfg(test)]
mod tests {
    use crate::diffie_hellman::MODULUS;
    use crate::srp::{create_password_verifier, make_request, run_server, sha256, sha256_hmac};
    use crypto_bigint::{Encoding, U1536, U256};
    use std::time::Duration;

    #[test]
    fn srp_zero_key_attack() {
        // SRP from https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
        // has a little bit different flow (more pragmatic)
        // but the underlying math is the same
        // For purposes of future challenges we skip
        // checks for keys values
        let port = 43214;
        std::thread::spawn(move || run_server(port, U1536::from(3u8)));
        std::thread::sleep(Duration::from_secs(1));

        let identifier = "email@email.com";

        // registration by user
        println!("== REGISTRATION");
        let (salt, password_verifier) = create_password_verifier("my_secret");
        // Send I, s, v to server for initial registration
        make_request(
            port,
            "/register",
            format!("identifier={identifier}&verifier={password_verifier}&salt={salt}").as_str(),
        );

        // Usage by attacker

        // Exchange keys
        println!("== KEYS EXCHANGE");
        let pubkey = U1536::from_be_hex(MODULUS); //U1536::from(0u8); // A = 0, N, 2N .. equals 0 under mod N
        let server_data = make_request(
            port,
            "/exchange-keys",
            format!("identifier={identifier}&key={pubkey}").as_str(),
        );
        let salt = U256::from_be_hex(server_data.get("salt").unwrap()); // s
        let _server_key = U1536::from_be_hex(server_data.get("key").unwrap()); // B

        // Create session key and verify
        // Under zero client pubkey the shared key for the server should be 0
        println!("== VERIFICATION ");
        let session_key = sha256(&U1536::from(0u8).to_be_bytes());
        let session_key = sha256_hmac(&session_key, &salt.to_be_bytes());
        let server_data = make_request(
            port,
            "/verify",
            format!("session={}", U256::from_be_slice(&session_key)).as_str(),
        );
        assert_eq!("ok", server_data.get("status").unwrap());
    }
}
