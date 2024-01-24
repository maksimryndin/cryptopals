/// https://cryptopals.com/sets/5/challenges/38

#[cfg(test)]
mod tests {
    use crate::diffie_hellman::{derive_public_key, generate_private_key, Modulus};
    use crate::srp::{
        client_session, convert_u256_to_u1536, create_password_verifier, make_request, run_server,
        salt_password, sha256, sha256_hmac,
    };
    use crypto_bigint::{
        const_residue, modular::constant_mod::ResidueParams, Encoding, U1536, U256,
    };
    use std::time::Duration;

    #[test]
    fn simplified_srp_dictionary_attack() {
        // Simplified SRP described in the challenge is basically SRP parametrized with k=0
        // As the main idea is that server pub key doesn't depend on password
        let port = 43215;
        std::thread::spawn(move || run_server(port, U1536::from(0u8)));
        std::thread::sleep(Duration::from_secs(1));

        let identifier = "email@email.com";

        // registration
        println!("== REGISTRATION");
        let (salt, password_verifier) = create_password_verifier("dictionary");
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
            "dictionary",
            salt,
            pubkey,
            private_key,
            server_key,
            U1536::from(0u8),
        );
        let server_data = make_request(
            port,
            "/verify",
            format!("session={}", U256::from_be_slice(&session_key)).as_str(),
        );
        assert_eq!("ok", server_data.get("status").unwrap());

        // Offline part
        // Now malicious server has K from client
        // which was HMAC256(SHA256(B**(a+ux)), salt), where x is SHA256(salt|password)
        // That K should also be equal to server's
        // HMAC256(SHA256((Av**u)**b), salt), or
        // HMAC256(SHA256((Ag**xu)**b), salt), where x is SHA256(salt|password) so
        // the attacker can try different passwords until the result hash will be equal to the client's K
        // the key assumption is that the server public key and client's shared session key doesn't depend on password

        let server_state = make_request(port, "/state", "");
        let u = U1536::from_be_hex(server_state.get("u").unwrap()); // u
        let salt = U256::from_be_hex(server_state.get("salt").unwrap()); // s
        let server_private_key = U1536::from_be_hex(server_state.get("private_key").unwrap()); // b
        let client_key = U1536::from_be_hex(server_state.get("client_key").unwrap()); // A

        fn password_cracker(
            password: &str,
            client_key: U1536,
            salt: &U256,
            u: &U1536,
            server_private_key: &U1536,
        ) -> [u8; 32] {
            let salted = salt_password(salt, password);
            let salted = convert_u256_to_u1536(&salted);
            let v = derive_public_key(salted);
            let v = const_residue!(v, Modulus);
            let shared = const_residue!(client_key, Modulus)
                .mul(&v.pow(u))
                .pow(server_private_key)
                .retrieve();
            let session_key = sha256(&shared.to_be_bytes());
            sha256_hmac(&session_key, &salt.to_be_bytes())
        }

        // here we assume the attacker calculates different hashes with password_cracker
        // for different words

        assert_eq!(
            session_key,
            password_cracker("dictionary", client_key, &salt, &u, &server_private_key)
        );
    }
}
