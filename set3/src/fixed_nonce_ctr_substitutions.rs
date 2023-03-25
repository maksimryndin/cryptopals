/// https://cryptopals.com/sets/3/challenges/19
use crate::ctr::{AESKeyStream, BLOCK_SIZE};
use set1::convert_hex_to_base64::base64decode;

const PLAINTEXTS: [&str; 40] = [
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    "U2hlIHJvZGUgdG8gaGFycmllcnM/",
    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
];

fn encrypt_texts(key: [u8; BLOCK_SIZE]) -> Vec<Vec<u8>> {
    PLAINTEXTS
        .iter()
        .map(|p| {
            let keystream = AESKeyStream::new(0, 0, key);
            base64decode(p.as_bytes())
                .into_iter()
                .zip(keystream)
                .map(|(b, k)| b ^ k)
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use set1::single_byte_xor_cipher::score_english_text;
    use set2::ecb_cbc_oracle::random_aes_key;

    #[test]
    fn same_nonce_ctr_break() {
        let key = random_aes_key();

        let ciphertexts = encrypt_texts(key);
        let original_ciphertexts = ciphertexts.clone();

        let min_len = ciphertexts.iter().map(|c| c.len()).min().unwrap();
        let mut keystream = vec![0_u8; min_len];
        let mut max_score = f32::MIN;

        for i in 0..min_len {
            for k in 0_u8..=255 {
                let mut text = vec![];
                for c in &ciphertexts {
                    text.push(c[i] ^ k);
                }
                let score = score_english_text(&text);
                if score > max_score {
                    max_score = score;
                    keystream[i] = k;
                }
            }
        }

        // discover first letters
        println!("===== first 3 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // first phrase `I have ` so
        keystream[0] = b'I' ^ ciphertexts[0][0];
        keystream[1] = b' ' ^ ciphertexts[0][1];
        keystream[2] = b'h' ^ ciphertexts[0][2];
        keystream[3] = b'a' ^ ciphertexts[0][3];
        keystream[4] = b'v' ^ ciphertexts[0][4];
        keystream[5] = b'e' ^ ciphertexts[0][5];
        keystream[6] = b' ' ^ ciphertexts[0][6];

        println!("===== first 7 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // fourth phrase `Eighteen` so
        keystream[7] = b'n' ^ ciphertexts[3][7];

        println!("===== first 8 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 30th phrase `So daring` so
        keystream[8] = b'g' ^ ciphertexts[29][8];

        println!("===== first 9 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 17th `That woman`
        keystream[9] = b'n' ^ ciphertexts[16][9];
        println!("===== first 10 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 2d `Coming with`
        keystream[10] = b'h' ^ ciphertexts[1][10];
        println!("===== first 11 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 13th `Being certain`
        keystream[11] = b'i' ^ ciphertexts[12][11];
        keystream[12] = b'n' ^ ciphertexts[12][12];
        println!("===== first 13 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 4th `Eighteenth-ce�luɲ�W`
        keystream[13] = b'n' ^ ciphertexts[3][13];
        keystream[14] = b't' ^ ciphertexts[3][14];
        keystream[15] = b'u' ^ ciphertexts[3][15];
        keystream[16] = b'r' ^ ciphertexts[3][16];
        keystream[17] = b'y' ^ ciphertexts[3][17];
        println!("===== first 18 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 6th `Or polite meaningl��`
        keystream[18] = b'e' ^ ciphertexts[5][18];
        keystream[19] = b's' ^ ciphertexts[5][19];
        println!("===== first 20 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 21st `What voice more sweet`
        keystream.push(b't' ^ ciphertexts[20][20]);

        // we revealed min_len messages
        // now let's filter
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 1)
            .collect();
        println!("===== first 21 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 16th `That woman's days were`
        keystream.push(b'e' ^ ciphertexts[15][21]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 2)
            .collect();
        println!("===== first 22 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 4th `Eighteenth-century house`
        keystream.push(b's' ^ ciphertexts[3][22]);
        keystream.push(b'e' ^ ciphertexts[3][23]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 4)
            .collect();
        println!("===== first 24 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 32d `He, too, has been changed`
        keystream.push(b'd' ^ ciphertexts[31][24]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 5)
            .collect();
        println!("===== first 25 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 12th `ll changed, changed utter`
        keystream.push(b'r' ^ ciphertexts[11][25]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 6)
            .collect();
        println!("===== first 26 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 17th `So sensitive his nature seem`
        keystream.push(b'e' ^ ciphertexts[16][26]);
        keystream.push(b'm' ^ ciphertexts[16][27]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 8)
            .collect();
        println!("===== first 28 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 15th `He had done most bitter wrong`
        keystream.push(b'g' ^ ciphertexts[14][28]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 9)
            .collect();
        println!("===== first 29 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 9th `So sensitive his nature seemed`
        keystream.push(b'd' ^ ciphertexts[8][29]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 10)
            .collect();
        println!("===== first 30 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 7th `This other his helper and friend`
        keystream.push(b'n' ^ ciphertexts[6][30]);
        keystream.push(b'd' ^ ciphertexts[6][31]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 12)
            .collect();
        println!("===== first 32 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 7th `He might have won fame in the end`
        keystream.push(b'd' ^ ciphertexts[1][32]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 13)
            .collect();
        println!("===== first 33 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 1st `I have passed with a nod of the head`
        keystream.push(b'e' ^ ciphertexts[0][33]);
        keystream.push(b'a' ^ ciphertexts[0][34]);
        keystream.push(b'd' ^ ciphertexts[0][35]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 16)
            .collect();
        println!("===== first 36 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        // 1st `He, too, has been changed in his turn`
        keystream.push(b'n' ^ ciphertexts[0][36]);
        let ciphertexts: Vec<Vec<u8>> = ciphertexts
            .into_iter()
            .filter(|c| c.len() > min_len + 17)
            .collect();
        println!("===== first 37 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");

        println!("===== !!!!!!! final texts !!!!!!! =====");
        for c in original_ciphertexts.into_iter() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{}", String::from_utf8(plain).unwrap());
        }
    }
}
