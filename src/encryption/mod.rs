extern crate ed25519_dalek;
extern crate x25519_dalek;
extern crate rand;
extern crate sha2;
extern crate argon2rs;
pub extern crate miscreant;

pub mod signing_key;
pub mod exchange_key;

pub use encryption::ed25519_dalek::PUBLIC_KEY_LENGTH as PUBLIC_KEY_LENGTH;
pub use encryption::ed25519_dalek::SECRET_KEY_LENGTH as SECRET_KEY_LENGTH;
pub use encryption::x25519_dalek::PublicKey;
pub use encryption::argon2rs::Argon2;
pub use encryption::argon2rs::Variant::Argon2i;
pub use encryption::rand::Rng;
pub use encryption::sha2::{Sha512Trunc256, Digest};
use std::io::Result;
use std::cmp;
use encryption::miscreant::siv::Aes128PmacSiv;
use base64::{encode, decode};
use error::CommonResult;

pub fn hash_password(password: &str) -> String {

    let salt = random_int_256();
    let hash = hash_salted_password(password, &salt);

    let mut merged = [0u8; 64];

    merged[..32].copy_from_slice(&salt);
    merged[32..].copy_from_slice(&hash);

    encode(&merged.to_vec())
}

pub fn hash_salted_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let hasher = Argon2::default(Argon2i);

    let mut result = [b'0'; 32];

    hasher.hash(&mut result, password.as_bytes(), salt, &[0u8;0], &[0u8;0]);

    result
}

pub fn check_password(password: &str, hashed_password: &str) -> bool {
    let merged: [u8; 64] = match decode(hashed_password) {
        Ok(v) if v.len() == 64 => to_512(&v),
        _ => return false,
    };

    let salt: [u8;32] = to_256(&merged[0..32]);
    let hash: [u8;32] = to_256(&merged[32..64]);

    let new_hash = hash_salted_password(password, &salt); 

    hash_eq(&hash, &new_hash)
}

// Constant-time equality check for 32 byte arrays
pub fn hash_eq (a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0;

    for i in 0..32 {
        result |= a[i] ^ b[i];
    }

    result == 0
}

pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut siv = Aes128PmacSiv::new(&key);
    // passing empty additional data for now. Might be nice to 
    // sign permissions at some point to prevent privilege escalation.
    let additional_data: Vec<Vec<u8>> = Vec::new();

    siv.seal(&additional_data, &data)
}

pub fn decrypt(data: &[u8], key: &[u8]) -> CommonResult<Vec<u8>> {
    let additional_data: Vec<Vec<u8>> = Vec::new();
    let mut siv = Aes128PmacSiv::new(&key);
    Ok(siv.open(&additional_data, &data)?)
}

pub fn to_256(data: &[u8]) -> [u8; 32] {
    if data.len() > 32 { 
        panic!("Can't convert {} bytes to 32 bytes without loss of data!", data.len()); 
    }

    let mut result = [0; 32];

    for i in 0..cmp::min(result.len(), data.len()) {
        result[i] = data[i];
    }
    result
}

pub fn to_512(data: &[u8]) -> [u8; 64] {
    let mut result = [0; 64];

    for i in 0..cmp::min(result.len(), data.len()) {
        result[i] = data[i];
    }
    result
}

pub fn secure_hash(data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512Trunc256::new();
    let mut hash_data = Vec::new();
    
    for slice in data {
        hash_data.extend_from_slice(slice);
    }

    hasher.input(hash_data);

    hasher.result().into()
}


pub fn pk_bytes(data: &[u8]) -> [u8; PUBLIC_KEY_LENGTH] {
    if data.len() > PUBLIC_KEY_LENGTH { 
        panic!("Can't convert {} bytes to {} bytes without loss of data!", data.len(), PUBLIC_KEY_LENGTH); 
    }

    let mut result = [0; PUBLIC_KEY_LENGTH];

    for i in 0..cmp::min(result.len(), data.len()) {
        result[i] = data[i];
    }
    result
}

pub fn sk_bytes(data: &[u8]) -> [u8; SECRET_KEY_LENGTH] {
    if data.len() > SECRET_KEY_LENGTH { 
        panic!("Can't convert {} bytes to {} bytes without loss of data!", data.len(), SECRET_KEY_LENGTH); 
    }

    let mut result = [0; SECRET_KEY_LENGTH];

    for i in 0..cmp::min(result.len(), data.len()) {
        result[i] = data[i];
    }
    result
}

pub fn random_int_256() -> [u8; 32] {

    let mut result = [0u8; 32];
    let mut rng = rand::thread_rng();

    rng.fill(&mut result);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        // get some data to encrypt not nicely aligned.
        let mut data = b"Pardon me thou bleeding piece of earth that I am meek and gentle with these butchers.";

        // get an encryption key
        let mut key = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill(&mut key);

        let encrypted = encrypt(data, &key);
        let decrypted = decrypt(&encrypted, &key).unwrap();

        // compare all elements
        let mut result = 0;

        for i in 0..data.len() {
            result |= data[i] ^ decrypted[i];
        }

        assert_eq!(result, 0);
    }

    #[test]
    fn convert_to_256() {
        let data = [0u8,  1u8,  2u8,  3u8,  4u8,  5u8,  6u8,  7u8,
                    8u8,  9u8,  10u8, 11u8, 12u8, 13u8, 14u8, 15u8,
                    16u8, 17u8, 18u8, 19u8, 20u8, 21u8, 22u8, 23u8,
                    24u8, 25u8, 26u8, 27u8, 28u8, 29u8, 30u8, 32u8];

        let converted_data = to_256(&data);

        let mut result = 0;

        for i in 0..data.len() {
            result |= data[i] ^ converted_data[i];
        }

        assert_eq!(result, 0);
    }
}
