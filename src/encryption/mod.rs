extern crate argon2rs;
extern crate ed25519_compact;
pub extern crate miscreant;
extern crate rand;
extern crate sha2;
extern crate x25519_dalek;

pub mod byte_encryption;
pub mod exchange_key;
pub mod signing_key;

use base64::{decode, encode};
pub use encryption::argon2rs::Argon2;
pub use encryption::argon2rs::Variant::Argon2i;
use encryption::miscreant::siv::Aes128PmacSiv;
pub use encryption::rand::Rng;
pub use encryption::sha2::{Digest, Sha512Trunc256};
pub use encryption::x25519_dalek::PublicKey as XPublicKey;
use error::CommonResult;
use std::convert::TryInto;

pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SECRET_KEY_LENGTH: usize = 32;

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

    hasher.hash(&mut result, password.as_bytes(), salt, &[0u8; 0], &[0u8; 0]);

    result
}

pub fn check_password(password: &str, hashed_password: &str) -> bool {
    let merged: [u8; 64] = match decode(hashed_password) {
        Ok(v) if v.len() == 64 => *as_512(v.as_slice()),
        _ => return false,
    };

    let salt: [u8; 32] = merged[0..32].try_into().unwrap();
    let hash: [u8; 32] = merged[32..64].try_into().unwrap();

    let new_hash = hash_salted_password(password, &salt);

    hash_eq(&hash, &new_hash)
}

// Constant-time equality check for 32 byte arrays
pub fn hash_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
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

pub fn secure_hash(data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512Trunc256::new();
    let mut hash_data = Vec::new();

    for slice in data {
        hash_data.extend_from_slice(slice);
    }

    hasher.input(hash_data);

    hasher.result().into()
}

pub fn hash_by_parts(data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512Trunc256::new();
    let mut hash_data = Vec::new();

    for slice in data {
        let mut slice_hasher = Sha512Trunc256::new();
        slice_hasher.input(slice);
        let add_data = slice_hasher.result();

        hash_data.extend_from_slice(&add_data);
    }

    hasher.input(hash_data);

    hasher.result().into()
}

pub fn decode_64(input: &str) -> CommonResult<[u8; 64]> {
    let vec_ouput = decode(input)?;
    let mut output: [u8; 64] = [0u8; 64];
    output.copy_from_slice(&vec_ouput);
    Ok(output)
}

pub fn decode_32(input: &str) -> CommonResult<[u8; 32]> {
    let vec_ouput = decode(input)?;
    let mut output: [u8; 32] = [0u8; 32];
    output.copy_from_slice(&vec_ouput);
    Ok(output)
}

pub fn random_int_256() -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut rng = rand::thread_rng();

    rng.fill(&mut result);

    result
}

pub fn as_512(input: &[u8]) -> &[u8; 64] {
    if input.len() == 64 {
        let ptr = input.as_ptr() as *const [u8; 64];
        // SAFETY: ok because we just checked that the length fits
        unsafe { &*ptr }
    } else {
        panic!("Array length not 64 bytes");
    }
}

pub fn as_256(input: &[u8]) -> &[u8; 32] {
    if input.len() == 32 {
        let ptr = input.as_ptr() as *const [u8; 32];
        // SAFETY: ok because we just checked that the length fits
        unsafe { &*ptr }
    } else {
        panic!("Array length not 32 bytes");
    }
}

pub fn lpad_to_256(input: &[u8]) -> [u8; 32] {
    if input.len() == 32 {
        let ptr = input.as_ptr() as *const [u8; 32];
        // SAFETY: ok because we just checked that the length fits
        unsafe { *ptr }
    } else if input.len() < 32 {
        let mut result = [0u8; 32];

        for i in 0..input.len() {
            result[32 - input.len() + i] = input[i];
        }

        return result;
    } else {
        panic!("Array length over 32 bytes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn left_pad_32byte_array() {
        let num: u64 = 999999999;
        let array_8: [u8; 8] = num.to_be_bytes();
        let array_32: [u8; 32] = lpad_to_256(&array_8);

        for i in 0..24 {
            assert_eq!(array_32[i], 0u8);
        }

        for i in 24..32 {
            assert_eq!(array_32[i], array_8[i - 24]);
        }

        let input_32: &[u8] = &[7u8; 32];

        let array_32: [u8; 32] = lpad_to_256(input_32);

        for i in 0..32 {
            assert_eq!(input_32[i], array_32[i]);
        }

    }

    #[test]
    fn encrypt_decrypt() {
        // get some data to encrypt not nicely aligned.
        let data = b"Pardon me thou bleeding piece of earth that I am meek and gentle with these butchers.";

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
}
