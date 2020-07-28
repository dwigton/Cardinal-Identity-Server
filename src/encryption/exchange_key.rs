use encryption::x25519_dalek::StaticSecret;
use encryption::x25519_dalek::EphemeralSecret;
use encryption::x25519_dalek::PublicKey;
use encryption::rand;
use encryption::SECRET_KEY_LENGTH;
use encryption::{Sha512Trunc256, Digest};
use encryption::byte_encryption::{encrypt_32, decrypt_32};
use error::CommonResult;
use std::convert::TryInto;

// This acts as a constant interface while the backing library is
// in flux. should eventually use the library type.
pub struct ExchangeKey {
    key: StaticSecret,
}

impl ExchangeKey {
    pub fn new() -> ExchangeKey {
        let mut rng = rand::thread_rng();

        ExchangeKey {
            key: StaticSecret::new(&mut rng),
        }
    }

    pub fn from_key(private: [u8; SECRET_KEY_LENGTH]) -> ExchangeKey {

        ExchangeKey {
            key: StaticSecret::from(private),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        *PublicKey::from(&self.key).as_bytes()
    }

    pub fn encrypted_private_key(&self, encryption_key: &[u8; 32]) -> [u8; 64] {
        encrypt_32(&self.key.to_bytes().try_into().unwrap(), encryption_key)
    }

    pub fn private_key(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn from_encrypted(encryption_key: &[u8; 32], encrypted_key: &[u8; 64]) -> CommonResult<ExchangeKey>{ 
        let decrypted_key: [u8; SECRET_KEY_LENGTH] = decrypt_32(&encrypted_key, &encryption_key)?;

        Ok(ExchangeKey::from_key(decrypted_key))
    }
}

pub struct EphemeralKey {
    key: EphemeralSecret
}

impl EphemeralKey {
    pub fn new() -> EphemeralKey {
        let mut rng = rand::thread_rng();

        EphemeralKey {
            key: EphemeralSecret::new(&mut rng),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        *PublicKey::from(&self.key).as_bytes()
    }

    pub fn key_gen(self, public_key: [u8; 32]) -> [u8; 32] {

        let pk = PublicKey::from(public_key);
        let shared_key = self.key.diffie_hellman(&pk);

        let mut hasher = Sha512Trunc256::new();

        hasher.input(shared_key.as_bytes());

        hasher.result().try_into().unwrap()
    }
}
