use encryption::rand;
use encryption::random_int_256;
use encryption::ed25519_compact::{KeyPair, Seed, Noise};
use encryption::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use encryption::{encrypt, decrypt};
use encryption::{sk_bytes};
use error::CommonResult;
use std::convert::TryInto;

#[derive(Copy, Clone)]
pub struct SigningKey {
    seed: [u8; SECRET_KEY_LENGTH],
    key_pair: KeyPair,
}

impl SigningKey {
    pub fn new() -> SigningKey {
        let mut rng = rand::thread_rng();
        let seed = random_int_256();
        let pair = KeyPair::from_seed(Seed::new(seed));

        SigningKey { 
            seed,
            key_pair: pair 
        }
    }

    pub fn from_keys(public: &[u8; PUBLIC_KEY_LENGTH], private: &[u8; SECRET_KEY_LENGTH]) -> SigningKey {
        SigningKey {
            seed: private.to_owned(),
            key_pair: KeyPair::from_seed(Seed::new(private.to_owned())),
        }
    }

    // Fails if IV authentication fails.
    pub fn from_encrypted(encryption_key: &[u8], public: &[u8; PUBLIC_KEY_LENGTH], encrypted_key: &[u8]) -> CommonResult<SigningKey>{ 
        let decrypted_key = sk_bytes(&decrypt(&encrypted_key, &encryption_key)?);

        Ok(SigningKey::from_keys(public, &decrypted_key))
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key_pair.sk.sign(data, Some(Noise::default())).as_ref().to_vec()
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        let output: [u8; PUBLIC_KEY_LENGTH] = self.key_pair.pk.as_ref().try_into().unwrap();
        output
    }

    pub fn encrypted_private_key(&self, encryption_key: &[u8]) -> Vec<u8> {
        encrypt(&self.seed, &encryption_key)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_key() {
        use encryption::rand::Rng;

        let ed_key = SigningKey::new();

        let public_key = ed_key.public_key();

        // get an encryption key
        let mut key = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill(&mut key);

        let encrypted_key = ed_key.encrypted_private_key(&key);

        let restored_key = SigningKey::from_encrypted(&key, &public_key, &encrypted_key);

        // create a new key
        //assert_eq!(restored_key.public_key(), public_key);
        //assert_eq!(restored_key.encrypted_private_key(&key), encrypted_key);
    }
}
