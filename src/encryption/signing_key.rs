use encryption::rand;
use encryption::rand::rngs::ThreadRng;
use encryption::ed25519_dalek::Keypair;
use encryption::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use encryption::{encrypt, decrypt, to_256};
use encryption::{sk_bytes};
use error::CommonResult;

#[derive(Debug)]
pub struct SigningKey {
    key_pair: Keypair,
}

impl Clone for SigningKey {
    
    fn clone(&self) -> SigningKey {
        // Should be impossible to generate an error since 
        // to_bytes provides the correct byte length.
        SigningKey {
            key_pair: Keypair::from_bytes(&self.key_pair.to_bytes()).unwrap(),
        }
    }
}

impl SigningKey {
    pub fn new() -> SigningKey {
        let mut rng = rand::thread_rng();
        let pair = Keypair::generate::<ThreadRng>(&mut rng);

        SigningKey { key_pair: pair }
    }

    pub fn from_keys(public: &[u8; PUBLIC_KEY_LENGTH], private: &[u8; SECRET_KEY_LENGTH]) -> SigningKey {
        let mut output = [0u8; PUBLIC_KEY_LENGTH + SECRET_KEY_LENGTH];

        output[..SECRET_KEY_LENGTH].copy_from_slice(private);
        output[SECRET_KEY_LENGTH..].copy_from_slice(public);

        SigningKey {
            key_pair: Keypair::from_bytes(&output).expect("Could not create Keypair from bytes")
        }
    }

    // Fails if IV authentication fails.
    pub fn from_encrypted(encryption_key: &[u8], public: &[u8; PUBLIC_KEY_LENGTH], encrypted_key: &[u8]) -> CommonResult<SigningKey>{ 
        let decrypted_key = sk_bytes(&decrypt(&encrypted_key, &encryption_key)?);

        Ok(SigningKey::from_keys(public, &decrypted_key))
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key_pair.sign(data).to_bytes().to_vec()
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.key_pair.public.to_bytes()
    }

    pub fn encrypted_private_key(&self, encryption_key: &[u8]) -> Vec<u8> {
        encrypt(&self.key_pair.secret.to_bytes(), &encryption_key)
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
