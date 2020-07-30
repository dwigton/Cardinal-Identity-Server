use encryption::secure_hash;
use error::{CommonError, CommonResult};
// Xor encrypt 32byte data by 32B key and append
// 32B data hash for verification.
pub fn encrypt_32 (input: &[u8; 32], key: &[u8; 32]) -> [u8; 64] {
    let check = secure_hash(&[input]); 
    let mut encrypted: [u8; 64] = [0u8; 64];

    // xor and add verification hash
    for i in 0..32 {
        encrypted[i] = input[i] ^ key[i];
        encrypted[i + 32] = check[i];
    }

    encrypted
}

pub fn decrypt_32 (encrypted: &[u8; 64], key: &[u8; 32]) -> CommonResult<[u8; 32]> {
    let mut decrypted: [u8; 32] = [0u8; 32];

    for i in 0..32 {
        decrypted[i] = encrypted[i] ^ key[i];
    }

    let check = secure_hash(&[&decrypted]); 
    
    let mut error = false;
    for i in 0..32 {
        error = error || (check[i] != encrypted[i + 32]);
    }

    if error {
        Err(CommonError::FailedVerification(None))
    } else {
        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encryption::random_int_256;


    #[test]
    fn encrypt32_decrypt32() {
        let data = random_int_256();
        let key = random_int_256();

        let encrypted_data = encrypt_32(&data, &key);
        let decrypted_data = decrypt_32(&encrypted_data, &key).unwrap();

        assert_eq!(data, decrypted_data);
    }
}
