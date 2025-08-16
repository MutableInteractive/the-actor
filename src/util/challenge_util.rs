use base64::{engine::general_purpose, Engine as _};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::distr::Alphanumeric;
use rand::Rng;
use sha2::{Digest, Sha256};

pub fn generate_challenge_and_encrypt(
    password: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Hash password to get 128-bit key (first 16 bytes of SHA-256)
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let key = &hash[..16]; // AES-128 key

    let cipher = Cipher::aes_128_ecb();

    // 32-byte random plaintext (2 AES blocks)
    let plaintext: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let plaintext_bytes = plaintext.as_bytes();

    // Create Crypter in ECB mode with no padding
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;
    crypter.pad(false);

    let mut ciphertext = vec![0u8; plaintext_bytes.len() + cipher.block_size()];
    let count = crypter.update(plaintext_bytes, &mut ciphertext)?;
    let rest = crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count + rest);

    let plaintext_b64 = general_purpose::STANDARD.encode(plaintext_bytes);
    let ciphertext_b64 = general_purpose::STANDARD.encode(&ciphertext);

    Ok((plaintext_b64, ciphertext_b64))
}

pub fn decrypt_aes_ecb_base64(
    password: &str,
    ciphertext_b64: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Hash password to get 128-bit key
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let key = &hash[..16];

    let encrypted_bytes = general_purpose::STANDARD.decode(ciphertext_b64)?;

    if encrypted_bytes.len() != 32 {
        return Err("Ciphertext must be exactly 32 bytes (2 AES blocks)".into());
    }

    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None)?;
    crypter.pad(false);

    let mut decrypted = vec![0u8; encrypted_bytes.len() + cipher.block_size()];
    let count = crypter.update(&encrypted_bytes, &mut decrypted)?;
    let rest = crypter.finalize(&mut decrypted[count..])?;
    decrypted.truncate(count + rest);

    let plaintext_b64 = general_purpose::STANDARD.encode(&decrypted);
    Ok(plaintext_b64)
}
