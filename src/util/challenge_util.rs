
/*use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use base64::{Engine as _, engine::general_purpose};
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use rand::Rng;
use rand::distr::Alphanumeric;
use sha2::{Digest, Sha256};

pub fn generate_challenge_and_encrypt(
    password: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Hash the password to derive a key
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let key = GenericArray::from_slice(&hash[..16]); // AES-128 uses 16-byte key

    let cipher = Aes128::new(&key);

    // Generate 32-byte plaintext
    let plaintext: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let plaintext_bytes = plaintext.as_bytes();

    // Encrypt in two 16-byte blocks
    let mut block1 = GenericArray::clone_from_slice(&plaintext_bytes[..16]);
    let mut block2 = GenericArray::clone_from_slice(&plaintext_bytes[16..32]);

    cipher.encrypt_block(&mut block1);
    cipher.encrypt_block(&mut block2);

    // Concatenate encrypted blocks
    let mut ciphertext = Vec::with_capacity(32);
    ciphertext.extend_from_slice(&block1);
    ciphertext.extend_from_slice(&block2);

    // Base64 encode both plaintext and ciphertext
    let plaintext_b64 = general_purpose::STANDARD.encode(plaintext_bytes);
    let ciphertext_b64 = general_purpose::STANDARD.encode(&ciphertext);

    Ok((plaintext_b64, ciphertext_b64))
}

pub fn decrypt_aes_ecb_base64(password: &str, ciphertext_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Derive 128-bit key from SHA256(password)
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let key = GenericArray::from_slice(&hash[..16]);

    // Decode Base64 ciphertext
    let encrypted_bytes = general_purpose::STANDARD.decode(ciphertext_b64)?;

    if encrypted_bytes.len() != 32 {
        return Err("Ciphertext must be exactly 32 bytes (2 AES blocks)".into());
    }

    // Split into two blocks
    let mut block1 = GenericArray::clone_from_slice(&encrypted_bytes[..16]);
    let mut block2 = GenericArray::clone_from_slice(&encrypted_bytes[16..]);

    // Decrypt blocks
    let cipher = Aes128::new(&key);
    cipher.decrypt_block(&mut block1);
    cipher.decrypt_block(&mut block2);

    // Concatenate decrypted blocks
    let mut decrypted = Vec::with_capacity(32);
    decrypted.extend_from_slice(&block1);
    decrypted.extend_from_slice(&block2);

    // Base64-encode the decrypted plaintext (to match encryption output format)
    let plaintext_b64 = general_purpose::STANDARD.encode(&decrypted);

    Ok(plaintext_b64)
}*/
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
