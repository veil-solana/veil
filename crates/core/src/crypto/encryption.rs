//! Note Encryption using ECDH + ChaCha20-Poly1305
//!
//! This module provides encryption for note data so that recipients can
//! recover their note contents from on-chain encrypted data.
//!
//! Privacy model:
//! - Sender encrypts note data (amount, blinding, asset_id) using ECDH
//! - Encrypted note is published alongside the commitment
//! - Only the recipient can decrypt using their private key
//!
//! Encryption scheme:
//! 1. Sender generates ephemeral keypair (r, R = r*G)
//! 2. Shared secret = ECDH(r, recipient_pubkey) = r * recipient_pubkey
//! 3. Derive symmetric key from shared secret using HKDF
//! 4. Encrypt note data using ChaCha20-Poly1305
//! 5. Publish (R, ciphertext) alongside the commitment
//!
//! Decryption:
//! 1. Recipient computes shared secret = ECDH(private_key, R)
//! 2. Derive symmetric key from shared secret
//! 3. Decrypt ciphertext using ChaCha20-Poly1305

use ark_bn254::Fr;
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The curve used for encryption (same as commitment curve)
type G1 = ark_bn254::G1Projective;
type G1Affine = ark_bn254::G1Affine;

/// Domain separator for key derivation
const ENCRYPTION_DOMAIN: &[u8] = b"NYX_NOTE_ENCRYPTION_V1";

/// Size of encrypted note data (before padding)
pub const NOTE_DATA_SIZE: usize = 48; // amount(8) + blinding(32) + asset_id(8)

/// Size of the encrypted note ciphertext
pub const CIPHERTEXT_SIZE: usize = NOTE_DATA_SIZE + 16; // + auth tag

/// Size of the ephemeral public key
pub const EPHEMERAL_KEY_SIZE: usize = 32;

/// Total size of an encrypted note
pub const ENCRYPTED_NOTE_SIZE: usize = EPHEMERAL_KEY_SIZE + CIPHERTEXT_SIZE;

/// Errors for encryption operations
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid ciphertext length")]
    InvalidCiphertextLength,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Note data to be encrypted
#[derive(Clone, Debug)]
pub struct NoteData {
    /// Amount in the note
    pub amount: u64,
    /// Blinding factor
    pub blinding: [u8; 32],
    /// Asset ID (0 for native SOL)
    pub asset_id: u64,
}

impl NoteData {
    /// Create new note data
    pub fn new(amount: u64, blinding: [u8; 32], asset_id: u64) -> Self {
        Self { amount, blinding, asset_id }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; NOTE_DATA_SIZE] {
        let mut bytes = [0u8; NOTE_DATA_SIZE];
        bytes[0..8].copy_from_slice(&self.amount.to_le_bytes());
        bytes[8..40].copy_from_slice(&self.blinding);
        bytes[40..48].copy_from_slice(&self.asset_id.to_le_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() < NOTE_DATA_SIZE {
            return Err(EncryptionError::InvalidCiphertextLength);
        }

        let amount = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&bytes[8..40]);
        let asset_id = u64::from_le_bytes(bytes[40..48].try_into().unwrap());

        Ok(Self { amount, blinding, asset_id })
    }
}

/// Encrypted note structure
#[derive(Clone, Debug)]
pub struct EncryptedNote {
    /// Ephemeral public key (R = r*G)
    pub ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
    /// Encrypted data + auth tag
    pub ciphertext: [u8; CIPHERTEXT_SIZE],
}

impl EncryptedNote {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; ENCRYPTED_NOTE_SIZE] {
        let mut bytes = [0u8; ENCRYPTED_NOTE_SIZE];
        bytes[0..EPHEMERAL_KEY_SIZE].copy_from_slice(&self.ephemeral_key);
        bytes[EPHEMERAL_KEY_SIZE..].copy_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() < ENCRYPTED_NOTE_SIZE {
            return Err(EncryptionError::InvalidCiphertextLength);
        }

        let mut ephemeral_key = [0u8; EPHEMERAL_KEY_SIZE];
        ephemeral_key.copy_from_slice(&bytes[0..EPHEMERAL_KEY_SIZE]);

        let mut ciphertext = [0u8; CIPHERTEXT_SIZE];
        ciphertext.copy_from_slice(&bytes[EPHEMERAL_KEY_SIZE..ENCRYPTED_NOTE_SIZE]);

        Ok(Self { ephemeral_key, ciphertext })
    }
}

/// Encryption keypair
pub struct EncryptionKeypair {
    /// Private key (scalar)
    private_key: Fr,
    /// Public key (point)
    public_key: G1,
}

impl EncryptionKeypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        use ark_ff::UniformRand;
        let private_key = Fr::rand(&mut OsRng);
        let public_key = G1::generator() * private_key;
        Self { private_key, public_key }
    }

    /// Create from a 32-byte secret
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let private_key = Fr::from_le_bytes_mod_order(secret);
        let public_key = G1::generator() * private_key;
        Self { private_key, public_key }
    }

    /// Get the public key as bytes (compressed)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        let affine = self.public_key.into_affine();
        let mut bytes = Vec::new();
        affine.serialize_compressed(&mut bytes).expect("serialization failed");

        // Pad or truncate to 32 bytes
        let mut result = [0u8; 32];
        let len = bytes.len().min(32);
        result[..len].copy_from_slice(&bytes[..len]);
        result
    }

    /// Get the private key as bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        use ark_serialize::CanonicalSerialize;
        let mut bytes = Vec::new();
        self.private_key.serialize_compressed(&mut bytes).expect("serialization failed");

        let mut result = [0u8; 32];
        let len = bytes.len().min(32);
        result[..len].copy_from_slice(&bytes[..len]);
        result
    }
}

/// Encrypt note data for a recipient
///
/// # Arguments
/// * `note_data` - The note data to encrypt
/// * `recipient_pubkey` - The recipient's public key (32 bytes)
///
/// # Returns
/// * `EncryptedNote` containing ephemeral key and ciphertext
pub fn encrypt_note(
    note_data: &NoteData,
    recipient_pubkey: &[u8; 32],
) -> Result<EncryptedNote, EncryptionError> {
    use ark_ff::UniformRand;

    // Parse recipient public key
    let recipient = G1Affine::deserialize_compressed(recipient_pubkey.as_slice())
        .map_err(|_| EncryptionError::InvalidPublicKey)?;
    let recipient_point = G1::from(recipient);

    // Generate ephemeral keypair
    let ephemeral_private = Fr::rand(&mut OsRng);
    let ephemeral_public = G1::generator() * ephemeral_private;

    // Compute shared secret via ECDH
    let shared_secret = recipient_point * ephemeral_private;

    // Derive symmetric key
    let symmetric_key = derive_symmetric_key(&shared_secret);

    // Encrypt note data
    let plaintext = note_data.to_bytes();
    let ciphertext = chacha20_poly1305_encrypt(&symmetric_key, &plaintext)?;

    // Serialize ephemeral public key
    let mut ephemeral_key = [0u8; EPHEMERAL_KEY_SIZE];
    let affine = ephemeral_public.into_affine();
    let mut key_bytes = Vec::new();
    affine.serialize_compressed(&mut key_bytes)
        .map_err(|e| EncryptionError::SerializationError(e.to_string()))?;
    let len = key_bytes.len().min(EPHEMERAL_KEY_SIZE);
    ephemeral_key[..len].copy_from_slice(&key_bytes[..len]);

    Ok(EncryptedNote {
        ephemeral_key,
        ciphertext,
    })
}

/// Decrypt an encrypted note
///
/// # Arguments
/// * `encrypted_note` - The encrypted note
/// * `private_key` - The recipient's private key (32 bytes)
///
/// # Returns
/// * `NoteData` if decryption succeeds
pub fn decrypt_note(
    encrypted_note: &EncryptedNote,
    private_key: &[u8; 32],
) -> Result<NoteData, EncryptionError> {
    // Parse private key
    let sk = Fr::from_le_bytes_mod_order(private_key);

    // Parse ephemeral public key
    let ephemeral = G1Affine::deserialize_compressed(encrypted_note.ephemeral_key.as_slice())
        .map_err(|_| EncryptionError::InvalidPublicKey)?;
    let ephemeral_point = G1::from(ephemeral);

    // Compute shared secret via ECDH
    let shared_secret = ephemeral_point * sk;

    // Derive symmetric key
    let symmetric_key = derive_symmetric_key(&shared_secret);

    // Decrypt ciphertext
    let plaintext = chacha20_poly1305_decrypt(&symmetric_key, &encrypted_note.ciphertext)?;

    // Parse note data
    NoteData::from_bytes(&plaintext)
}

/// Derive a 32-byte symmetric key from an ECDH shared secret
fn derive_symmetric_key(shared_secret: &G1) -> [u8; 32] {
    let mut point_bytes = Vec::new();
    shared_secret.into_affine().serialize_compressed(&mut point_bytes)
        .expect("serialization failed");

    // HKDF-like derivation using SHA256
    let mut hasher = Sha256::new();
    hasher.update(ENCRYPTION_DOMAIN);
    hasher.update(&point_bytes);
    hasher.update(b"symmetric_key");

    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Encrypt using ChaCha20-Poly1305 (simplified implementation)
///
/// Note: In production, use a proper ChaCha20-Poly1305 implementation
/// from a cryptography library like `chacha20poly1305`.
fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    plaintext: &[u8; NOTE_DATA_SIZE],
) -> Result<[u8; CIPHERTEXT_SIZE], EncryptionError> {
    // Simplified: XOR with key-derived stream + append MAC
    // In production, use proper ChaCha20-Poly1305
    let mut ciphertext = [0u8; CIPHERTEXT_SIZE];

    // Derive stream from key
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(b"stream");
    let stream = hasher.finalize();

    // XOR plaintext with stream (simplified encryption)
    for i in 0..NOTE_DATA_SIZE {
        ciphertext[i] = plaintext[i] ^ stream[i % 32];
    }

    // Compute MAC
    let mut mac_hasher = Sha256::new();
    mac_hasher.update(key);
    mac_hasher.update(&ciphertext[..NOTE_DATA_SIZE]);
    let mac = mac_hasher.finalize();

    // Append MAC (truncated to 16 bytes)
    ciphertext[NOTE_DATA_SIZE..].copy_from_slice(&mac[..16]);

    Ok(ciphertext)
}

/// Decrypt using ChaCha20-Poly1305 (simplified implementation)
fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    ciphertext: &[u8; CIPHERTEXT_SIZE],
) -> Result<[u8; NOTE_DATA_SIZE], EncryptionError> {
    // Verify MAC first
    let mut mac_hasher = Sha256::new();
    mac_hasher.update(key);
    mac_hasher.update(&ciphertext[..NOTE_DATA_SIZE]);
    let computed_mac = mac_hasher.finalize();

    // Compare MACs (constant time would be better in production)
    if &computed_mac[..16] != &ciphertext[NOTE_DATA_SIZE..] {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Derive stream from key
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(b"stream");
    let stream = hasher.finalize();

    // XOR ciphertext with stream
    let mut plaintext = [0u8; NOTE_DATA_SIZE];
    for i in 0..NOTE_DATA_SIZE {
        plaintext[i] = ciphertext[i] ^ stream[i % 32];
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_data_serialization() {
        let note = NoteData::new(1000, [42u8; 32], 0);
        let bytes = note.to_bytes();
        let decoded = NoteData::from_bytes(&bytes).unwrap();

        assert_eq!(note.amount, decoded.amount);
        assert_eq!(note.blinding, decoded.blinding);
        assert_eq!(note.asset_id, decoded.asset_id);
    }

    #[test]
    fn test_encryption_roundtrip() {
        // Generate recipient keypair
        let recipient = EncryptionKeypair::generate();
        let recipient_pubkey = recipient.public_key_bytes();
        let recipient_privkey = recipient.private_key_bytes();

        // Create note data
        let note = NoteData::new(1_000_000_000, [123u8; 32], 0);

        // Encrypt
        let encrypted = encrypt_note(&note, &recipient_pubkey).unwrap();

        // Decrypt
        let decrypted = decrypt_note(&encrypted, &recipient_privkey).unwrap();

        assert_eq!(note.amount, decrypted.amount);
        assert_eq!(note.blinding, decrypted.blinding);
        assert_eq!(note.asset_id, decrypted.asset_id);
    }

    #[test]
    fn test_wrong_key_fails() {
        let recipient = EncryptionKeypair::generate();
        let wrong_key = EncryptionKeypair::generate();

        let note = NoteData::new(1000, [1u8; 32], 0);
        let encrypted = encrypt_note(&note, &recipient.public_key_bytes()).unwrap();

        // Decrypting with wrong key should fail
        let result = decrypt_note(&encrypted, &wrong_key.private_key_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_note_serialization() {
        let recipient = EncryptionKeypair::generate();
        let note = NoteData::new(500, [5u8; 32], 1);
        let encrypted = encrypt_note(&note, &recipient.public_key_bytes()).unwrap();

        // Serialize and deserialize
        let bytes = encrypted.to_bytes();
        let restored = EncryptedNote::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.ephemeral_key, restored.ephemeral_key);
        assert_eq!(encrypted.ciphertext, restored.ciphertext);
    }
}
