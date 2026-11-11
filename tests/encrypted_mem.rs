//! Behavioural tests for `EncryptedMem` decryption, including the error
//! paths of the in-place decrypt.

#![cfg(feature = "encryption")]

use memsecurity::{EncryptedMem, MemSecurityErr};

// Secrets of several lengths, including none, decrypt to what was encrypted.
#[test]
fn decrypt_roundtrip() {
    for len in [0usize, 1, 15, 16, 17, 64] {
        let plaintext: Vec<u8> = (0u8..).take(len).collect();

        let mut secret = EncryptedMem::new().unwrap();
        secret.encrypt(&plaintext).unwrap();

        let decrypted = secret.decrypt().unwrap();
        assert_eq!(decrypted.as_slice(), &plaintext[..]);
    }
}

// The fixed-size decrypt functions return the encrypted bytes.
#[test]
fn decrypt_array_roundtrip() {
    let mut secret = EncryptedMem::new().unwrap();
    secret.encrypt(&[7u8; 16]).unwrap();
    assert_eq!(secret.decrypt_16byte().unwrap().as_slice(), &[7u8; 16]);

    secret.encrypt(&[9u8; 32]).unwrap();
    assert_eq!(secret.decrypt_32byte().unwrap().as_slice(), &[9u8; 32]);
}

// A secret of the wrong length is reported with both lengths.
#[test]
fn decrypt_array_rejects_wrong_length() {
    let mut secret = EncryptedMem::new().unwrap();
    secret.encrypt(&[1u8; 16]).unwrap();

    assert_eq!(
        secret.decrypt_32byte().unwrap_err(),
        MemSecurityErr::InvalidArrayLength {
            expected: 32,
            found: 16
        }
    );

    secret.encrypt(&[1u8; 32]).unwrap();

    assert_eq!(
        secret.decrypt_16byte().unwrap_err(),
        MemSecurityErr::InvalidArrayLength {
            expected: 16,
            found: 32
        }
    );
}

// Nothing has been encrypted yet, so there is no tag to verify.
#[test]
fn decrypt_without_ciphertext_fails() {
    let secret = EncryptedMem::new().unwrap();

    assert_eq!(secret.decrypt().unwrap_err(), MemSecurityErr::EncryptionErr);
}
