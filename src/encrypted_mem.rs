//! This module contains types and methods used to create a sealing key that stretches across multiple
//! memory pages ensuring impossible key recovery if certain attacks are used to try and recover the key.
//! These attacks are specified in the crate documentation.

use core::fmt;

use crate::MemSecurityResult;

#[cfg(all(feature = "symm_asymm", feature = "random"))]
use {
    crate::ZeroizeBytes,
    random_detached::{Generator, RandomBytes},
};

type AsconNonce = ascon_aead::AsconAead128Nonce;

/// The length of a 16 byte secret key
pub const SECRET_KEY_16BYTE: usize = 16;
/// The length of a 32 byte secret key
pub const SECRET_KEY_32BYTE: usize = 32;
/// The nonce length of Ascon 128 cipher
pub const ASCON128_NONCE_LEN: usize = 16;

/// The number of pages used to accommodate one page of 4KiB in size.
pub const DEFAULT_VAULT_PAGES: usize = 4;
/// A size in KiB of one page (a page is a fixed-size block of memory used by the operating system to manage memory)
pub const DEFAULT_VAULT_PAGE_SIZE: usize = 4096_usize;
/// The layout of the bytes used to create the key
pub type VaultPagesLayout<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> =
    [[u8; VAULT_PAGE_SIZE]; VAULT_PAGES];

/// A struct that holds the encrypted secret and performs encryption and decryption on the secret.
/// #### Structure
/// ```rs
/// pub struct EncryptedMem {
///     ciphertext: ZeroizeBytes,
///     nonce: AsconNonce,
/// }
/// ```
pub struct EncryptedMem {
    ciphertext: ZeroizeBytes,
    #[cfg(feature = "encryption")]
    nonce: AsconNonce,
}

impl EncryptedMem {
    /// Initializes a new [EncryptedMem]
    /// #### Usage
    /// ```rs
    /// let data = EncryptedMem::new();
    /// ```
    pub fn new() -> MemSecurityResult<Self> {
        let nonce = RandomBytes::<ASCON128_NONCE_LEN>::new()?;

        assert_ne!(*nonce.expose(), [0u8; ASCON128_NONCE_LEN]);

        Ok(EncryptedMem {
            ciphertext: ZeroizeBytes::new(),
            #[cfg(feature = "encryption")]
            nonce: AsconNonce::try_from(nonce.expose().as_ref())?,
        })
    }

    /// Expose the ciphertext
    pub fn ciphertext(&self) -> &ZeroizeBytes {
        &self.ciphertext
    }

    /// Expose Nonce
    #[cfg(feature = "encryption")]
    pub fn nonce(&self) -> &AsconNonce {
        &self.nonce
    }
}

impl fmt::Debug for EncryptedMem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedMem")
            .field(
                "ciphertext",
                &blake3::hash(self.ciphertext.expose_borrowed()),
            )
            .field("nonce", &blake3::hash(self.nonce.as_ref()))
            .finish()
    }
}

/// The struct used to hold the sealing key used for encrypt data
/// while it's loaded in memory.
/// #### Structure
/// ```rs
/// pub struct SealingKey<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>(
///     [[u8; VAULT_PAGE_SIZE]; VAULT_PAGES],
/// );
/// ```
pub struct SealingKey<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>(
    [[u8; VAULT_PAGE_SIZE]; VAULT_PAGES],
);

mod key_ops {
    use super::SealingKey;
    use crate::{
        EncryptedMem, MemSecurityErr, MemSecurityResult, ZeroizeArray, ZeroizeBytes,
        DEFAULT_VAULT_PAGES, DEFAULT_VAULT_PAGE_SIZE,
    };
    use ascon_aead::{
        aead::{Aead, KeyInit},
        AsconAead128, AsconAead128Key,
    };
    use once_cell::sync::Lazy;
    use random_detached::{Generator, RandomBytes};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    static SEALING_KEY: Lazy<SealingKey<DEFAULT_VAULT_PAGE_SIZE, DEFAULT_VAULT_PAGES>> =
        Lazy::new(|| SealingKey::new().unwrap());

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>
        SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
        fn new() -> MemSecurityResult<Self> {
            let mut pages = [[0u8; VAULT_PAGE_SIZE]; VAULT_PAGES];

            (0..VAULT_PAGES).try_for_each(|vault_page_index| {
                pages[vault_page_index] = *RandomBytes::<VAULT_PAGE_SIZE>::new()?.expose();

                Ok::<_, MemSecurityErr>(())
            })?;

            let mut outcome = SealingKey(pages);
            outcome.lock_pages();

            Ok(outcome)
        }

        #[allow(unsafe_code)]
        fn lock_pages(&mut self) {
            self.0.iter_mut().for_each(|page| unsafe {
                memsec::mlock(page.as_mut_slice().as_mut_ptr(), VAULT_PAGE_SIZE);
                //TODO Handle this bool
            });
        }

        #[allow(unsafe_code)]
        fn munlock_pages(&mut self) {
            self.0.iter_mut().for_each(|page| unsafe {
                memsec::munlock(page.as_mut_slice().as_mut_ptr(), VAULT_PAGE_SIZE);
                //TODO Handle this bool
            });
        }

        fn kek(&self) -> [u8; blake3::OUT_LEN] {
            let mut hasher = blake3::Hasher::new();
            self.0.iter().for_each(|page| {
                hasher.update(page);
            });

            *hasher.finalize().as_bytes()
        }

        #[allow(unsafe_code)]
        fn mlock_kek(&self, ptr: *mut u8) -> bool {
            unsafe { memsec::mlock(ptr, blake3::OUT_LEN) }
        }

        #[allow(unsafe_code)]
        fn munlock_kek(&self, ptr: *mut u8) -> bool {
            unsafe { memsec::munlock(ptr, blake3::OUT_LEN) }
        }
    }

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> Zeroize
        for SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
        fn zeroize(&mut self) {
            self.0 = [[0u8; VAULT_PAGE_SIZE]; VAULT_PAGES];
        }
    }

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> ZeroizeOnDrop
        for SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
    }

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> Drop
        for SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
        fn drop(&mut self) {
            self.munlock_pages();

            #[cfg(debug_assertions)]
            self.0
                .iter()
                .for_each(|page| debug_assert_eq!(page, &[0u8; VAULT_PAGE_SIZE]))
        }
    }

    impl EncryptedMem {
        /// Performs an encryption operation.
        pub fn encrypt<T: Zeroize + AsRef<[u8]>>(
            &mut self,
            plaintext: &T,
        ) -> MemSecurityResult<&mut Self> {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();
            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            let outcome = match cipher.encrypt(&self.nonce, plaintext.as_ref()) {
                Ok(ciphertext) => Ok(ciphertext),
                Err(_) => Err(MemSecurityErr::EncryptionErr),
            };

            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; blake3::OUT_LEN]);

            self.ciphertext = ZeroizeBytes::new_with_data(&outcome?);

            Ok(self)
        }

        /// Performs an decryption operation.
        pub fn decrypt(&self) -> MemSecurityResult<ZeroizeBytes> {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();
            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            let outcome =
                match cipher.decrypt(&self.nonce, self.ciphertext.expose_borrowed().as_ref()) {
                    Ok(plaintext) => Ok(ZeroizeBytes::new_with_data(&plaintext)),
                    Err(_) => Err(MemSecurityErr::EncryptionErr),
                };

            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; blake3::OUT_LEN]);

            outcome
        }

        /// Hash some bytes with Blake3 using a key to create a HMAC
        pub fn blake3_hmac<T: Zeroize + AsRef<[u8]>>(plaintext: T) -> blake3::Hash {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();

            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let outcome = blake3::keyed_hash(&kek, plaintext.as_ref());
            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; 32]);

            outcome
        }

        /// Hash some an array of bytes with Blake3 using a key to create a HMAC
        pub fn blake3_keyed_hash_with_array<T: Zeroize + AsRef<[u8]>>(
            plaintext_array: &[T],
        ) -> blake3::Hash {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();

            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let mut hasher = blake3::Hasher::new_keyed(&kek);
            plaintext_array.iter().for_each(|plaintext| {
                hasher.update(plaintext.as_ref());
            });

            let outcome = hasher.finalize();

            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; 32]);

            outcome
        }

        /// Hash a predetermined content with Blake3 using a secret key to derive a key (HKDF)
        pub fn blake3_hkdf(plaintext: &str) -> [u8; blake3::OUT_LEN] {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();

            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let outcome = blake3::derive_key(plaintext, &kek);
            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; 32]);

            outcome
        }

        /// Performs an decryption operation expecting a 16 byte array that is zeroed when dropped.
        pub fn decrypt_16byte(&self) -> MemSecurityResult<ZeroizeArray<16>> {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();
            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            let outcome =
                match cipher.decrypt(&self.nonce, self.ciphertext.expose_borrowed().as_ref()) {
                    Ok(plaintext) => {
                        let plaintext_len = plaintext.len();
                        if plaintext_len != crate::SECRET_KEY_16BYTE {
                            return Err(MemSecurityErr::InvalidArrayLength {
                                expected: crate::SECRET_KEY_16BYTE,
                                found: plaintext_len,
                            });
                        } else {
                            ZeroizeArray::<{ crate::SECRET_KEY_16BYTE }>::new_from_slice(&plaintext)
                        }
                    }
                    Err(_) => Err(MemSecurityErr::EncryptionErr),
                };

            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; blake3::OUT_LEN]);

            outcome
        }

        /// Performs an decryption operation expecting a 32 byte array that is zeroed when dropped.
        pub fn decrypt_32byte(&self) -> MemSecurityResult<ZeroizeArray<32>> {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();
            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            let outcome =
                match cipher.decrypt(&self.nonce, self.ciphertext.expose_borrowed().as_ref()) {
                    Ok(plaintext) => {
                        let plaintext_len = plaintext.len();
                        if plaintext_len != crate::SECRET_KEY_32BYTE {
                            return Err(MemSecurityErr::InvalidArrayLength {
                                expected: crate::SECRET_KEY_32BYTE,
                                found: plaintext_len,
                            });
                        } else {
                            ZeroizeArray::<{ crate::SECRET_KEY_32BYTE }>::new_from_slice(&plaintext)
                        }
                    }
                    Err(_) => Err(MemSecurityErr::EncryptionErr),
                };

            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; blake3::OUT_LEN]);

            outcome
        }

        /// Sign a message and return an Ed25519 digital signature
        #[cfg(feature = "ed25519")]
        pub fn sign<T: Zeroize + AsRef<[u8]>>(
            &self,
            message: T,
        ) -> MemSecurityResult<ed25519_dalek::Signature> {
            use ed25519_dalek::{Signer, SigningKey};

            let encrypted_key = self.decrypt_32byte()?;

            let signing_key = SigningKey::from_bytes(encrypted_key.expose_borrowed());

            drop(encrypted_key);

            Ok(signing_key.sign(message.as_ref()))
        }

        /// Perform a Diffie-Hellman key exchange of a secret key
        /// assuming that that secret key was added as an X25519 static secret
        #[cfg(feature = "x25519")]
        pub fn x25519_dh(
            &self,
            x25519_public_key: x25519_dalek::PublicKey,
        ) -> MemSecurityResult<x25519_dalek::SharedSecret> {
            use x25519_dalek::StaticSecret;

            let encrypted_key = self.decrypt_32byte()?;

            let x25519_static_key = StaticSecret::from(*encrypted_key.expose_borrowed());

            drop(encrypted_key);

            Ok(x25519_static_key.diffie_hellman(&x25519_public_key))
        }

        /// Generate the public key assuming that that secret key was added as an X25519 static secret
        #[cfg(feature = "x25519")]
        pub fn x25519_public_key(&self) -> MemSecurityResult<x25519_dalek::PublicKey> {
            use x25519_dalek::{PublicKey, StaticSecret};

            let encrypted_key = self.decrypt_32byte()?;

            let x25519_static_key = StaticSecret::from(*encrypted_key.expose_borrowed());

            drop(encrypted_key);

            Ok(PublicKey::from(&x25519_static_key))
        }

        /// Generate a new version 4 UUID and encrypt it immediately
        #[cfg(feature = "uuid")]
        pub fn encrypt_uuid(&mut self) -> MemSecurityResult<&mut Self> {
            use uuid::Uuid;

            let uuid_bytes = ZeroizeBytes::new_with_data(Uuid::new_v4().as_bytes());
            self.encrypt(&uuid_bytes)?;

            Ok(self)
        }

        /// Decrypt a version 4 UUID
        #[cfg(feature = "uuid")]
        pub fn decrypt_uuid(&mut self) -> MemSecurityResult<ZeroizeArray<16>> {
            self.decrypt_16byte()
        }
    }
}
