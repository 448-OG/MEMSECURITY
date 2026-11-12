//! This module contains types and methods used to create a sealing key that stretches across multiple
//! memory pages ensuring impossible key recovery if certain attacks are used to try and recover the key.
//! These attacks are specified in the crate documentation.

use core::fmt;

use zeroize::Zeroizing;

use crate::MemSecurityResult;

#[cfg(all(feature = "symm_asymm", feature = "random"))]
use random_detached::{Generator, RandomBytes};

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
///     ciphertext: Zeroizing<Vec<u8>>,
///     nonce: AsconNonce,
/// }
/// ```
pub struct EncryptedMem {
    ciphertext: Zeroizing<Vec<u8>>,
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
            ciphertext: Zeroizing::new(Vec::new()),
            #[cfg(feature = "encryption")]
            nonce: AsconNonce::try_from(nonce.expose().as_ref())?,
        })
    }

    /// Expose the ciphertext
    pub fn ciphertext(&self) -> &Zeroizing<Vec<u8>> {
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
            .field("ciphertext", &blake3::hash(&self.ciphertext))
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
        EncryptedMem, MemSecurityErr, MemSecurityResult, DEFAULT_VAULT_PAGES,
        DEFAULT_VAULT_PAGE_SIZE,
    };
    use ascon_aead::{
        aead::{Aead, KeyInit},
        AsconAead128, AsconAead128Key,
    };
    use core::ops::Deref;
    use once_cell::sync::Lazy;
    use random_detached::{Generator, RandomBytes};
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    static SEALING_KEY: Lazy<SealingKey<DEFAULT_VAULT_PAGES, DEFAULT_VAULT_PAGE_SIZE>> =
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
    }

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> Zeroize
        for SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
        fn zeroize(&mut self) {
            self.0.zeroize();
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
            let kek = LockedKek::new(&mut kek);

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            let outcome = match cipher.encrypt(&self.nonce, plaintext.as_ref()) {
                Ok(ciphertext) => Ok(ciphertext),
                Err(_) => Err(MemSecurityErr::EncryptionErr),
            };

            self.ciphertext = Zeroizing::new(outcome?);

            Ok(self)
        }

        /// Performs an decryption operation.
        pub fn decrypt(&self) -> MemSecurityResult<Zeroizing<Vec<u8>>> {
            let mut kek = SEALING_KEY.kek();
            let kek = LockedKek::new(&mut kek);

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            match cipher.decrypt(&self.nonce, self.ciphertext.as_slice()) {
                Ok(plaintext) => Ok(Zeroizing::new(plaintext)),
                Err(_) => Err(MemSecurityErr::EncryptionErr),
            }
        }

        /// Hash some bytes with Blake3 using a key to create a HMAC
        pub fn blake3_hmac<T: Zeroize + AsRef<[u8]>>(plaintext: T) -> blake3::Hash {
            let mut kek = SEALING_KEY.kek();
            let kek = LockedKek::new(&mut kek);

            blake3::keyed_hash(&kek, plaintext.as_ref())
        }

        /// Hash some an array of bytes with Blake3 using a key to create a HMAC
        pub fn blake3_keyed_hash_with_array<T: Zeroize + AsRef<[u8]>>(
            plaintext_array: &[T],
        ) -> blake3::Hash {
            let mut kek = SEALING_KEY.kek();
            let kek = LockedKek::new(&mut kek);

            let mut hasher = blake3::Hasher::new_keyed(&kek);
            plaintext_array.iter().for_each(|plaintext| {
                hasher.update(plaintext.as_ref());
            });

            hasher.finalize()
        }

        /// Hash a predetermined content with Blake3 using a secret key to derive a key (HKDF)
        pub fn blake3_hkdf(plaintext: &str) -> [u8; blake3::OUT_LEN] {
            let mut kek = SEALING_KEY.kek();
            let kek = LockedKek::new(&mut kek);

            blake3::derive_key(plaintext, &*kek)
        }

        /// Performs an decryption operation expecting a 16 byte array that is zeroed when dropped.
        pub fn decrypt_16byte(&self) -> MemSecurityResult<Zeroizing<[u8; 16]>> {
            let mut kek = SEALING_KEY.kek();
            let kek = LockedKek::new(&mut kek);

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            match cipher.decrypt(&self.nonce, self.ciphertext.as_slice()) {
                Ok(plaintext) => {
                    let plaintext = Zeroizing::new(plaintext);
                    let plaintext_len = plaintext.len();
                    if plaintext_len != crate::SECRET_KEY_16BYTE {
                        Err(MemSecurityErr::InvalidArrayLength {
                            expected: crate::SECRET_KEY_16BYTE,
                            found: plaintext_len,
                        })
                    } else {
                        let mut array = Zeroizing::new([0u8; crate::SECRET_KEY_16BYTE]);
                        array.copy_from_slice(&plaintext);

                        Ok(array)
                    }
                }
                Err(_) => Err(MemSecurityErr::EncryptionErr),
            }
        }

        /// Performs an decryption operation expecting a 32 byte array that is zeroed when dropped.
        pub fn decrypt_32byte(&self) -> MemSecurityResult<Zeroizing<[u8; 32]>> {
            let mut kek = SEALING_KEY.kek();
            let kek = LockedKek::new(&mut kek);

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            match cipher.decrypt(&self.nonce, self.ciphertext.as_slice()) {
                Ok(plaintext) => {
                    let plaintext = Zeroizing::new(plaintext);
                    let plaintext_len = plaintext.len();
                    if plaintext_len != crate::SECRET_KEY_32BYTE {
                        Err(MemSecurityErr::InvalidArrayLength {
                            expected: crate::SECRET_KEY_32BYTE,
                            found: plaintext_len,
                        })
                    } else {
                        let mut array = Zeroizing::new([0u8; crate::SECRET_KEY_32BYTE]);
                        array.copy_from_slice(&plaintext);

                        Ok(array)
                    }
                }
                Err(_) => Err(MemSecurityErr::EncryptionErr),
            }
        }

        /// Sign a message and return an Ed25519 digital signature
        #[cfg(feature = "ed25519")]
        pub fn sign<T: Zeroize + AsRef<[u8]>>(
            &self,
            message: T,
        ) -> MemSecurityResult<ed25519_dalek::Signature> {
            use ed25519_dalek::{Signer, SigningKey};

            let encrypted_key = self.decrypt_32byte()?;

            let signing_key = SigningKey::from_bytes(&encrypted_key);

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

            let x25519_static_key = StaticSecret::from(*encrypted_key);

            drop(encrypted_key);

            Ok(x25519_static_key.diffie_hellman(&x25519_public_key))
        }

        /// Generate the public key assuming that that secret key was added as an X25519 static secret
        #[cfg(feature = "x25519")]
        pub fn x25519_public_key(&self) -> MemSecurityResult<x25519_dalek::PublicKey> {
            use x25519_dalek::{PublicKey, StaticSecret};

            let encrypted_key = self.decrypt_32byte()?;

            let x25519_static_key = StaticSecret::from(*encrypted_key);

            drop(encrypted_key);

            Ok(PublicKey::from(&x25519_static_key))
        }

        /// Generate a new version 4 UUID and encrypt it immediately
        #[cfg(feature = "uuid")]
        pub fn encrypt_uuid(&mut self) -> MemSecurityResult<&mut Self> {
            use uuid::Uuid;

            self.encrypt(Uuid::new_v4().as_bytes())?;

            Ok(self)
        }

        /// Decrypt a version 4 UUID
        #[cfg(feature = "uuid")]
        pub fn decrypt_uuid(&mut self) -> MemSecurityResult<Zeroizing<[u8; 16]>> {
            self.decrypt_16byte()
        }
    }

    /// The KEK, locked in memory while it is borrowed. Unlocking it on
    /// drop also wipes it, so every return path leaves it zeroed.
    struct LockedKek<'a>(&'a mut [u8; blake3::OUT_LEN]);

    impl<'a> LockedKek<'a> {
        #[allow(unsafe_code)]
        fn new(kek: &'a mut [u8; blake3::OUT_LEN]) -> Self {
            unsafe { memsec::mlock(kek.as_mut_ptr(), blake3::OUT_LEN) }; //TODO Handle this bool

            LockedKek(kek)
        }
    }

    impl Deref for LockedKek<'_> {
        type Target = [u8; blake3::OUT_LEN];

        fn deref(&self) -> &Self::Target {
            self.0
        }
    }

    impl Drop for LockedKek<'_> {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // munlock zeroes the memory before unlocking it.
            unsafe { memsec::munlock(self.0.as_mut_ptr(), blake3::OUT_LEN) }; //TODO Handle this bool

            debug_assert_eq!(*self.0, [0u8; blake3::OUT_LEN]);
        }
    }
}
