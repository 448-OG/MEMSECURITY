//! This module contains types and methods used to create a large, locked sealing key. The key encryption
//! key is derived by hashing the whole block with Blake3, so recovering it through attacks such as
//! Rowhammer or RAMBleed would require every bit of the block. These attacks are specified in the crate
//! documentation.

use core::{fmt, ptr::NonNull};

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

/// The smallest sealing key accepted, 16KiB, matching the OpenSSL implementation.
pub const MIN_SEALING_KEY_SIZE: usize = 16 * 1024;
/// The default size of the sealing key, 16KiB.
pub const DEFAULT_SEALING_KEY_SIZE: usize = MIN_SEALING_KEY_SIZE;

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
/// pub struct SealingKey<const SEALING_KEY_SIZE: usize>(NonNull<[u8; SEALING_KEY_SIZE]>);
/// ```
/// The block is allocated with `memsec::malloc`: page-aligned, locked,
/// and fenced by guard pages.
pub struct SealingKey<const SEALING_KEY_SIZE: usize>(NonNull<[u8; SEALING_KEY_SIZE]>);

mod key_ops {
    use super::SealingKey;
    use crate::{
        DEFAULT_SEALING_KEY_SIZE, EncryptedMem, MIN_SEALING_KEY_SIZE, MemSecurityErr,
        MemSecurityResult,
    };
    use ascon_aead::{
        AsconAead128, AsconAead128Key, AsconAead128Tag,
        aead::{Aead, AeadInOut, KeyInit, inout::InOutBuf},
    };
    use core::ops::Deref;
    use once_cell::sync::Lazy;
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    /// The length of the Ascon-AEAD128 authentication tag, which follows
    /// the ciphertext.
    const ASCON128_TAG_LEN: usize = 16;

    static SEALING_KEY: Lazy<SealingKey<DEFAULT_SEALING_KEY_SIZE>> =
        Lazy::new(|| SealingKey::new().unwrap());

    impl<const SEALING_KEY_SIZE: usize> SealingKey<SEALING_KEY_SIZE> {
        pub(super) fn new() -> MemSecurityResult<Self> {
            if SEALING_KEY_SIZE < MIN_SEALING_KEY_SIZE {
                return Err(MemSecurityErr::SealingKeyTooSmall {
                    minimum: MIN_SEALING_KEY_SIZE,
                    found: SEALING_KEY_SIZE,
                });
            }

            // `malloc` returns a page-aligned block with guard pages which
            // is already locked.
            #[allow(unsafe_code)]
            let block = unsafe { memsec::malloc::<[u8; SEALING_KEY_SIZE]>() }
                .ok_or(MemSecurityErr::AllocationErr)?;

            // If filling fails, dropping `outcome` frees the block.
            let mut outcome = SealingKey(block);
            random_detached::getrandom::fill(outcome.as_mut_slice())?;

            Ok(outcome)
        }

        #[allow(unsafe_code)]
        fn as_slice(&self) -> &[u8] {
            // SAFETY: the block is live until `drop`.
            unsafe { self.0.as_ref() }
        }

        #[allow(unsafe_code)]
        fn as_mut_slice(&mut self) -> &mut [u8] {
            // SAFETY: as above, and `&mut self` guarantees exclusive access.
            unsafe { self.0.as_mut() }
        }

        fn kek(&self) -> [u8; blake3::OUT_LEN] {
            *blake3::hash(self.as_slice()).as_bytes()
        }
    }

    // SAFETY: the block is owned by the `SealingKey` and only mutated through
    // `&mut self`, so sharing `&SealingKey` across threads is read-only.
    #[allow(unsafe_code)]
    unsafe impl<const SEALING_KEY_SIZE: usize> Send for SealingKey<SEALING_KEY_SIZE> {}
    #[allow(unsafe_code)]
    unsafe impl<const SEALING_KEY_SIZE: usize> Sync for SealingKey<SEALING_KEY_SIZE> {}

    impl<const SEALING_KEY_SIZE: usize> Zeroize for SealingKey<SEALING_KEY_SIZE> {
        fn zeroize(&mut self) {
            self.as_mut_slice().zeroize();
        }
    }

    impl<const SEALING_KEY_SIZE: usize> ZeroizeOnDrop for SealingKey<SEALING_KEY_SIZE> {}

    impl<const SEALING_KEY_SIZE: usize> Drop for SealingKey<SEALING_KEY_SIZE> {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            self.zeroize();

            debug_assert!(
                self.as_slice().iter().all(|&byte| byte == 0),
                "sealing key was not wiped"
            );

            // SAFETY: the block came from `memsec::malloc`.
            unsafe { memsec::free(self.0) };
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

        /// Performs a decryption operation.
        ///
        /// The plaintext is only ever written into the returned
        /// [Zeroizing] buffer, so no unwiped copy is left in freed memory.
        ///
        /// # Errors
        ///
        /// [MemSecurityErr::EncryptionErr] if nothing has been encrypted,
        /// the ciphertext is shorter than its tag, or authentication fails.
        pub fn decrypt(&self) -> MemSecurityResult<Zeroizing<Vec<u8>>> {
            let mut plaintext = Zeroizing::new(vec![0u8; self.plaintext_len()?]);
            self.decrypt_into(&mut plaintext)?;

            Ok(plaintext)
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

        /// Performs a decryption operation expecting a 16 byte array that is zeroed when dropped.
        ///
        /// The plaintext is only ever written into the returned
        /// [Zeroizing] array. Moving the array out of this function can still
        /// leave a copy in a stack frame that is not wiped.
        /// [EncryptedMem::with_decrypted_16byte] avoids the move.
        ///
        /// # Errors
        ///
        /// - [MemSecurityErr::InvalidArrayLength] if the secret is not 16
        ///   bytes long. This is checked before authenticating.
        /// - [MemSecurityErr::EncryptionErr] if nothing has been
        ///   encrypted, the ciphertext is shorter than its tag, or
        ///   authentication fails.
        pub fn decrypt_16byte(&self) -> MemSecurityResult<Zeroizing<[u8; 16]>> {
            self.decrypt_array()
        }

        /// Performs a decryption operation expecting a 32 byte array that is zeroed when dropped.
        ///
        /// The plaintext is only ever written into the returned
        /// [Zeroizing] array. Moving the array out of this function can still
        /// leave a copy in a stack frame that is not wiped.
        /// [EncryptedMem::with_decrypted_32byte] avoids the move.
        ///
        /// # Errors
        ///
        /// - [MemSecurityErr::InvalidArrayLength] if the secret is not 32
        ///   bytes long. This is checked before authenticating.
        /// - [MemSecurityErr::EncryptionErr] if nothing has been
        ///   encrypted, the ciphertext is shorter than its tag, or
        ///   authentication fails.
        pub fn decrypt_32byte(&self) -> MemSecurityResult<Zeroizing<[u8; 32]>> {
            self.decrypt_array()
        }

        /// Decrypts a 16 byte secret and lends it to `f`.
        ///
        /// The plaintext stays in one buffer that is wiped when `f`
        /// returns, so unlike [EncryptedMem::decrypt_16byte] it is never
        /// moved. Whatever `f` returns is the caller's to wipe.
        ///
        /// ```rs
        /// let first_byte = secret.with_decrypted_16byte(|key| key[0])?;
        /// ```
        ///
        /// # Errors
        ///
        /// `f` is not called on error.
        /// - [MemSecurityErr::InvalidArrayLength] if the secret is not 16
        ///   bytes long. This is checked before authenticating.
        /// - [MemSecurityErr::EncryptionErr] if nothing has been
        ///   encrypted, the ciphertext is shorter than its tag, or
        ///   authentication fails.
        pub fn with_decrypted_16byte<R>(
            &self,
            f: impl FnOnce(&[u8; 16]) -> R,
        ) -> MemSecurityResult<R> {
            self.with_decrypted_array(f)
        }

        /// Decrypts a 32 byte secret and lends it to `f`.
        ///
        /// The plaintext stays in one buffer that is wiped when `f`
        /// returns, so unlike [EncryptedMem::decrypt_32byte] it is never
        /// moved. Whatever `f` returns is the caller's to wipe.
        ///
        /// ```rs
        /// let signing_key = secret.with_decrypted_32byte(SigningKey::from_bytes)?;
        /// ```
        ///
        /// # Errors
        ///
        /// `f` is not called on error.
        /// - [MemSecurityErr::InvalidArrayLength] if the secret is not 32
        ///   bytes long. This is checked before authenticating.
        /// - [MemSecurityErr::EncryptionErr] if nothing has been
        ///   encrypted, the ciphertext is shorter than its tag, or
        ///   authentication fails.
        pub fn with_decrypted_32byte<R>(
            &self,
            f: impl FnOnce(&[u8; 32]) -> R,
        ) -> MemSecurityResult<R> {
            self.with_decrypted_array(f)
        }

        /// Decrypts into a [Zeroizing] array of `N` bytes. Returning the
        /// array moves it, which can leave an unwiped copy on the stack.
        fn decrypt_array<const N: usize>(&self) -> MemSecurityResult<Zeroizing<[u8; N]>> {
            let mut plaintext = Zeroizing::new([0u8; N]);
            self.decrypt_array_into(&mut plaintext)?;

            Ok(plaintext)
        }

        /// Decrypts into a [Zeroizing] array of `N` bytes that never leaves
        /// this frame and lends it to `f`.
        fn with_decrypted_array<const N: usize, R>(
            &self,
            f: impl FnOnce(&[u8; N]) -> R,
        ) -> MemSecurityResult<R> {
            let mut plaintext = Zeroizing::new([0u8; N]);
            self.decrypt_array_into(&mut plaintext)?;

            Ok(f(&plaintext))
        }

        /// Decrypts into `plaintext`, rejecting a secret that is not `N`
        /// bytes long before authenticating.
        fn decrypt_array_into<const N: usize>(
            &self,
            plaintext: &mut [u8; N],
        ) -> MemSecurityResult<()> {
            let plaintext_len = self.plaintext_len()?;
            if plaintext_len != N {
                return Err(MemSecurityErr::InvalidArrayLength {
                    expected: N,
                    found: plaintext_len,
                });
            }

            self.decrypt_into(plaintext)
        }

        /// The length of the plaintext, which is the ciphertext without the
        /// authentication tag.
        fn plaintext_len(&self) -> MemSecurityResult<usize> {
            self.ciphertext
                .len()
                .checked_sub(ASCON128_TAG_LEN)
                .ok_or(MemSecurityErr::EncryptionErr)
        }

        /// Decrypts the ciphertext straight into `plaintext`, so the
        /// plaintext never exists outside of it.
        ///
        /// `plaintext` must be as long as the ciphertext without its tag.
        /// It is wiped if decryption fails, so unauthenticated bytes never
        /// outlive this call.
        pub(super) fn decrypt_into(&self, plaintext: &mut [u8]) -> MemSecurityResult<()> {
            let (body, tag) = self
                .ciphertext
                .split_last_chunk::<ASCON128_TAG_LEN>()
                .ok_or(MemSecurityErr::EncryptionErr)?;
            let buffer =
                InOutBuf::new(body, plaintext).map_err(|_| MemSecurityErr::EncryptionErr)?;

            let mut kek = SEALING_KEY.kek();
            let kek = LockedKek::new(&mut kek);

            let cipher = AsconAead128::new(&AsconAead128Key::try_from(kek[0..16].as_ref())?);

            let outcome = cipher
                .decrypt_inout_detached(&self.nonce, &[], buffer, &AsconAead128Tag::from(*tag))
                .map_err(|_| MemSecurityErr::EncryptionErr);
            if outcome.is_err() {
                plaintext.zeroize();
            }

            outcome
        }

        /// Sign a message and return an Ed25519 digital signature
        #[cfg(feature = "ed25519")]
        pub fn sign<T: Zeroize + AsRef<[u8]>>(
            &self,
            message: T,
        ) -> MemSecurityResult<ed25519_dalek::Signature> {
            use ed25519_dalek::{Signer, SigningKey};

            let signing_key = self.with_decrypted_32byte(SigningKey::from_bytes)?;

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

            // StaticSecret only takes the key by value, so one copy is
            // unavoidable. StaticSecret wipes it on drop.
            let x25519_static_key = self.with_decrypted_32byte(|key| StaticSecret::from(*key))?;

            Ok(x25519_static_key.diffie_hellman(&x25519_public_key))
        }

        /// Generate the public key assuming that that secret key was added as an X25519 static secret
        #[cfg(feature = "x25519")]
        pub fn x25519_public_key(&self) -> MemSecurityResult<x25519_dalek::PublicKey> {
            use x25519_dalek::{PublicKey, StaticSecret};

            // StaticSecret only takes the key by value, so one copy is
            // unavoidable. StaticSecret wipes it on drop.
            let x25519_static_key = self.with_decrypted_32byte(|key| StaticSecret::from(*key))?;

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

            debug_assert!(
                self.0.iter().all(|&byte| byte == 0),
                "KEK was not wiped"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemSecurityErr;

    // Flipping the first or last byte of the ciphertext body or of the tag
    // fails authentication in every decrypt function.
    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        for secret_len in [SECRET_KEY_16BYTE, SECRET_KEY_32BYTE] {
            let tag_end = encrypted(vec![5u8; secret_len]).ciphertext().len() - 1;

            for position in [0, secret_len - 1, secret_len, tag_end] {
                let mut secret = encrypted(vec![5u8; secret_len]);
                secret.ciphertext[position] ^= 1;

                assert_eq!(secret.decrypt().unwrap_err(), MemSecurityErr::EncryptionErr);
                let fixed_size = if secret_len == SECRET_KEY_16BYTE {
                    secret.decrypt_16byte().map(drop)
                } else {
                    secret.decrypt_32byte().map(drop)
                };
                assert_eq!(fixed_size.unwrap_err(), MemSecurityErr::EncryptionErr);
            }
        }
    }

    // The closure never sees bytes that failed authentication.
    #[test]
    fn with_decrypted_array_skips_closure_on_failure() {
        let mut secret = encrypted(vec![5u8; 32]);
        secret.ciphertext[0] ^= 1;

        assert_eq!(
            secret
                .with_decrypted_32byte(|_| panic!("closure called"))
                .unwrap_err(),
            MemSecurityErr::EncryptionErr
        );
    }

    // A failed decrypt leaves no unauthenticated bytes in the buffer.
    #[test]
    fn decrypt_into_wipes_buffer_on_failure() {
        let mut secret = encrypted(vec![5u8; 32]);
        secret.ciphertext[0] ^= 1;

        let mut plaintext = [0xAAu8; 32];
        assert_eq!(
            secret.decrypt_into(&mut plaintext).unwrap_err(),
            MemSecurityErr::EncryptionErr
        );
        assert_eq!(plaintext, [0u8; 32]);
    }

    // A buffer of the wrong length is an error, not a panic.
    #[test]
    fn decrypt_into_rejects_length_mismatch() {
        let secret = encrypted(vec![5u8; 32]);

        let mut plaintext = [0u8; 31];
        assert_eq!(
            secret.decrypt_into(&mut plaintext).unwrap_err(),
            MemSecurityErr::EncryptionErr
        );
    }

    // A ciphertext shorter than the 16 byte tag cannot be authenticated.
    #[test]
    fn decrypt_rejects_truncated_ciphertext() {
        let mut secret = encrypted(vec![5u8; 32]);
        secret.ciphertext.truncate(15);

        assert_eq!(secret.decrypt().unwrap_err(), MemSecurityErr::EncryptionErr);
    }

    // An empty secret is still authenticated by its tag.
    #[test]
    fn decrypt_rejects_tampered_tag_on_empty_secret() {
        let mut secret = encrypted(Vec::new());
        assert_eq!(secret.ciphertext().len(), 16);
        secret.ciphertext[0] ^= 1;

        assert_eq!(secret.decrypt().unwrap_err(), MemSecurityErr::EncryptionErr);
    }

    // Decrypting under a different nonce fails authentication.
    #[test]
    fn decrypt_rejects_tampered_nonce() {
        let mut secret = encrypted(vec![5u8; 32]);
        secret.nonce[0] ^= 1;

        assert_eq!(secret.decrypt().unwrap_err(), MemSecurityErr::EncryptionErr);
    }

    // A sealing key below the minimum size is an error.
    #[test]
    fn sealing_key_rejects_size_below_minimum() {
        assert_eq!(
            SealingKey::<{ MIN_SEALING_KEY_SIZE - 1 }>::new().err(),
            Some(MemSecurityErr::SealingKeyTooSmall {
                minimum: MIN_SEALING_KEY_SIZE,
                found: MIN_SEALING_KEY_SIZE - 1,
            })
        );
        assert!(SealingKey::<MIN_SEALING_KEY_SIZE>::new().is_ok());
    }

    fn encrypted(plaintext: Vec<u8>) -> EncryptedMem {
        let mut secret = EncryptedMem::new().unwrap();
        secret.encrypt(&plaintext).unwrap();

        secret
    }
}
