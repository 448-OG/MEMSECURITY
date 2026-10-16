# MEMSECURITY

[![Rust](https://github.com/448-engineering/MEMSECURITY/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/448-engineering/MEMSECURITY/actions/workflows/rust.yml)  ![crates.io](https://img.shields.io/crates/v/memsecurity.svg)[![Docs](https://docs.rs/memsecurity/badge.svg)](https://docs.rs/memsecurity)


Securely hold secrets in memory and protect them against cross-protection-boundary readout via microarchitectural, via attacks on physical layout, and via coldboot attacks. `mlock` is also used to prevent the operating system from swapping these secrets to RAM which offers some level of protection aganist cold boot attacks.

This algorithm was invented by [OpenSSH](https://marc.info/?l=openbsd-cvs&m=156109087822676). The given type of encryption secures sensitive data, such as secret keys, by encrypting them in memory while they are not in use and decrypting them on demand. This method provides protection against various types of attacks, including cross-protection-boundary readout via microarchitectural flaws like Spectre or Meltdown, attacks on physical layout like Rowbleed, and coldboot attacks. The key insight is that these attacks are imperfect, meaning that the recovered data contains bitflips or the attack only provides a probability for any given bit. When applied to cryptographic keys, these kinds of imperfect attacks are enough to recover the actual key. 

However, this implementation derives a sealing key from a large area of memory called the "pre-key" using a key derivation function. Any single bitflip in the readout of the pre-key will avalanche through all the bits in the sealing key, rendering it unusable with no indication of where the error occurred.


This crate has not received an audit. Use at your own risk!!!

#### Features
- **`symm_asymm`** - feature enables data types that can be used to securely zero out memory when they are dropped. They implement `Zeroize` trait from `zeroize` crate.
- **`clonable_mem`** - Allows the cloning of data types enabled by the `symm_asymm`  features.
- **`encryption`** - This enables encrypted memory with `mlock` and `munlock` and encrypts using Ascon128a cipher.
- **`random`** - This enables cryptographically secure random number generator which use `rand_core` and `rand_chacha`.


#### Usage Examples
1. ###### Generating random bytes
   Using the random byte generator (it is cryptographically secure based on the randomness provided by the OS you are using). The `random` feature must be enabled.
    ```rust
    use random_detached::{RandomBytes,Generator};

    // Generate a 32 byte array of random bytes
    let random_bytes = RandomBytes::<32>::new().unwrap();

    // Assert that the random bytes are not zeroes
    assert_ne!(random_bytes.expose(), &[0u8; 32]);
    ```
2. ###### Using the data types that are zeroed when dropped
    Sometimes sensitive data needs to be zeroed when it is dropped. This can be to protect secrets like encryption keys or passwords by ensuring they are not kept in memory when they are no longer needed. The `symm_asymm` feature must be enabled. The `clonable_mem` feature can be enabled if they you need to clone these secrets (Use these with care). Most of these have the `.expose_borrowed()` method which exposes the inner value if you want to use that value.
    ```rust
    use memsecurity::{ZeroizeArray, ZeroizeBytes};

    // Create an array of 4 bytes that will be zeroed out when dropped.
    let array_like = ZeroizeArray::<4>::new([4u8, 3,2,1]);

    // Use the value
    array_like.expose_owned();

    // Create a Vec like array using `BytesMut` from `bytes` crate that re-allocates when it's capacity is exceeded.
    let mut vector_like = ZeroizeBytes::new();

    // Insert a slice of bytes
    vector_like.set(&[4u8, 5,6,7]); // Must be a byte (u8) type

    // Use the value
    vector_like.expose_borrowed();
    ```
3. ###### Encrypt a secret while in memory using Ascon128a encryption
    Whenever you want to encrypt secrets like passwords or encryption keys in memory, enable the `encryption` feature to use the `EncryptedMem` type. `mlock` and `munlock` are also implemented in this data. The encryption key is generated afresh on each app run.
    ```rust
    use memsecurity::EncryptedMem;
    use random_detached::{RandomBytes,Generator};

    // Initialize the struct with a random nonce (Nonce for Ascon128a)
    let mut foo = EncryptedMem::new().unwrap();

    // Here a some random bytes are generated to simulate
    // some secret you want to protect.
    // Here the value must implement `Zeroize` trait
    // and `impl From<AsRef<[u8]>>` trait so be accepted
    // by the `encrypt()` and `decrypt()` methods of `EncryptedMem`.
    let plaintext_bytes = RandomBytes::<1>::new().unwrap();

    // Encrypt the secret in memory using the randomly
    // generated encryption key that is `mlocked`
    foo.encrypt(&mut plaintext_bytes.expose().to_vec()).unwrap();

    // Decrypt the secret using the `mlocked` key
    let decrypted = foo.decrypt().unwrap();

    assert_eq!(
        plaintext_bytes.expose(),
        decrypted.expose_borrowed().as_ref()
    );
    ```

#### LICENSE
This crate is licensed under Apache license and all contributions and redistributions must bear the same license.

#### Code of Conduct
All conversations and contributions must obey the Rust Code of Conduct [https://www.rust-lang.org/policies/code-of-conduct](https://www.rust-lang.org/policies/code-of-conduct)

