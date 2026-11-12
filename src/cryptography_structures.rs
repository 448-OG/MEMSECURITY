use zeroize::Zeroizing;

use crate::ToBlake3Hash;

/// The 32 bytes of a Blake3 Hash
pub type Blake3Hash = Zeroizing<[u8; 32]>;
/// The 64 bytes of an ed25519 keypair
pub type Ed25519KeyPair = Zeroizing<[u8; 64]>;
/// The 32 bytes of an ed25519 keypair
pub type Ed25519PublicKey = Zeroizing<[u8; 32]>;
/// The 32 bytes of an ed25519 secret
pub type Ed25519SecretKey = Zeroizing<[u8; 32]>;
/// The 64 bytes of an X25519 keypair
pub type X25519StaticKeyPair = Zeroizing<[u8; 64]>;
/// The 32 bytes of an X25519 public key
pub type X25519PublicKey = Zeroizing<[u8; 32]>;
/// The 32 bytes of an X25519 static secret key
pub type X25519StaticSecretKey = Zeroizing<[u8; 32]>;
/// The 32 bytes of an X25519 ephemeral secret key
pub type X25519EphemeralSecretKey = Zeroizing<[u8; 32]>;
/// The 32 bytes of an X25519 reusable secret key
pub type X25519ReusableSecretKey = Zeroizing<[u8; 32]>;
/// The 32 bytes of an X25519 shared secret key from the outcome of a DH key exchange
pub type X25519SharedSecretKey = Zeroizing<[u8; 32]>;
/// The 32 bytes secret key
pub type Key32Byte = Zeroizing<[u8; 32]>;
/// The 16 bytes of a Poly1305 AEAD tag
pub type Poly1305Tag = Zeroizing<[u8; 16]>;
/// The  bytes of a Tai64N timestamp
pub type TaiTimestamp = Zeroizing<[u8; 12]>;

impl<const N: usize> ToBlake3Hash for Zeroizing<[u8; N]> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.as_slice())
    }
}
