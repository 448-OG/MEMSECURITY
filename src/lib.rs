#![deny(unsafe_code)]
#![forbid(missing_docs)]
#![doc = include_str!("../README.md")]

mod errors;
pub use errors::*;

#[cfg(feature = "symm_asymm")]
mod cryptography_structures;
#[cfg(feature = "symm_asymm")]
pub use cryptography_structures::*;

#[cfg(feature = "encryption")]
mod encrypted_mem;
#[cfg(feature = "encryption")]
pub use encrypted_mem::*;

#[cfg(feature = "symm_asymm")]
mod zeroizable_arrays;
#[cfg(feature = "symm_asymm")]
pub use zeroizable_arrays::*;

#[cfg(feature = "symm_asymm")]
mod traits;
#[cfg(feature = "symm_asymm")]
pub use traits::*;

/// Re-export  crates
#[cfg(feature = "encryption")]
pub use arrayvec;
#[cfg(feature = "encryption")]
pub use ascon_aead;
#[cfg(feature = "bitcode")]
pub use bitcode;
#[cfg(feature = "encryption")]
pub use blake3;
#[cfg(feature = "encryption")]
pub use bytes;
#[cfg(feature = "ed25519")]
pub use ed25519_dalek;
#[cfg(feature = "encryption")]
pub use memsec;
#[cfg(feature = "encryption")]
pub use once_cell;

#[cfg(feature = "serde")]
pub use serde;
#[cfg(feature = "uuid")]
pub use uuid;
#[cfg(feature = "x25519")]
pub use x25519_dalek;

pub use zeroize;
