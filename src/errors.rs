/// Wraps `core::result::Result` with the `MemSecurityErr` as the `Err()` value
pub type MemSecurityResult<T> = Result<T, MemSecurityErr>;

/// Errors encountered in execution of the code in this crate
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MemSecurityErr {
    /// An error was encountered while encrypting the data using Ascon128a  
    #[cfg(feature = "encryption")]
    EncryptionErr,
    /// An error was encountered when decrypting data using Ascon128a    
    #[cfg(feature = "encryption")]
    DecryptionError,
    /// The length of the arrays should be the same
    InvalidArrayLength {
        /// The length defined in generic value `N` in `const N: usize`
        expected: usize,
        /// The length of the mutable array `&mut [u8; N]`
        found: usize,
    },
    /// The length of the arrays should be the same
    InvalidSliceLength {
        /// The length defined in generic value `N` in `const N: usize`
        expected: usize,
        /// The length of the `&[u8]` slice
        found: usize,
    },
    /// Cannot convert into type from a slice
    TryFromSliceError,
    /// Unable to generate random bytes/chars
    #[cfg(feature = "random")]
    Random(random_detached::getrandom::Error),
}

impl From<core::array::TryFromSliceError> for MemSecurityErr {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Self::TryFromSliceError
    }
}

#[cfg(feature = "random")]
impl From<random_detached::getrandom::Error> for MemSecurityErr {
    fn from(error: random_detached::getrandom::Error) -> Self {
        Self::Random(error)
    }
}
