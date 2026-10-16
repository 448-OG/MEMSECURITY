use crate::{MemSecurityErr, MemSecurityResult, ToBlake3Hash};
use arrayvec::ArrayVec;
use bytes::{BufMut, BytesMut};
use core::fmt;
use core::ops::DerefMut;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "random")]
use random_detached::{Generator, RandomBytes};

/// This a byte that is zeroed out when dropped from memory.
/// #### Structure
/// ```rust
/// pub struct ZeroizeByte(u8);
/// ```
#[cfg_attr(feature = "bitcode", derive(bitcode::Encode, bitcode::Decode))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ZeroizeByte(u8);

impl ZeroizeByte {
    /// Initialize a ZeroizeByte with the value of specified by byte
    pub fn new(value: u8) -> Self {
        ZeroizeByte(value)
    }

    /// Initialize a new byte which is zeroed byte
    pub fn new_zeroed() -> Self {
        ZeroizeByte(0u8)
    }

    /// File the current array with new values specified by the method parameter `value: u8`
    pub fn set(&mut self, value: u8) -> &mut Self {
        self.0 = value;

        self
    }

    /// Expose the internal as an owned byte
    #[cfg(feature = "clonable_mem")]
    pub fn expose_owned(&self) -> u8 {
        self.0
    }

    /// Expose the internal as an borrowed byte
    pub fn expose_borrowed(&self) -> &u8 {
        &self.0
    }

    /// Clone the array
    #[cfg(feature = "clonable_mem")]
    pub fn clone_inner(&self) -> ZeroizeByte {
        Self(self.0)
    }

    /// Own this array
    pub fn own(self) -> Self {
        self
    }

    /// Generate some random byte and initialize an new `ZeroizeByte` in the process.
    #[cfg(feature = "random")]
    pub fn csprng() -> MemSecurityResult<Self> {
        Ok(ZeroizeByte(RandomBytes::<1>::new()?.expose()[0]))
    }
}

impl PartialEq for ZeroizeByte {
    fn eq(&self, other: &Self) -> bool {
        blake3::hash(&self.0.to_le_bytes()) == blake3::hash(&other.0.to_le_bytes())
    }
}

impl Eq for ZeroizeByte {}

impl Zeroize for ZeroizeByte {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

impl Drop for ZeroizeByte {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ZeroizeOnDrop for ZeroizeByte {}

/// This is a array whose size is specified as a const generic `N` and can be zeroed out when dropped from memory.
/// This array is useful when specifying fixed size bytes like passwords which need to be zeroed out from memory before being dropped.
/// #### Structure
/// ```rust
/// pub struct ZeroizeArray<const N: usize>([u8; N]);
/// ```
#[cfg_attr(feature = "bitcode", derive(bitcode::Encode, bitcode::Decode))]
#[cfg_attr(feature = "serde_derive", derive(serde::Serialize, serde::Deserialize))]
pub struct ZeroizeArray<const N: usize>(
    #[cfg_attr(feature = "serde_derive", serde(with = "bytes_array"))] [u8; N],
);

#[cfg(feature = "serde_derive")]
mod bytes_array {
    use core::fmt;
    use serde::de::Visitor;
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        struct V<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for V<N> {
            type Value = [u8; N];

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a byte array of length {}", N)
            }

            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }

            // Needed for formats (e.g. JSON) that represent bytes as a sequence
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; N];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }

        d.deserialize_bytes(V::<N>)
    }
}

impl<const N: usize> AsRef<[u8]> for ZeroizeArray<N> {
    fn as_ref(&self) -> &[u8] {
        self.expose_borrowed()
    }
}

impl<const N: usize> fmt::Debug for ZeroizeArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZeroizeArray<const N: usize>({:?})",
            blake3::hash(&self.0)
        )
    }
}

impl<const N: usize> PartialEq for ZeroizeArray<N> {
    fn eq(&self, other: &Self) -> bool {
        blake3::hash(&self.0) == blake3::hash(&other.0)
    }
}

impl<const N: usize> Eq for ZeroizeArray<N> {}

impl<const N: usize> ZeroizeArray<N> {
    /// Initialize a ZeroizeArray with the value of specified by the array of bytes
    pub fn new(value: [u8; N]) -> Self {
        ZeroizeArray(value)
    }

    /// Initialize a new array which is zeroed bytes of len `N` as specified by the generic `const N: usize`
    pub fn new_zeroed() -> Self {
        ZeroizeArray([0u8; N])
    }

    /// File the current array with new values specified by the method parameter `value: [u8; N]`
    pub fn fill_from_array(mut self, value: [u8; N]) -> Self {
        self.0.copy_from_slice(&value);

        self
    }

    /// Fill the current array with new values specified by the method parameter `value: [u8; N]` but returing a `&mut Self`
    pub fn fill_from_array_borrowed(&mut self, value: [u8; N]) -> &mut Self {
        self.0.copy_from_slice(&value);

        self
    }

    /// Create array with new values specified by the method parameter `value: [u8; N]`
    pub fn new_from_slice(value: &[u8]) -> MemSecurityResult<Self> {
        let mut array: [u8; N] = match value.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(MemSecurityErr::InvalidSliceLength {
                    expected: N,
                    found: value.len(),
                })
            }
        };

        let outcome = ZeroizeArray::new(array);
        array.fill(0);

        Ok(outcome)
    }

    /// Fill the current array with new values specified by the method parameter `value: [u8; N]`
    pub fn fill_from_slice(mut self, value: &[u8]) -> MemSecurityResult<Self> {
        let array: [u8; N] = match value.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(MemSecurityErr::InvalidSliceLength {
                    expected: N,
                    found: value.len(),
                })
            }
        };

        self.0.copy_from_slice(&array);

        Ok(self)
    }

    /// File the current array with new values specified by the method parameter `value: [u8; N]`
    pub fn fill_from_slice_borrowed(&mut self, value: &[u8]) -> MemSecurityResult<&mut Self> {
        let array: [u8; N] = match value.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(MemSecurityErr::InvalidSliceLength {
                    expected: N,
                    found: value.len(),
                })
            }
        };

        self.0.copy_from_slice(&array);

        Ok(self)
    }

    /// Expose the internal as an owned array
    #[cfg(feature = "clonable_mem")]
    pub fn expose_owned(&self) -> [u8; N] {
        self.0
    }

    /// Expose the internal as an borrowed array
    pub fn expose_borrowed(&self) -> &[u8; N] {
        &self.0
    }

    /// Clone the array
    #[cfg(feature = "clonable_mem")]
    pub fn clone_inner(&self) -> ZeroizeArray<N> {
        Self(self.0)
    }

    /// Own this array
    pub fn own(self) -> Self {
        self
    }

    /// Insert a value at index specified in the array
    pub fn insert(&mut self, index: usize, value: u8) -> &mut Self {
        self.0[index] = value;

        self
    }
}

impl<const N: usize> Zeroize for ZeroizeArray<N> {
    fn zeroize(&mut self) {
        self.0[..].copy_from_slice(&[0u8; N]);
    }
}

impl<const N: usize> Drop for ZeroizeArray<N> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const N: usize> ZeroizeOnDrop for ZeroizeArray<N> {}

/// This is an array of variable length bytes that can be zeroed out on drop.
/// #### Structure
///
/// ```rust
/// use bytes::BytesMut;
///
/// pub struct ZeroizeBytesArray<const N: usize>(BytesMut);
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ZeroizeBytesArray<const N: usize>(BytesMut);

impl<const N: usize> ZeroizeBytesArray<N> {
    /// Initialize the array with an initial length of `N`
    pub fn new() -> Self {
        ZeroizeBytesArray(BytesMut::with_capacity(N))
    }

    /// Initialize the array and set the internal value of the array to the value specified by method argument
    pub fn new_with_data(value: [u8; N]) -> Self {
        let mut value_bytes = BytesMut::with_capacity(N);

        value_bytes.put(&value[..]);

        ZeroizeBytesArray(value_bytes)
    }

    /// Initialize the array and set the internal value of the array to the value specified by method argument
    #[cfg(feature = "random")]
    pub fn new_with_csprng() -> MemSecurityResult<Self> {
        let mut value_bytes = BytesMut::with_capacity(N);

        let mut value = RandomBytes::<N>::new()?;

        value_bytes.put(&value.expose()[..]);

        value.zeroize_mem();

        Ok(ZeroizeBytesArray(value_bytes))
    }

    /// Set the internal value of the array to the value specified by method argument
    pub fn set(mut self, value: [u8; N]) -> Self {
        self.0.put(&value[..]);

        self
    }

    /// Add the byte the internal value
    pub fn set_byte(&mut self, value: u8) -> &mut Self {
        self.0.put_u8(value);

        self
    }

    /// Set the internal value of the array to the value specified by method argument value which is a `BytesMut`
    pub fn set_bytes_mut(mut self, value: BytesMut) -> Self {
        self.0.put(&value[..]);

        self
    }

    /// Initialize the array with the length specified by the generic const `N` added to the value specified by the
    /// method argument `capacity:usize` (N + capacity)
    pub fn with_additional_capacity(capacity: usize) -> Self {
        ZeroizeBytesArray(BytesMut::with_capacity(N + capacity))
    }

    /// Expose the internal value of the array
    pub fn expose_borrowed(&self) -> &BytesMut {
        &self.0
    }

    /// Clone the array
    #[cfg(feature = "clonable_mem")]
    pub fn clone_inner(&self) -> ZeroizeBytesArray<N> {
        Self(self.0.clone())
    }
}

impl<const N: usize> AsRef<[u8]> for ZeroizeBytesArray<N> {
    fn as_ref(&self) -> &[u8] {
        self.expose_borrowed()
    }
}

impl<const N: usize> PartialEq for ZeroizeBytesArray<N> {
    fn eq(&self, other: &Self) -> bool {
        blake3::hash(&self.0) == blake3::hash(&other.0)
    }
}

impl<const N: usize> Eq for ZeroizeBytesArray<N> {}

impl<const N: usize> Default for ZeroizeBytesArray<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Debug for ZeroizeBytesArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZeroizeBytesArray<const N: usize>({:?})",
            blake3::hash(&self.0)
        )
    }
}

impl<const N: usize> Zeroize for ZeroizeBytesArray<N> {
    fn zeroize(&mut self) {
        self.0.deref_mut().zeroize();
        self.0.clear();
    }
}

impl<const N: usize> Drop for ZeroizeBytesArray<N> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const N: usize> ZeroizeOnDrop for ZeroizeBytesArray<N> {}

/// Similar to `ZeroizeBytesArray` but this does not have a fixed size length.
/// This is more similar to using a `Vec` than an `array`
/// #### Structure
/// ```rust
/// use bytes::BytesMut;
///
/// pub struct ZeroizeBytes(BytesMut);
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ZeroizeBytes(BytesMut);

impl ZeroizeBytes {
    /// Create a new array with no allocation and no specified capacity
    pub fn new() -> Self {
        ZeroizeBytes(BytesMut::new())
    }

    /// Initialize the array and set the internal value of the array to the value specified by method argument
    pub fn new_with_data(value: &[u8]) -> Self {
        let mut value_bytes = BytesMut::new();
        value_bytes.put(value);

        ZeroizeBytes(value_bytes)
    }

    /// Set the internal value of the array to the value specified by method argument value which is a `BytesMut`
    pub fn set_bytes_mut(&mut self, value: BytesMut) -> &mut Self {
        self.0.put(&value[..]);

        self
    }

    /// Sets the internal value to the new value
    pub fn set(&mut self, value: &[u8]) -> &mut Self {
        let mut container = BytesMut::new();
        container.put(value);
        self.0 = container;

        self
    }

    /// Add the byte the internal value
    pub fn set_byte(&mut self, value: u8) -> &mut Self {
        self.0.put_u8(value);

        self
    }

    /// Initializes the array with a specified capacity
    pub fn new_with_capacity(capacity: usize) -> Self {
        ZeroizeBytes(BytesMut::with_capacity(capacity))
    }

    /// Expose the internal value
    pub fn expose_borrowed(&self) -> &BytesMut {
        &self.0
    }

    /// Clone the array
    #[cfg(feature = "clonable_mem")]
    pub fn clone_inner(&self) -> ZeroizeBytes {
        Self(self.0.clone())
    }
}

impl Default for ZeroizeBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[u8]> for ZeroizeBytes {
    fn as_ref(&self) -> &[u8] {
        self.expose_borrowed()
    }
}

impl PartialEq for ZeroizeBytes {
    fn eq(&self, other: &Self) -> bool {
        blake3::hash(&self.0) == blake3::hash(&other.0)
    }
}

impl Eq for ZeroizeBytes {}

impl fmt::Debug for ZeroizeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZeroizeBytes({:?})", blake3::hash(&self.0))
    }
}

impl Zeroize for ZeroizeBytes {
    fn zeroize(&mut self) {
        self.0.deref_mut().zeroize();
        self.0.clear();
    }
}

impl Drop for ZeroizeBytes {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ZeroizeOnDrop for ZeroizeBytes {}

/// This is an ArrayVec whose size is specified as a const generic `N` and can be zeroed out when dropped from memory.
/// This array is useful when specifying fixed size bytes like passwords which need to be zeroed out from memory before being dropped.
/// #### Structure
/// ```rust
/// use arrayvec::ArrayVec;
///
/// pub struct ZeroizeArrayVec<const N: usize, T>(ArrayVec<T, N>);
/// ```
pub struct ZeroizeArrayVec<const N: usize, T: fmt::Debug + ToBlake3Hash>(ArrayVec<T, N>);

impl<const N: usize, T: fmt::Debug + ToBlake3Hash> ZeroizeArrayVec<N, T>
where
    T: core::marker::Copy,
{
    /// Initialize a ZeroizeArray with the value of specified by the array of bytes
    pub fn new() -> Self {
        ZeroizeArrayVec(ArrayVec::<T, N>::new())
    }

    /// Initialize a ZeroizeArray with the value of specified by the array of bytes
    pub fn new_with(value: [T; N]) -> Self {
        let mut outcome = ArrayVec::<T, N>::new();
        outcome.try_extend_from_slice(&value).unwrap(); // Should never fail due to const size constraints

        ZeroizeArrayVec(outcome)
    }

    /// File the current array with new values specified by the method parameter `value: [u8; N]`
    pub fn fill_from_slice(&mut self, value: [T; N]) -> &mut Self {
        self.0.try_extend_from_slice(&value).unwrap(); // Should never fail due to const size constraints

        self
    }

    /// Expose the internal as an owned array
    #[cfg(feature = "clonable_mem")]
    pub fn expose_owned(&self) -> ArrayVec<T, N> {
        self.0.clone()
    }

    /// Expose the internal as an borrowed array
    pub fn expose_borrowed(&self) -> &ArrayVec<T, N> {
        &self.0
    }

    /// Expose the internal as an owned array
    #[cfg(feature = "clonable_mem")]
    pub fn clone_inner(&self) -> ZeroizeArrayVec<N, T> {
        Self(self.0.clone())
    }

    /// Own this array
    pub fn own(self) -> Self {
        self
    }

    /// Insert a value in the array after the last index
    pub fn push(&mut self, value: T) -> &mut Self {
        self.0.push(value);

        self
    }

    /// Insert a value at index specified in the array
    pub fn insert(&mut self, index: usize, value: T) -> &mut Self {
        self.0.insert(index, value);

        self
    }
}

impl<const N: usize, T: fmt::Debug + ToBlake3Hash + Copy> Default for ZeroizeArrayVec<N, T> {
    fn default() -> Self {
        ZeroizeArrayVec::new()
    }
}

impl<const N: usize, T: fmt::Debug + ToBlake3Hash> PartialEq for ZeroizeArrayVec<N, T> {
    fn eq(&self, other: &Self) -> bool {
        for (index, value) in self.0.iter().enumerate() {
            if value.hash() != other.0[index].hash() {
                return false;
            }
        }

        true
    }
}

impl<const N: usize, T: fmt::Debug + ToBlake3Hash> fmt::Debug for ZeroizeArrayVec<N, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut value = blake3::Hasher::new();
        self.0.iter().for_each(|inner| {
            value.update(inner.hash().as_bytes());
        });

        let outcome = value.finalize();

        write!(
            f,
            "ZeroizeArrayVec<const N: usize, T: fmt::Debug + ToBlake3Hash>({:?})",
            outcome
        )
    }
}

impl<const N: usize, T: fmt::Debug + ToBlake3Hash> Eq for ZeroizeArrayVec<N, T> {}

impl<const N: usize, T: fmt::Debug + ToBlake3Hash> Zeroize for ZeroizeArrayVec<N, T> {
    fn zeroize(&mut self) {
        self.0.clear()
    }
}

impl<const N: usize, T: fmt::Debug + ToBlake3Hash> Drop for ZeroizeArrayVec<N, T> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const N: usize, T: fmt::Debug + ToBlake3Hash> ZeroizeOnDrop for ZeroizeArrayVec<N, T> {}

/// This is an ArrayVec of bytes whose size is specified as a const generic `N` and can be zeroed out when dropped from memory.
/// This array is useful when specifying fixed size bytes like passwords which need to be zeroed out from memory before being dropped.
/// #### Structure
/// ```rust
/// use arrayvec::ArrayVec;
/// pub struct ZeroizeArrayVecBytes<const N: usize>(ArrayVec<u8, N>);
/// ```
pub struct ZeroizeArrayVecBytes<const N: usize>(ArrayVec<u8, N>);

impl<const N: usize> ZeroizeArrayVecBytes<N> {
    /// Initialize a ZeroizeArray with the value of specified by the array of bytes
    pub fn new() -> Self {
        ZeroizeArrayVecBytes(ArrayVec::<u8, N>::new())
    }

    /// Initialize a ZeroizeArray with the value of specified by the array of bytes
    pub fn new_with(value: [u8; N]) -> Self {
        let mut outcome = ArrayVec::<u8, N>::new();
        outcome.try_extend_from_slice(&value).unwrap(); // Should never fail due to const size constraints

        ZeroizeArrayVecBytes(outcome)
    }

    /// File the current array with new values specified by the method parameter `value: [u8; N]`
    pub fn fill_from_slice(&mut self, value: [u8; N]) -> &mut Self {
        self.0.try_extend_from_slice(&value).unwrap(); // Should never fail due to const size constraints

        self
    }

    /// Expose the internal as an owned array
    #[cfg(feature = "clonable_mem")]
    pub fn expose_owned(&self) -> ArrayVec<u8, N> {
        self.0.clone()
    }

    /// Expose the internal as an borrowed array
    pub fn expose_borrowed(&self) -> &ArrayVec<u8, N> {
        &self.0
    }

    /// Expose the internal as an owned array
    #[cfg(feature = "clonable_mem")]
    pub fn clone_inner(&self) -> ZeroizeArrayVecBytes<N> {
        Self(self.0.clone())
    }

    /// Own this array
    pub fn own(self) -> Self {
        self
    }

    /// Insert a value in the array after the last index
    pub fn push(&mut self, value: u8) -> &mut Self {
        self.0.push(value);

        self
    }

    /// Insert a value at index specified in the array
    pub fn insert(&mut self, index: usize, value: u8) -> &mut Self {
        self.0.insert(index, value);

        self
    }
}

impl<const N: usize> Default for ZeroizeArrayVecBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PartialEq for ZeroizeArrayVecBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        blake3::hash(&self.0) == blake3::hash(&other.0)
    }
}

impl<const N: usize> Eq for ZeroizeArrayVecBytes<N> {}

impl<const N: usize> Zeroize for ZeroizeArrayVecBytes<N> {
    fn zeroize(&mut self) {
        self.0.clear()
    }
}

impl<const N: usize> Drop for ZeroizeArrayVecBytes<N> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const N: usize> ZeroizeOnDrop for ZeroizeArrayVecBytes<N> {}

impl<const N: usize> fmt::Debug for ZeroizeArrayVecBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZeroizeArrayVecBytes<const N: usize>({:?})",
            blake3::hash(&self.0)
        )
    }
}
