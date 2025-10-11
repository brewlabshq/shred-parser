use std::ops::Deref;

use bytes::{Bytes, BytesMut};

#[derive(Clone, Debug, Eq)]
pub struct Payload {
    pub bytes: Bytes,
}
impl PartialEq for Payload {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl From<Vec<u8>> for Payload {
    #[inline]
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Bytes::from(bytes),
        }
    }
}

impl From<Bytes> for Payload {
    #[inline]
    fn from(bytes: Bytes) -> Self {
        Self { bytes }
    }
}

impl From<BytesMut> for Payload {
    #[inline]
    fn from(bytes: BytesMut) -> Self {
        Self {
            bytes: bytes.freeze(),
        }
    }
}

impl AsRef<[u8]> for Payload {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl Deref for Payload {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.bytes.deref()
    }
}
