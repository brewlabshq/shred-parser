use serde::{Deserialize, Deserializer, Serialize, Serializer};
use wincode::{SchemaRead, SchemaWrite};

/// Number of bytes in a signature
pub const SIGNATURE_BYTES: usize = 64;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, SchemaWrite, SchemaRead)]
pub struct Signature([u8; SIGNATURE_BYTES]);

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <&[u8]>::deserialize(deserializer)?;
        if bytes.len() != SIGNATURE_BYTES {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"64 bytes"));
        }
        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(bytes);
        Ok(Signature(sig))
    }
}
