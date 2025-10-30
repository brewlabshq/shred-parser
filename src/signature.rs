use std::io::Error;

use wincode::{SchemaRead, SchemaWrite};

/// Number of bytes in a signature
pub const SIGNATURE_BYTES: usize = 64;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, SchemaWrite, SchemaRead)]
pub struct Signature([u8; SIGNATURE_BYTES]);
