use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use crate::signature::Signature;
pub mod merkle;
pub mod payload;
pub mod shred_code;
pub mod signature;
const SIZE_OF_COMMON_SHRED_HEADER: usize = 83;
pub const SIZE_OF_DATA_SHRED_HEADERS: usize = 88;
const SIZE_OF_CODING_SHRED_HEADERS: usize = 89;
const SIZE_OF_SIGNATURE: usize = 64;

pub const DATA_SHREDS_PER_FEC_BLOCK: usize = 32;
pub const CODING_SHREDS_PER_FEC_BLOCK: usize = 32;
pub const SHREDS_PER_FEC_BLOCK: usize = DATA_SHREDS_PER_FEC_BLOCK + CODING_SHREDS_PER_FEC_BLOCK;
pub const MAX_DATA_SHREDS_PER_SLOT: usize = 32_768;
pub const MAX_CODE_SHREDS_PER_SLOT: usize = MAX_DATA_SHREDS_PER_SLOT;

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize, SchemaWrite, SchemaRead,
)]
pub enum ShredType {
    Data = 0b1010_0101,
    Code = 0b0101_1010,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize, SchemaWrite, SchemaRead,
)]
pub enum ShredVariant {
    MerkleCode { proof_size: u8, resigned: bool }, // 0b01??_????
    MerkleData { proof_size: u8, resigned: bool }, // 0b10??_????
}

bitflags! {
 #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
    pub struct ShredFlags:u8 {
        const SHRED_TICK_REFERENCE_MASK = 0b0011_1111;
        const DATA_COMPLETE_SHRED       = 0b0100_0000;
        const LAST_SHRED_IN_SLOT        = 0b1100_0000;
    }

}
impl ShredFlags {
    pub fn from_reference_tick(reference_tick: u8) -> Self {
        Self::from_bits_retain(Self::SHRED_TICK_REFERENCE_MASK.bits().min(reference_tick))
    }
}
// A common header that is present in data and code shred headers
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, SchemaWrite, SchemaRead)]
pub struct ShredCommonHeader {
    pub signature: Signature,
    pub shred_variant: ShredVariant,
    pub slot: u64,
    pub index: u32,
    pub version: u16,
    pub fec_set_index: u32,
}

/// The data shred header has parent offset and flags
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, SchemaWrite, SchemaRead)]
pub struct DataShredHeader {
    pub parent_offset: u16,
    pub flags: ShredFlags,
    size: u16, // common shred header + data shred header + data
}

/// The coding shred header has FEC information
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CodingShredHeader {
    pub num_data_shreds: u16,
    pub num_coding_shreds: u16,
    pub position: u16, // [0..num_coding_shreds)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shred {
    ShredCode(merkle::ShredCode),
    ShredData(merkle::ShredData),
}
