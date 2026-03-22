use std::io::{Error, ErrorKind};
use std::mem::MaybeUninit;
use std::u8;

use crate::signature::Signature;
use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use wincode::config::ConfigCore;
use wincode::containers::Pod;
use wincode::io::{Reader, Writer};
use wincode::{SchemaRead, SchemaWrite, TypeMeta};
pub mod merkle;
pub mod payload;
pub mod shred_code;
pub mod signature;

pub const SIZE_OF_SIGNATURE: usize = 64;
pub const SIZE_OF_COMMON_SHRED_HEADER: usize = 83;
pub const SIZE_OF_DATA_SHRED_HEADERS: usize = 88;
pub const SIZE_OF_CODING_SHRED_HEADERS: usize = 89;
pub const PACKET_DATA_SIZE: usize = 1232;
pub const SIZE_OF_NONCE: usize = 4;

pub const DATA_SHREDS_PER_FEC_BLOCK: usize = 32;
pub const CODING_SHREDS_PER_FEC_BLOCK: usize = 32;
pub const SHREDS_PER_FEC_BLOCK: usize = DATA_SHREDS_PER_FEC_BLOCK + CODING_SHREDS_PER_FEC_BLOCK;
pub const MAX_DATA_SHREDS_PER_SLOT: usize = 32_768;
pub const MAX_CODE_SHREDS_PER_SLOT: usize = MAX_DATA_SHREDS_PER_SLOT;

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
    pub struct ShredFlags:u8 {
        const SHRED_TICK_REFERENCE_MASK = 0b0011_1111;
        const DATA_COMPLETE_SHRED       = 0b0100_0000;
        const LAST_SHRED_IN_SLOT        = 0b1100_0000;
    }
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    SchemaWrite,
    SchemaRead,
    TryFromPrimitive,
    IntoPrimitive,
    Serialize,
    Deserialize,
)]
#[wincode(tag_encoding = "u8")]
#[serde(into = "u8", try_from = "u8")]
pub enum ShredType {
    #[wincode(tag = 0b1010_0101)]
    Data = 0b1010_0101,
    #[wincode(tag = 0b0101_1010)]
    Code = 0b0101_1010,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum ShredVariant {
    MerkleCode { proof_size: u8, resigned: bool }, // 0b01??_????
    MerkleData { proof_size: u8, resigned: bool }, // 0b10??_????
}
impl From<ShredVariant> for ShredType {
    #[inline]
    fn from(shred_variant: ShredVariant) -> Self {
        match shred_variant {
            ShredVariant::MerkleCode { .. } => ShredType::Code,
            ShredVariant::MerkleData { .. } => ShredType::Data,
        }
    }
}

impl From<ShredVariant> for u8 {
    #[inline]
    fn from(shred_variant: ShredVariant) -> u8 {
        match shred_variant {
            ShredVariant::MerkleCode {
                proof_size,
                resigned: false,
            } => proof_size | 0x60,
            ShredVariant::MerkleCode {
                proof_size,
                resigned: true,
            } => proof_size | 0x70,
            ShredVariant::MerkleData {
                proof_size,
                resigned: false,
            } => proof_size | 0x90,
            ShredVariant::MerkleData {
                proof_size,
                resigned: true,
            } => proof_size | 0xb0,
        }
    }
}

impl TryFrom<u8> for ShredVariant {
    type Error = Error;
    #[inline]
    fn try_from(shred_variant: u8) -> Result<Self, Self::Error> {
        if shred_variant == u8::from(ShredType::Code) || shred_variant == u8::from(ShredType::Data)
        {
            Err(Error::new(ErrorKind::InvalidData, "Invalid shred variant"))
        } else {
            let proof_size = shred_variant & 0x0F;
            match shred_variant & 0xF0 {
                0x60 => Ok(ShredVariant::MerkleCode {
                    proof_size,
                    resigned: false,
                }),
                0x70 => Ok(ShredVariant::MerkleCode {
                    proof_size,
                    resigned: true,
                }),
                0x90 => Ok(ShredVariant::MerkleData {
                    proof_size,
                    resigned: false,
                }),
                0xb0 => Ok(ShredVariant::MerkleData {
                    proof_size,
                    resigned: true,
                }),
                _ => Err(Error::new(ErrorKind::InvalidData, "Invalid shred variant")),
            }
        }
    }
}

unsafe impl<C: ConfigCore> SchemaWrite<C> for ShredVariant {
    type Src = Self;
    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: 1,
        zero_copy: false,
    };

    fn size_of(_src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(1)
    }

    fn write(writer: impl Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        let repr: u8 = (*src).into();
        <u8 as SchemaWrite<C>>::write(writer, &repr)
    }
}

unsafe impl<'a, C: ConfigCore> SchemaRead<'a, C> for ShredVariant {
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: 1,
        zero_copy: false,
    };

    fn read(reader: impl Reader<'a>, dst: &mut MaybeUninit<Self::Dst>) -> wincode::ReadResult<()> {
        let repr = <u8 as SchemaRead<C>>::get(reader)?;
        let value = Self::try_from(repr)
            .map_err(|_| wincode::ReadError::InvalidTagEncoding(repr as usize))?;
        dst.write(value);
        Ok(())
    }
}

// A common header that is present in data and code shred headers
#[derive(Clone, Copy, Debug, SchemaRead, SchemaWrite)]
pub struct ShredCommonHeader {
    #[wincode(with = "Pod<_>")]
    pub signature: Signature,
    pub shred_variant: ShredVariant,
    pub slot: u64,
    pub index: u32,
    pub version: u16,
    pub fec_set_index: u32,
}

/// The data shred header has parent offset and flags
#[derive(Clone, Copy, Debug, SchemaRead, SchemaWrite)]
pub struct DataShredHeader {
    pub parent_offset: u16,
    #[wincode(with = "Pod<_>")]
    pub flags: ShredFlags,
    pub size: u16, // common shred header + data shred header + data
}

/// The coding shred header has FEC information
#[derive(Clone, Copy, Debug, SchemaRead, SchemaWrite)]
pub struct CodingShredHeader {
    pub num_data_shreds: u16,
    pub num_coding_shreds: u16,
    pub position: u16, // [0..num_coding_shreds)
}

#[derive(Clone, Debug)]
pub enum Shred {
    ShredCode(merkle::ShredCode),
    ShredData(merkle::ShredData),
}

pub mod layout {
    use super::*;

    /// Reads the shred variant byte at offset 64 (right after the signature).
    pub fn get_shred_variant(shred: &[u8]) -> Result<ShredVariant, Error> {
        let Some(&shred_variant) = shred.get(SIZE_OF_SIGNATURE) else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "payload too small for shred variant",
            ));
        };
        ShredVariant::try_from(shred_variant)
    }
}

impl Shred {
    /// Construct a Shred from raw serialized packet bytes.
    pub fn new_from_serialized_shred(shred: Vec<u8>) -> Result<Self, Error> {
        match layout::get_shred_variant(&shred)? {
            ShredVariant::MerkleCode { .. } => {
                Ok(Self::ShredCode(merkle::ShredCode::from_payload(shred)?))
            }
            ShredVariant::MerkleData { .. } => {
                Ok(Self::ShredData(merkle::ShredData::from_payload(shred)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::merkle::{ShredCode, ShredData};

    use super::*;
    use base64::Engine;
    use serde::Deserialize;
    use std::fs;
    use std::time::Instant;

    #[derive(Deserialize)]
    struct Packet {
        raw_data_base64: String,
    }

    #[derive(Deserialize)]
    struct ShredFile {
        packets: Vec<Packet>,
    }

    fn percentile(sorted: &[u64], p: f64) -> u64 {
        if sorted.is_empty() {
            return 0;
        }
        let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    #[test]
    fn bench_parse_shreds() {
        // Load shred.json
        let json_data = fs::read_to_string("shred.json").expect("Failed to read shred.json");
        let shred_file: ShredFile =
            serde_json::from_str(&json_data).expect("Failed to parse shred.json");

        println!("\n=== Shred Parser Benchmark ===");
        println!("Total packets: {}", shred_file.packets.len());

        // UDP header size to skip

        // Decode all base64 (not timed)
        let buffers: Vec<Vec<u8>> = shred_file
            .packets
            .iter()
            .map(|p| {
                base64::engine::general_purpose::STANDARD
                    .decode(&p.raw_data_base64)
                    .expect("Failed to decode base64")
            })
            .collect();

        // Parse shreds (skip UDP header) and measure parse time only
        let mut parse_times: Vec<u64> = Vec::with_capacity(buffers.len());
        let mut success_count = 0;
        let mut fail_count = 0;
        let mut shred_code_fail = 0;
        let mut shred_code_success = 0;
        let mut shred_data_fail = 0;
        let mut shred_data_success = 0;

        for buf in &buffers {
            let shred_data = &buf[..];
            let start = Instant::now();
            let _shred_playload = match wincode::deserialize::<ShredCommonHeader>(&shred_data[..88])
            {
                Ok(entry) => {
                    success_count += 1;
                    // match wincode::deserialize::<ShredCommonHeader>(&shred_data[..88]) {
                    //     Ok(header) => match header.shred_variant {
                    //         ShredVariant::MerkleCode { .. } => shred_code_success += 1,
                    //         ShredVariant::MerkleData { .. } => shred_code_fail += 1,
                    //     },
                    //     Err(e) => {}
                    // };
                    entry
                }
                Err(_) => {
                    fail_count += 1;
                    println!("buffer size: {}", shred_data.len());
                    continue;
                }
            };

            // println!("Shred payload: {:?}", shred_playload);
            // match wincode::deserialize::<Shred>(&shred_data[..96]) {
            //     Ok(shred_variant) => {
            //         println!("Shred variant: {:?}", shred_variant);
            //         // match shred_variant {
            //         //     ShredVariant::MerkleCode { .. } => {
            //         //         match wincode::deserialize::<ShredCode>(&shred_data[..96]) {
            //         //             Ok(_) => success_count += 1,
            //         //             Err(_) => fail_count += 1,
            //         //         }
            //         //     }
            //         //     ShredVariant::MerkleData { .. } => {
            //         //         match wincode::deserialize::<ShredData>(&shred_data[..96]) {
            //         //             Ok(_) => success_count += 1,
            //         //             Err(_) => fail_count += 1,
            //         //         }
            //         //     }
            //         // }
            //     }
            //     Err(_) => fail_count += 1,
            // }
            parse_times.push(start.elapsed().as_nanos() as u64);
        }

        // Sort for percentile calculations
        parse_times.sort_unstable();

        let avg: u64 = parse_times.iter().sum::<u64>() / parse_times.len() as u64;

        println!("\n--- Results ---");
        println!("Parsed: {} success, {} failed", success_count, fail_count);
        println!(
            "Parsed coded : {} success, {} failed",
            shred_code_success, shred_code_fail
        );
        println!(
            "Parsed data : {} success, {} failed",
            shred_code_success, shred_code_fail
        );

        println!("\n[Parse Times (nanoseconds)]");
        println!("  avg:  {:>8} ns", avg);
        println!("  p50:  {:>8} ns", percentile(&parse_times, 50.0));
        println!("  p90:  {:>8} ns", percentile(&parse_times, 90.0));
        println!("  p99:  {:>8} ns", percentile(&parse_times, 99.0));
        println!("  min:  {:>8} ns", parse_times.first().unwrap_or(&0));
        println!("  max:  {:>8} ns", parse_times.last().unwrap_or(&0));

        let throughput =
            buffers.len() as f64 / (parse_times.iter().sum::<u64>() as f64 / 1_000_000_000.0);
        println!("\n[Throughput]");
        println!("  {:>12.0} shreds/sec", throughput);
    }
}
