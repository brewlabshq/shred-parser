use crate::{
    CodingShredHeader, DataShredHeader, ShredCommonHeader, ShredVariant,
    payload::Payload,
    PACKET_DATA_SIZE, SIZE_OF_CODING_SHRED_HEADERS, SIZE_OF_NONCE, SIZE_OF_SIGNATURE,
};
use std::io::{Error, ErrorKind};

#[derive(Clone, Debug)]
pub struct ShredData {
    pub common_header: ShredCommonHeader,
    pub data_header: DataShredHeader,
    pub payload: Payload,
}

#[derive(Clone, Debug)]
pub struct ShredCode {
    pub common_header: ShredCommonHeader,
    pub coding_header: CodingShredHeader,
    pub payload: Payload,
}

impl ShredData {
    // ShredCode::SIZE_OF_PAYLOAD - SIZE_OF_CODING_SHRED_HEADERS + SIZE_OF_SIGNATURE = 1203
    pub const SIZE_OF_PAYLOAD: usize =
        ShredCode::SIZE_OF_PAYLOAD - SIZE_OF_CODING_SHRED_HEADERS + SIZE_OF_SIGNATURE;
    pub const SIZE_OF_HEADERS: usize = crate::SIZE_OF_DATA_SHRED_HEADERS;

    pub fn from_payload(shred: Vec<u8>) -> Result<Self, Error> {
        if shred.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("payload too small: {} < {}", shred.len(), Self::SIZE_OF_PAYLOAD),
            ));
        }
        let mut payload = Payload::from(shred);
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        let (common_header, data_header): (ShredCommonHeader, DataShredHeader) =
            wincode::deserialize(&payload[..]).map_err(|e| {
                Error::new(ErrorKind::InvalidData, format!("deserialize error: {e}"))
            })?;
        if !matches!(common_header.shred_variant, ShredVariant::MerkleData { .. }) {
            return Err(Error::new(ErrorKind::InvalidData, "invalid shred variant"));
        }
        Ok(Self {
            common_header,
            data_header,
            payload,
        })
    }
}

impl ShredCode {
    // PACKET_DATA_SIZE - SIZE_OF_NONCE = 1228
    pub const SIZE_OF_PAYLOAD: usize = PACKET_DATA_SIZE - SIZE_OF_NONCE;
    pub const SIZE_OF_HEADERS: usize = SIZE_OF_CODING_SHRED_HEADERS;

    pub fn from_payload(shred: Vec<u8>) -> Result<Self, Error> {
        let payload = Payload::from(shred);
        let (common_header, coding_header): (ShredCommonHeader, CodingShredHeader) =
            wincode::deserialize(&payload[..]).map_err(|e| {
                Error::new(ErrorKind::InvalidData, format!("deserialize error: {e}"))
            })?;
        if !matches!(common_header.shred_variant, ShredVariant::MerkleCode { .. }) {
            return Err(Error::new(ErrorKind::InvalidData, "invalid shred variant"));
        }
        if payload.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("payload too small: {} < {}", payload.len(), Self::SIZE_OF_PAYLOAD),
            ));
        }
        let mut payload = payload;
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        Ok(Self {
            common_header,
            coding_header,
            payload,
        })
    }
}
