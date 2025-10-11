use crate::{CodingShredHeader, DataShredHeader, ShredCommonHeader, payload::Payload};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShredData {
    pub common_header: ShredCommonHeader,
    pub data_header: DataShredHeader,
    pub payload: Payload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShredCode {
    pub common_header: ShredCommonHeader,
    pub coding_header: CodingShredHeader,
    pub payload: Payload,
}
