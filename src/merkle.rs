use crate::{payload::Payload, CodingShredHeader, DataShredHeader, ShredCommonHeader};
use wincode::{SchemaRead, SchemaWrite};

#[derive(Clone, Debug, SchemaRead, SchemaWrite)]
pub struct ShredData {
    pub common_header: ShredCommonHeader,
    pub data_header: DataShredHeader,
    pub payload: Payload,
}

#[derive(Clone, Debug, SchemaRead, SchemaWrite)]
pub struct ShredCode {
    pub common_header: ShredCommonHeader,
    pub coding_header: CodingShredHeader,
    pub payload: Payload,
}
