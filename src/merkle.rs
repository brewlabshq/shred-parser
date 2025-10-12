use serde::{Deserialize, Serialize};

use crate::{payload::Payload, CodingShredHeader, DataShredHeader, ShredCommonHeader};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ShredData {
    pub common_header: ShredCommonHeader,
    pub data_header: DataShredHeader,
    pub payload: Payload,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ShredCode {
    pub common_header: ShredCommonHeader,
    pub coding_header: CodingShredHeader,
    pub payload: Payload,
}
