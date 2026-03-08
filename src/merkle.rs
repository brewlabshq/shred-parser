
use crate::{CodingShredHeader, DataShredHeader, ShredCommonHeader};
use wincode::{SchemaRead, SchemaWrite};

#[derive(Clone, Debug, SchemaRead, SchemaWrite)]
pub struct ShredData {
    pub common_header: ShredCommonHeader,
    pub data_header: DataShredHeader,
}

#[derive(Clone, Debug, SchemaRead, SchemaWrite)]
pub struct ShredCode {
    pub common_header: ShredCommonHeader,
    pub coding_header: CodingShredHeader,
}

// #[derive(Debug, Default, PartialEq, Eq, Clone, SchemaWrite, SchemaRead)]
// pub struct Entry {
//     /// The number of hashes since the previous Entry ID.
//     pub num_hashes: u64,

//     /// The SHA-256 hash `num_hashes` after the previous Entry ID.
//     #[wincode(with = "Pod<Hash>")]
//     pub hash: Hash,

//     /// An unordered list of transactions that were observed before the Entry ID was
//     /// generated. They may have been observed before a previous Entry ID but were
//     /// pushed back into this list to ensure deterministic interpretation of the ledger.
//     #[wincode(with = "Vec<crate::wincode::VersionedTransaction>")]
//     pub transactions: Vec<VersionedTransaction>,
// }
