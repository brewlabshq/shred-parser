use wincode::{containers::Pod, SchemaRead, SchemaWrite};

#[derive(Clone, Debug, SchemaRead, SchemaWrite)]
pub struct Payload {
    #[wincode(with = "Vec<Pod<_>>")]
    pub bytes: Vec<u8>,
}
