
// pub(crate) mod serde_bytes_payload {
//     use {
//         super::Payload,
//         serde::{Deserialize, Deserializer, Serializer},
//         serde_bytes::ByteBuf,
//     };

//     pub(crate) fn serialize<S: Serializer>(
//         payload: &Payload,
//         serializer: S,
//     ) -> Result<S::Ok, S::Error> {
//         serializer.serialize_bytes(payload)
//     }

//     pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Payload, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         Deserialize::deserialize(deserializer)
//             .map(ByteBuf::into_vec)
//             .map(Payload::from)
//     }
// }
