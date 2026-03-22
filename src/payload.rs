use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut, Range},
};

use wincode::{
    config::Config,
    io::{Reader, Writer},
    ReadResult, SchemaRead, SchemaWrite, TypeMeta, WriteResult,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payload {
    bytes: Vec<u8>,
}

impl Payload {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len);
    }

    pub fn get(&self, range: Range<usize>) -> Option<&[u8]> {
        self.bytes.get(range)
    }

    pub fn get_mut(&mut self, range: Range<usize>) -> Option<&mut [u8]> {
        self.bytes.get_mut(range)
    }
}

impl From<Vec<u8>> for Payload {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for Payload {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Deref for Payload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for Payload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

// Wincode SchemaWrite: serialize as length-prefixed bytes (same as Vec<u8>).
unsafe impl<C: Config> SchemaWrite<C> for Payload {
    type Src = Self;

    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        <Vec<u8> as SchemaWrite<C>>::size_of(&src.bytes)
    }

    fn write(writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
        <Vec<u8> as SchemaWrite<C>>::write(writer, &src.bytes)
    }
}

// Wincode SchemaRead: deserialize from length-prefixed bytes (same as Vec<u8>).
unsafe impl<'de, C: Config> SchemaRead<'de, C> for Payload {
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Dynamic;

    fn read(reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let mut vec_dst: MaybeUninit<Vec<u8>> = MaybeUninit::uninit();
        <Vec<u8> as SchemaRead<'de, C>>::read(reader, &mut vec_dst)?;
        // SAFETY: read() succeeded, so vec_dst is initialized.
        let vec = unsafe { vec_dst.assume_init() };
        dst.write(Payload::from(vec));
        Ok(())
    }
}
