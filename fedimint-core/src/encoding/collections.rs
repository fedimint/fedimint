use std::any::TypeId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;

use crate::module::registry::ModuleRegistry;
use crate::{Decodable, DecodeError, Encodable, ModuleDecoderRegistry};

impl<T> Encodable for &[T]
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            let bytes = unsafe { std::mem::transmute::<&[T], &[u8]>(self) };

            (bytes.len() as u64).consensus_encode(writer)?;
            writer.write_all(bytes)?;
            return Ok(());
        }

        (self.len() as u64).consensus_encode(writer)?;

        for item in *self {
            item.consensus_encode(writer)?;
        }
        Ok(())
    }
}

impl<T> Encodable for Vec<T>
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        (self as &[T]).consensus_encode(writer)
    }
}

impl<T> Decodable for Vec<T>
where
    T: Decodable + 'static,
{
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        const CHUNK_SIZE: usize = 64 * 1024;

        if TypeId::of::<T>() == TypeId::of::<u8>() {
            let len =
                u64::consensus_decode_partial_from_finite_reader(d, &ModuleRegistry::default())?;

            let mut len: usize =
                usize::try_from(len).map_err(|_| DecodeError::from_str("size exceeds memory"))?;

            let mut bytes = vec![];

            // Adapted from <https://github.com/rust-bitcoin/rust-bitcoin/blob/e2b9555070d9357fb552e56085fb6fb3f0274560/bitcoin/src/consensus/encode.rs#L667-L674>
            while 0 < len {
                let chunk_start = bytes.len();
                let chunk_size = core::cmp::min(len, CHUNK_SIZE);
                let chunk_end = chunk_start + chunk_size;
                bytes.resize(chunk_end, 0u8);
                d.read_exact(&mut bytes[chunk_start..chunk_end])?;
                len -= chunk_size;
            }

            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return Ok(unsafe { std::mem::transmute::<Vec<u8>, Self>(bytes) });
        }
        let len = u64::consensus_decode_partial_from_finite_reader(d, modules)?;

        // `collect` under the hood uses `FromIter::from_iter`, which can potentially be
        // backed by code like:
        // <https://github.com/rust-lang/rust/blob/fe03b46ee4688a99d7155b4f9dcd875b6903952d/library/alloc/src/vec/spec_from_iter_nested.rs#L31>
        // This can take `size_hint` from input iterator and pre-allocate memory
        // upfront with `Vec::with_capacity`. Because of that untrusted `len`
        // should not be used directly.
        let cap_len = std::cmp::min(8_000 / std::mem::size_of::<T>() as u64, len);

        // Up to a cap, use the (potentially specialized for better perf in stdlib)
        // `from_iter`.
        let mut v: Self = (0..cap_len)
            .map(|_| T::consensus_decode_partial_from_finite_reader(d, modules))
            .collect::<Result<Self, DecodeError>>()?;

        // Add any excess manually avoiding any surprises.
        while (v.len() as u64) < len {
            v.push(T::consensus_decode_partial_from_finite_reader(d, modules)?);
        }

        assert_eq!(v.len() as u64, len);

        Ok(v)
    }
}

impl<T> Encodable for VecDeque<T>
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        (self.len() as u64).consensus_encode(writer)?;
        for i in self {
            i.consensus_encode(writer)?;
        }
        Ok(())
    }
}

impl<T> Decodable for VecDeque<T>
where
    T: Decodable + 'static,
{
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from(
            Vec::<T>::consensus_decode_partial_from_finite_reader(d, modules)?,
        ))
    }
}

impl<T, const SIZE: usize> Encodable for [T; SIZE]
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            let bytes = unsafe { std::mem::transmute::<&[T; SIZE], &[u8; SIZE]>(self) };
            writer.write_all(bytes)?;
            return Ok(());
        }

        for item in self {
            item.consensus_encode(writer)?;
        }
        Ok(())
    }
}

impl<T, const SIZE: usize> Decodable for [T; SIZE]
where
    T: Decodable + Debug + Default + Copy + 'static,
{
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        // From <https://github.com/rust-lang/rust/issues/61956>
        unsafe fn horribe_array_transmute_workaround<const N: usize, A, B>(
            mut arr: [A; N],
        ) -> [B; N] {
            let ptr = std::ptr::from_mut(&mut arr).cast::<[B; N]>();
            let res = unsafe { ptr.read() };
            core::mem::forget(arr);
            res
        }

        if TypeId::of::<T>() == TypeId::of::<u8>() {
            let mut bytes = [0u8; SIZE];
            d.read_exact(bytes.as_mut_slice())?;

            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return Ok(unsafe { horribe_array_transmute_workaround(bytes) });
        }

        // todo: impl without copy
        let mut data = [T::default(); SIZE];
        for item in &mut data {
            *item = T::consensus_decode_partial_from_finite_reader(d, modules)?;
        }
        Ok(data)
    }
}

impl<K, V> Encodable for BTreeMap<K, V>
where
    K: Encodable,
    V: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        (self.len() as u64).consensus_encode(writer)?;
        for (k, v) in self {
            k.consensus_encode(writer)?;
            v.consensus_encode(writer)?;
        }
        Ok(())
    }
}

impl<K, V> Decodable for BTreeMap<K, V>
where
    K: Decodable + Ord,
    V: Decodable,
{
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut res = Self::new();
        let len = u64::consensus_decode_partial_from_finite_reader(d, modules)?;
        for _ in 0..len {
            let k = K::consensus_decode_partial_from_finite_reader(d, modules)?;
            if res
                .last_key_value()
                .is_some_and(|(prev_key, _v)| k <= *prev_key)
            {
                return Err(DecodeError::from_str("Non-canonical encoding"));
            }
            let v = V::consensus_decode_partial_from_finite_reader(d, modules)?;
            if res.insert(k, v).is_some() {
                return Err(DecodeError::from_str("Duplicate key"));
            }
        }
        Ok(res)
    }
}

impl<K> Encodable for BTreeSet<K>
where
    K: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        (self.len() as u64).consensus_encode(writer)?;
        for k in self {
            k.consensus_encode(writer)?;
        }
        Ok(())
    }
}

impl<K> Decodable for BTreeSet<K>
where
    K: Decodable + Ord,
{
    fn consensus_decode_partial_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut res = Self::new();
        let len = u64::consensus_decode_partial_from_finite_reader(d, modules)?;
        for _ in 0..len {
            let k = K::consensus_decode_partial_from_finite_reader(d, modules)?;
            if res.last().is_some_and(|prev_key| k <= *prev_key) {
                return Err(DecodeError::from_str("Non-canonical encoding"));
            }
            if !res.insert(k) {
                return Err(DecodeError::from_str("Duplicate key"));
            }
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests;
