extern crate num;

use std::mem::size_of;

use bytes::Bytes;
use self::num::PrimInt;

trait HashModule {
    fn digest_len(&self) -> usize;
    fn initialize(&mut self);
    fn compress_block(&mut self);
    fn pad_length(&mut self);
    fn dump_digest(&self) -> Bytes;
}

pub trait Hasher {
    fn update(&mut self, message: &Vec<u8>);
    fn digest(&mut self) -> Bytes;
}

struct HashContext<T> {
    size: usize,
    pub digest: Vec<T>,
    pub input: Vec<T>,
    pub count: Vec<T>,
}

// hashX_context 는 매크로로 추출 가능
impl<T: PrimInt + Clone> HashContext<T> {
    pub fn size_of_input(&self) -> usize {
        self.input.len() * size_of::<u32>()
    }

    pub fn copy_to_input(&mut self, _message: &Vec<u8>, b_index: usize, m_index: usize, len: usize) {
        unsafe {
            (self.input.as_mut_ptr() as *mut u8).add(b_index).copy_from(_message.as_ptr().add(m_index), len);
        }
    }

    pub fn set_input(&mut self, b_index: usize, len: usize) {
        unsafe {
            (self.input.as_mut_ptr() as *mut u8).add(b_index).write_bytes(0, len)
        }
    }

    pub fn clone(&self) -> HashContext<T> {
        HashContext {
            size: self.size,
            digest: self.digest.clone(),
            input: self.input.clone(),
            count: self.count.clone(),
        }
    }

    pub fn hash32_context() -> HashContext<T> {
        HashContext {
            size: 32,
            digest: vec![T::zero(); 16],
            input: vec![T::zero(); 32],
            count: vec![T::zero(); 4],
        }
    }

    pub fn hash64_context() -> HashContext<T> {
        HashContext {
            size: 64,
            digest: vec![T::zero(); 16],
            input: vec![T::zero(); 32],
            count: vec![T::zero(); 4],
        }
    }
}

pub mod sha2;
