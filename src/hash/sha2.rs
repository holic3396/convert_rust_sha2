use std::mem::size_of;
use std::ptr::copy;

use bytes::{BufMut, Bytes, BytesMut};

use crate::hash::{HashContext, Hasher, HashModule};
use super::num::{PrimInt, FromPrimitive};

trait UInt: PrimInt + FromPrimitive {
    fn overflowing_add(self, other: Self) -> (Self, bool);
}

impl UInt for u32 {
    fn overflowing_add(self, other: Self) -> (Self, bool) {
        <Self>::overflowing_add(self, other)
    }
}

impl UInt for u64 {
    fn overflowing_add(self, other: Self) -> (Self, bool) {
        <Self>::overflowing_add(self, other)
    }
}

#[inline]
fn rotl32(x: u32, n: u32) -> u32 {
    (x << n) | ((x & 0xffffffff) >> (32 - (n)))
}

#[inline]
fn rotl64(x: u64, n: u64) -> u64 {
    (x << n) | ((x) & 0xffffffffffffffff) >> (64 - (n))
}

static A: usize = 0;
static B: usize = 1;
static C: usize = 2;
static D: usize = 3;
static E: usize = 4;
static F: usize = 5;
static G: usize = 6;
static H: usize = 7;

struct Sha2Params<T: UInt + 'static> {
    primes: &'static [T],
    init: &'static [T],
    sigma0_cap: fn(T) -> T,
    sigma1_cap: fn(T) -> T,
    sigma0_low: fn(T) -> T,
    sigma1_low: fn(T) -> T,
    rotl: fn(T, T) -> T,
    digest_len: usize,
    work_size: usize,
    mask_byte: T,
    input_block_size: usize,
    append_block_size: usize,
    dump_size: usize,
}

#[inline]
fn ch<T: UInt>(x: T, y: T, z: T) -> T {
    z ^ (x & (y ^ z))
}

#[inline]
fn maj<T: UInt>(x: T, y: T, z: T) -> T {
    (x & y) | (z & (x | y))
}

static K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

static SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

//#define Sigma0(x)	(ROTL32((x),30) ^ ROTL32((x),19) ^ ROTL32((x),10))
//#define Sigma1(x)	(ROTL32((x),26) ^ ROTL32((x),21) ^ ROTL32((x),7))
//#define sigma0(x)	(ROTL32((x),25) ^ ROTL32((x),14) ^ ((x)>>3))
//#define sigma1(x)	(ROTL32((x),15) ^ ROTL32((x),13) ^ ((x)>>10))
static SHA256_PARAMS: Sha2Params<u32> = Sha2Params {
    primes: &K256,
    init: &SHA256_INIT,
    sigma0_cap: |x: u32| -> u32 { rotl32(x, 30) ^ rotl32(x, 19) ^ rotl32(x, 10) },
    sigma1_cap: |x: u32| -> u32 { rotl32(x, 26) ^ rotl32(x, 21) ^ rotl32(x, 7) },
    sigma0_low: |x: u32| -> u32 { rotl32(x, 25) ^ rotl32(x, 14) ^ (x >> 3) },
    sigma1_low: |x: u32| -> u32 { rotl32(x, 15) ^ rotl32(x, 13) ^ (x >> 10) },
    rotl: rotl32,
    digest_len: 32,
    work_size: 64,
    mask_byte: 0x3f,
    input_block_size: 64,
    append_block_size: 8,
    dump_size: 4,
};

static K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

static SHA512_INIT: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];

static SHA512_PARAMS: Sha2Params<u64> = Sha2Params {
    primes: &K512,
    init: &SHA512_INIT,
    sigma0_cap: |x: u64| -> u64 { rotl64(x, 36) ^ rotl64(x, 30) ^ rotl64(x, 25) },
    sigma1_cap: |x: u64| -> u64 { rotl64(x, 50) ^ rotl64(x, 46) ^ rotl64(x, 23) },
    sigma0_low: |x: u64| -> u64 { rotl64(x, 63) ^ rotl64(x, 56) ^ (x >> 7) },
    sigma1_low: |x: u64| -> u64 { rotl64(x, 45) ^ rotl64(x, 3) ^ (x >> 6) },
    rotl: rotl64,
    digest_len: 64,
    work_size: 80,
    mask_byte: 0x7f,
    input_block_size: 128,
    append_block_size: 16,
    dump_size: 8,
};

struct Sha2<T: UInt + 'static> {
    context: HashContext<T>,
    param: &'static Sha2Params<T>,
}

impl<T: UInt> HashModule for Sha2<T> {
    fn digest_len(&self) -> usize {
        self.param.digest_len
    }

    fn initialize(&mut self) {
        for i in 0..8usize {
            self.context.digest[i] = self.param.init[i]
        }
    }

    fn compress_block(&mut self) {
        let mut x = vec![T::zero(); self.param.work_size];

        if cfg!(target_endian = "little") {
            for i in 0..16 {
                self.context.input[i] = self.context.input[i].swap_bytes();
            }
        }

        for i in 0..16usize {
            x[i] = self.context.input[i];
        }

        for i in 0..x.len() - 16 {
            x[i + 16] = (self.param.sigma1_low)(x[i + 14])
                .overflowing_add(x[i + 9]).0
                .overflowing_add((self.param.sigma0_low)(x[i + 1])).0
                .overflowing_add(x[i]).0;
        }

        // a, b, c, d, e, f, g, h
        let mut ring = [T::zero(); 8];
        for i in 0..8usize {
            ring[i] = self.context.digest[i]
        }

//#define FF(a,b,c,d,e,f,g,h,i)\
//  h += Sigma1(e) + Ch(e,f,g) + K256[i] + X[i];\
//  d += h;\
//  h += Sigma0(a) + Maj(a,b,c);
        for i in 0..x.len() {
            let t1 = ring[H]
                .overflowing_add((self.param.sigma1_cap)(ring[E])).0
                .overflowing_add(ch(ring[E], ring[F], ring[G])).0
                .overflowing_add(self.param.primes[i]).0
                .overflowing_add(x[i]).0;
            ring[D] = ring[D].overflowing_add(t1).0;
            ring[H] = t1
                .overflowing_add((self.param.sigma0_cap)(ring[A])).0
                .overflowing_add(maj(ring[A], ring[B], ring[C])).0;
            ring = {
                let mut ring_clone = [ring[7]; 8];
                unsafe { copy(ring.as_ptr(), ring_clone.as_mut_ptr().add(1), 7) }
                ring_clone
            };
        }

        for i in 0..8usize {
            self.context.digest[i] = self.context.digest[i].overflowing_add(ring[i]).0
        }
    }

    fn pad_length(&mut self) {
        self.context.input[14] = self.context.count[1];
        self.context.input[15] = self.context.count[0];
        if cfg!(target_endian = "little") {
            self.context.input[14] = self.context.input[14].swap_bytes();
            self.context.input[15] = self.context.input[15].swap_bytes();
        }
    }

    fn dump_digest(&self) -> Bytes {
        let mut dump = Vec::<u8>::new();
        self.context.digest.iter().for_each(|&x| {
            for i in 0..self.param.dump_size {
                let c: u64 = num::cast(x >> ((self.param.dump_size - i - 1) * 8)).unwrap();
                dump.put_u8((c & 0xff) as u8);
            }
        });
        let mut digested = BytesMut::with_capacity(self.digest_len());
        digested.put_slice(dump.as_slice());
        digested.freeze()
    }
}

impl<T: UInt> Hasher for Sha2<T> {
    fn update(&mut self, _message: &Vec<u8>) {
        let msg_len = _message.len();

        if msg_len == 0 {
            return;
        }

        let mask_byte = self.param.mask_byte;
        let input_block_size = self.param.input_block_size;
        let tmp = self.context.count[0];

        let mut m_index = 0usize;
        let mut b_index: usize = num::cast(tmp & mask_byte).unwrap();
        let mut t_len = msg_len + b_index;

        self.context.count[0] = self.context.count[0].overflowing_add(T::from_usize(msg_len).unwrap()).0;
        if self.context.count[0] < tmp {
            self.context.count[1] = self.context.count[1] + T::from_u32(1).unwrap();
        }

        if input_block_size > self.context.size_of_input() {
            return;
        }

        if b_index > self.context.size_of_input() - 1 {
            return;
        }

        while t_len >= input_block_size {
            if msg_len - m_index < input_block_size - b_index {
                break;
            }

            self.context.copy_to_input(_message, b_index, m_index, input_block_size - b_index);
            self.compress_block();
            m_index += input_block_size - b_index;
            b_index = 0;
            t_len -= input_block_size;
        }

        if t_len < b_index {
            return;
        }

        self.context.copy_to_input(_message, b_index, m_index, t_len - b_index);
    }

    fn digest(&mut self) -> Bytes {
        match self.digest_raw() {
            Some(v) => v.slice(0..self.digest_len()),
            None => panic!("Fail to digest")
        }
    }
}

impl<T: UInt> Sha2<T> {
    pub fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            param: self.param,
        }
    }

    fn digest_raw(&mut self) -> Option<Bytes> {
        let mask_byte = self.param.mask_byte;
        let input_block_size = self.param.input_block_size;
        let append_block_size = self.param.append_block_size;

        let mut cloned = self.clone();

        let mut b_index: usize = num::cast(cloned.context.count[0] & mask_byte).unwrap();

        if b_index > cloned.context.size_of_input() - 2 {
            return None;
        }

        unsafe {
            (cloned.context.input.as_mut_ptr() as *mut u8).add(b_index).replace(0x80);
            b_index += 1;
        }

        if input_block_size > cloned.context.size_of_input() {
            return None;
        }

        if b_index > input_block_size - append_block_size {
            cloned.context.set_input(b_index, input_block_size - b_index);
            cloned.compress_block();
            cloned.context.set_input(0, input_block_size - append_block_size);
        } else {
            cloned.context.set_input(b_index, input_block_size - append_block_size - b_index);
        }

        cloned.context.count[1] = (cloned.context.count[1] << 3) | (cloned.context.count[0] >> 29);
        cloned.context.count[0] = cloned.context.count[0] << 3;

        cloned.pad_length();
        cloned.compress_block();
        Some(cloned.dump_digest())
    }
}

type Sha256 = Sha2<u32>;
type Sha512 = Sha2<u64>;

pub fn get_sha512() -> Box<dyn Hasher> {
    let mut hasher = Box::new(Sha512 {
        context: HashContext::hash64_context(),
        param: &SHA512_PARAMS,
    });
    hasher.initialize();
    hasher
}

pub fn get_sha256() -> Box<dyn Hasher> {
    let mut hasher = Box::new(Sha256 {
        context: HashContext::hash32_context(),
        param: &SHA256_PARAMS,
    });
    hasher.initialize();
    hasher
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;

    use crate::to_hex_string;
    use crate::hash::sha2::{get_sha256, get_sha512};

    // Hash test vector reference: https://www.di-mgt.com.au/sha_testvectors.html
    fn sha256_test(msg: &Vec<u8>, digested: &str) {
        let mut hasher = get_sha256();
        hasher.update(msg);
        let v = { to_hex_string(&hasher.digest()) };
        assert_eq!(v.as_str(), digested);
    }

    fn sha512_test(msg: &Vec<u8>, digested: &str) {
        let mut hasher = get_sha512();
        hasher.update(msg);
        let v = { to_hex_string(&hasher.digest()) };
        assert_eq!(v.as_str(), digested);
    }

    #[test]
    fn sha256_simple_test() {
        sha256_test(&vec![], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        sha256_test(&"abc".as_bytes().to_vec(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn sha256_long_test() {
        let msg1 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let msg2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

        sha256_test(
            &msg1.as_bytes().to_vec(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
        sha256_test(
            &msg2.as_bytes().to_vec(),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        )
    }


    #[test]
    fn sha512_simple_test() {
        sha512_test(&vec![], "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        sha512_test(&"abc".as_bytes().to_vec(), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

    #[test]
    fn sha512_long_test() {
        let msg1 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let msg2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

        sha512_test(
            &msg1.as_bytes().to_vec(),
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        );
        sha512_test(
            &msg2.as_bytes().to_vec(),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        )
    }

}