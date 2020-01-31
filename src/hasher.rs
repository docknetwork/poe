use blake2::Digest;
use blake2::digest::generic_array::typenum::U32;

pub trait Hasher {
    type Output;
    fn hash(preimage: &[&[u8]]) -> Self::Output;
}

impl<H: Digest<OutputSize = U32>> Hasher for H {
    type Output = [u8; 32];
    fn hash(preimage: &[&[u8]]) -> Self::Output {
        let mut hasher = H::new();
        for p in preimage {
            hasher.input(p);
        }
        let mut ret = Self::Output::default();
        ret.copy_from_slice(&hasher.result());
        ret
    }
}
