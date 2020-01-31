//! Stubs for typechecked merkle tree operations.
//! Just dummy types for now.

use crate::hasher::Hasher;
use blake2::Blake2s;
use codec::{Decode, Encode};
use core::{fmt::Debug, marker::PhantomData};
use derivative::Derivative;

#[derive(Encode, Decode, Derivative)]
#[derivative(
    Clone(bound = "H::Output: Clone"),
    PartialEq(bound = "H::Output: PartialEq"),
    Eq(bound = "H::Output: Eq"),
    Debug(bound = "H::Output: Debug")
)]
pub struct MerkleRoot<T, H: Hasher = Blake2s> {
    hash: H::Output,
    _spook: PhantomData<T>,
}

#[derive(Encode, Decode, Derivative)]
#[derivative(
    Clone(bound = "H::Output: Clone"),
    PartialEq(bound = "H::Output: PartialEq"),
    Eq(bound = "H::Output: Eq"),
    Debug(bound = "H::Output: Debug")
)]
pub struct Hashed<T, H: Hasher = Blake2s> {
    hash: H::Output,
    _spook: PhantomData<T>,
}

impl<T, H: Hasher> Hashed<T, H> {
    pub fn prehashed(hash: H::Output) -> Self {
        Self {
            hash: hash,
            _spook: PhantomData,
        }
    }
}

#[derive(Encode, Decode, Derivative)]
#[derivative(
    Clone(bound = "H::Output: Clone"),
    Debug(bound = "H::Output: Debug"),
    PartialEq(bound = "H::Output: PartialEq"),
    PartialEq = "feature_allow_slow_enum",
    Eq(bound = "H::Output: Eq")
)]
pub enum ProofElement<H: Hasher = Blake2s> {
    Left(H::Output),
    Right(H::Output),
}

pub fn verify_proof<T, H: Hasher>(
    _root: &MerkleRoot<T, H>,
    _proof: &[ProofElement<H>],
    _leaf: &H::Output,
) -> bool
where
    H::Output: AsRef<[u8]>,
{
    todo!()
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn hashed_is_codec() {
        struct Blah {}
        #[allow(dead_code)]
        fn to_hash() -> impl Encode + Decode {
            Hashed::<Blah>::prehashed([0u8; 32])
        }
    }
}
