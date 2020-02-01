//! Stubs for typechecked merkle tree operations.
//! Just dummy types for now.

use crate::hasher::{hash, Hashable, Hashed, Hasher};
use codec::{Decode, Encode};
use core::{fmt::Debug, iter::IntoIterator, marker::PhantomData};
use derivative::Derivative;

#[derive(Encode, Decode, Derivative)]
#[derivative(
    Clone(bound = "O: Clone"),
    PartialEq(bound = "O: PartialEq"),
    Eq(bound = "O: Eq"),
    Debug(bound = "O: Debug"),
    // Default makes sense in this context, A default MerkleRoot represents
    // a Root with no possible leaves. Since nothing hashes to [0u8; 32],
    // there are no valid proofs of inclusion in the default.
    Default(bound = "O: Default"),
)]
pub struct MerkleRoot<T, H, O> {
    hash: O,
    _spook: PhantomData<(T, H)>,
}

impl<T, H: Hasher<O>, O> MerkleRoot<T, H, O> {
    pub fn from_root(hash: O) -> Self {
        let _spook = PhantomData;
        Self { hash, _spook }
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum ProofElement<O> {
    Left(O),
    Right(O),
}

impl<O> ProofElement<O> {
    /// Concatentate self with sibling in the proper order and return the hash.
    fn merge<H>(&self, sibling: &O) -> O
    where
        H: Hasher<O>,
        O: Hashable<H>,
    {
        let (a, b) = match self {
            ProofElement::Left(h) => (h, sibling),
            ProofElement::Right(h) => (sibling, h),
        };
        hash(&(a, b))
    }
}

pub fn verify_proof<T, H: Hasher<O>, O: Hashable<H> + Eq>(
    root: &MerkleRoot<T, H, O>,
    proof: &[ProofElement<O>],
    leaf: Hashed<T, H, O>,
) -> bool {
    let leaf_doublehash = hash::<_, H, _>(&leaf.hash);
    let expected_root = proof
        .into_iter()
        .fold(leaf_doublehash, |leaf, pe| pe.merge(&leaf));
    expected_root == root.hash
}

#[cfg(test)]
mod test {
    use super::*;
    use blake2::Blake2s;

    fn static_assert_impls(_: impl Encode + Decode + Eq + Debug) {}

    #[test]
    fn types_impl_needed_traits() {
        struct Blah {}
        #[derive(Encode, Decode)]
        struct O {}
        static_assert_impls(Hashed::<Blah, Blake2s, [u8; 32]>::prehashed([0u8; 32]));
        static_assert_impls(MerkleRoot::<Blah, Blake2s, [u8; 32]>::from_root([0u8; 32]));
        static_assert_impls(ProofElement::<[u8; 32]>::Left([0u8; 32]));
    }

    #[test]
    fn proofs_and_trees() {
        todo!("Import merkle proof tests from outlines/andrew-revokable-signatures");
    }
}
