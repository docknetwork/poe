use blake2::digest::generic_array::typenum::U32;
use blake2::Digest;
use codec::{Decode, Encode};
use core::{fmt::Debug, marker::PhantomData};
use derivative::Derivative;

pub trait Hasher<Output>: Digest {
    fn output(self) -> Output;
}

impl<H: Digest<OutputSize = U32>> Hasher<[u8; 32]> for H {
    fn output(self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        ret.copy_from_slice(&self.result());
        ret
    }
}

pub trait Hashable<H: Digest> {
    fn hash(&self, hasher: &mut H);
}

impl<H: Digest, T: Hashable<H>> Hashable<H> for [T] {
    fn hash(&self, hasher: &mut H) {
        for s in self {
            s.hash(hasher);
        }
    }
}

impl<H: Digest, T: Hashable<H>> Hashable<H> for [T; 32] {
    fn hash(&self, hasher: &mut H) {
        let a: &[T] = self.as_ref();
        a.hash(hasher);
    }
}

impl<H: Digest, A: Hashable<H>, B: Hashable<H>> Hashable<H> for (&A, &B) {
    fn hash(&self, hasher: &mut H) {
        self.0.hash(hasher);
        self.1.hash(hasher);
    }
}

impl<H: Digest> Hashable<H> for u64 {
    fn hash(&self, hasher: &mut H) {
        hasher.input(self.to_be_bytes());
    }
}

impl<H: Digest> Hashable<H> for u8 {
    fn hash(&self, hasher: &mut H) {
        hasher.input([*self]);
    }
}

#[derive(Encode, Decode, Derivative)]
#[derivative(
    Clone(bound = "Output: Clone"),
    PartialEq(bound = "Output: PartialEq"),
    Eq(bound = "Output: Eq"),
    Debug(bound = "Output: Debug"),
    Default(bound = "Output: Default")
)]
pub struct Hashed<T, H: Hasher<Output>, Output> {
    pub hash: Output,
    _spook: PhantomData<(T, H)>,
}

impl<T, H: Hasher<O>, O> Hashed<T, H, O> {
    pub fn prehashed(hash: O) -> Self {
        let _spook = PhantomData;
        Self { hash, _spook }
    }
}

impl<T: Hashable<H>, H: Hasher<O>, O> From<T> for Hashed<T, H, O> {
    fn from(t: T) -> Self {
        Hashed::prehashed(hash::<T, H, O>(&t))
    }
}

pub fn hash<T: Hashable<H>, H: Hasher<O>, O>(preimage: &T) -> O {
    let mut hasher: H = H::new();
    preimage.hash(&mut hasher);
    hasher.output()
}
