#![cfg_attr(not(feature = "std"), no_std)]

pub mod hasher;
pub mod merkle;

use crate::hasher::Hasher;
use crate::merkle::{verify_proof, Hashed, MerkleRoot, ProofElement};
use codec::{Decode, Encode};
use frame_support::{
    decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure, StorageMap,
};
use system::ensure_signed;

// Max number of authorized accounts to operate on leaf-based revocation
// There's got to be a
pub const MAX_AUTHORIZED_ACCOUNTS: u8 = 10u8;

/// The output of the hash function used constructing merkle roots configurable.\
/// By default it is the the output specified in system::Trait.
pub trait Trait: system::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    /// The hash function used when constructing and verifying Merkle proofs.
    type TreeHash: Hasher<Output = [u8; 32]>;

    /// hash Self::AccountId using Self::Treehash
    fn account_id_hash(account: &Self::AccountId) -> <<Self as Trait>::TreeHash as Hasher>::Output;
}

pub struct Document;
pub type UnixTimeSeconds = u64;
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
enum Revokable<T> {
    NotRevoked(T),
    Revoked,
}

decl_storage! {
    trait Store for Module<T: Trait> as TemplateModule {
        /// Immutable anchors. Once inserted, they cannot be removed.
        Anchors: map MerkleRoot<Document, T::TreeHash> => Option<T::BlockNumber>;

        /// Scoping Anchors to the parties with revocation permission prevents frontrunning
        /// attacks.
        /// When a party proves their membership in "Administrators", they may revoke this anchor.
        RevocableAnchors: map (
            MerkleRoot<T::AccountId, T::TreeHash>, // Administrators
            MerkleRoot<Document, T::TreeHash>
        ) => Option<Revokable<T::BlockNumber>>;

        /// Suspensions mapped to suspension expiration.
        /// Setting suspension expiration to u64::max() is a permanent revocation.
        /// A party needs to prove their membership in "Administrators" in order to issue a
        /// suspension.
        SuspendedLeaves: map (
            MerkleRoot<T::AccountId, T::TreeHash>, // Administrators
            Hashed<Document, T::TreeHash>
        ) => Option<UnixTimeSeconds>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        fn create_anchor(_origin, root: MerkleRoot<Document, T::TreeHash>) -> DispatchResult {
            debug_assert!(Anchors::<T>::exists(&root) || Anchors::<T>::get(&root) == None);
            ensure!(!Anchors::<T>::exists(&root), "The root is already anchored.");
            Anchors::<T>::insert(&root, <system::Module<T>>::block_number());
            Ok(())
        }

        fn create_revocable_anchor(
            _origin,
            admins: MerkleRoot<T::AccountId, T::TreeHash>,
            root: MerkleRoot<Document, T::TreeHash>
        ) -> DispatchResult {
            let key = (admins, root.clone());
            debug_assert!( // todo: move this to a test
                RevocableAnchors::<T>::exists(&key) || RevocableAnchors::<T>::get(&key) == None
            );
            ensure!(!RevocableAnchors::<T>::exists(&key), "The root has already been anchored.");
            RevocableAnchors::<T>::insert(
                &key,
                Revokable::NotRevoked(<system::Module<T>>::block_number()),
            );
            Ok(())
        }

        /// An anchor can be revoked even before it is posted.
        fn revoke_anchor(
            origin,
            admins: MerkleRoot<T::AccountId, T::TreeHash>,
            root: MerkleRoot<Document, T::TreeHash>,
            proof: Vec<ProofElement<T::TreeHash>>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let valid = verify_proof(&admins, &proof, &T::account_id_hash(&sender));
            ensure!(valid, "invalid proof");
            RevocableAnchors::<T>::insert((admins, root), Revokable::Revoked);
            Ok(())
        }

        /// revoke leaf until suspend_end. If suspend_end is in the past, this has no sematic
        /// effect. Using u64::max() for suspend_end is a permanent revocation.
        ///
        /// This is independent of the anchor since we don't have/keep leaf data on-chain
        /// and merkle proof submission doesn't matter.
        pub fn suspend_leaf(
            origin,
            proof: Vec<ProofElement<T::TreeHash>>,
            admins: MerkleRoot<T::AccountId, T::TreeHash>,
            leaf_value: Hashed<Document, T::TreeHash>,
            suspend_end: UnixTimeSeconds,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let key = (admins.clone(), leaf_value);
            let current_suspend_end = SuspendedLeaves::<T>::get(&key);
            debug_assert!( // todo: move this to a test
                SuspendedLeaves::<T>::exists(&key) || current_suspend_end == None,
                "if no suspension exists, the default is expected to be None"
            );
            match current_suspend_end {
                Some(end) => ensure!(suspend_end <= end, "leaf is already suspended until specified time"),
                None => {}
            }
            let valid = verify_proof(&admins, &proof, &T::account_id_hash(&sender));
            ensure!(valid, "invalid proof");
            SuspendedLeaves::<T>::insert(key, suspend_end);
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    // // this is for revoking the anchor not any one of the leafs and directly tied to
    // // the origin account at create time. Note: for (on-chain) merkle tree aggregation
    // // we don't allow "root" revocation.
    // pub fn is_revokable(_anchor: <T as Trait>::MerkleHash) -> Result<bool, &'static str> {
    //     unimplemented!()
    //     // ensure!(Anchors::<T>::exists(&anchor), "This anchor does not exist.");
    //     // let (_, _, revokable) = Anchors::<T>::get(&anchor);
    //     // Ok(revokable)
    // }

    // pub fn is_leaf_revoked(
    //     _anchor_value: <T as Trait>::MerkleHash,
    //     _leaf_value: <T as Trait>::MerkleHash,
    // ) -> bool {
    //     unimplemented!()
    // }
}

decl_event!(
    pub enum Event<T>
    where
        <T as system::Trait>::AccountId,
    {
        Dummy(AccountId),
    }
);

/// tests for this pallet
#[cfg(test)]
mod tests {
    use super::*;

    use frame_support::{impl_outer_origin, parameter_types, weights::Weight};
    use sp_core::H256;
    use sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup},
        Perbill,
    };

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    // For testing the pallet, we construct most of a mock runtime. This means
    // first constructing a configuration type (`Test`) which `impl`s each of the
    // configuration traits of modules we want to use.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;
    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    }
    impl system::Trait for Test {
        type Origin = Origin;
        type Call = ();
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type MaximumBlockLength = MaximumBlockLength;
        type AvailableBlockRatio = AvailableBlockRatio;
        type Version = ();
        type ModuleToIndex = ();
    }
    impl Trait for Test {
        type Event = ();
        type TreeHash = blake2::Blake2s;
        fn account_id_hash(account_id: &u64) -> [u8; 32] {
            Self::TreeHash::hash(&[&account_id.to_be_bytes()])
        }
    }

    // This function basically just builds a genesis storage key/value store according to
    // our desired mockup.
    fn new_test_ext() -> sp_io::TestExternalities {
        system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap()
            .into()
    }

    #[test]
    fn it_works_for_default_value() {
        new_test_ext().execute_with(|| {
            // Just a dummy test for the dummy funtion `do_something`
            // calling the `do_something` function with a value 42

            // assert_ok!(TemplateModule::do_something(Origin::signed(1), 42));
            // let anchor = b"anchor date".to_vec();

            // asserting that the stored value is equal to what we stored

            // assert_eq!(TemplateModule::something(), Some(42));
        });
    }
}
