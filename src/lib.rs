#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use frame_support::{decl_event, decl_module, decl_storage, dispatch::DispatchResult};
use frame_support::{ensure, StorageMap};
use sp_runtime::traits::Hash;
use system::ensure_signed;

// Max number of authorized accounts to operate on leaf-based revocation
// There's got to be a
pub const MAX_AUTHORIZED_ACCOUNTS: usize = 10usize;

/*
NOTE: decided to try and push that to the requester s.t. suspension end needs to be specified
      in (chain) blocks. Requester should track telemmetry/instrumentation.

Block-based time units to check whether a suspended leaf is reinstated.
pub const MILLISECS_PER_BLOCK: u32 = 6_000u32; //Kusama-3 avg blocktime ~ 6 secs.
pub const BLOCK_MINUTES: u32 = MILLISECS_PER_BLOCK * 10; //60k blocks @ 6s/block = 1 Minute
pub const BLOCK_HOUR: u32 = BLOCK_MINUTES * 60;
pub const BLOCK_DAY: u32 = BLOCK_HOUR * 24;
*/

/// The pallet's configuration trait.
pub trait Trait: system::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

// This pallet's storage items.
decl_storage! {
    trait Store for Module<T: Trait> as TemplateModule {

        // Simple anchor storage for:
        // {"anchor value aaka digest": (from acct, block block height, revokable)}
        // Note:
        //         if revokable, the revocation can only come from the origin account
        //         this is different than "leaf revocation", see below !!!
        Anchors: map Vec<u8> => (T::AccountId, T::BlockNumber, bool);

        // Allocating leaf revocation rights for a given anchor to accounts other than
        // origin at creation.
        // NOTE: we should change that to a bloom filter where
        // hash(accountid, block_height, anchor_value) should do !!
        AuthorizedRevokers: map T::Hash => Vec<T::AccountId>;

        // Reference, aka storage, to revoked leafs, i.e., the reference data (hash) that can
        // be looked up in lieu of a centralized revocation reference a la blockcerts.
        // Instead of the central lookup list, the user needs to build the RPC call and then
        // format accordingly.
        //
        // {"leaf digest": (from acct, current block height, anchor_digest, Optional suspension end in block height)}
        // NOTE: we ought to streamline this into:
        // hashed_leaf_key = Hash(leaf digest + anchor digest + anchor block height) s.t.
        // {"key", (?)}
        // if not a suspension, we can put it in a bloomfilter  as well and be done with it
        RevokedLeafs: map Vec<u8> => (T::AccountId, T::BlockNumber, Vec<u8>, Option<T::BlockNumber>);
    }
}

// The pallet's dispatchable functions.
decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        fn deposit_event() = default;

        pub fn create_anchor(
            origin,
            anchor: Vec<u8>,
            revocable: bool,
            auth_addrs: Option<Vec<T::AccountId>>
        ) -> DispatchResult {
            // formalize that !!
            ensure!(!anchor.len() > 512, "Max bytes for digest values is 512");
            let sender = ensure_signed(origin)?;

            // NOTE: we should make the key Hash(data,block height) for a more accurate collision exclusion !!
            ensure!(!Anchors::<T>::exists(&anchor), "This anchor digest has already been claimed.");

            // we don't want some endless account list here and need the RPC to enforce that first and foremost
            let addrs = match auth_addrs {
                Some(a) => a,
                _ => Vec::<T::AccountId>::new(),
            };
            ensure!(
                addrs.len() <= MAX_AUTHORIZED_ACCOUNTS,
                "Exceeding allowable number of addresses"
            );

            let current_block = <system::Module<T>>::block_number();

            // if we have authorized AccountIds, add them to storage
            if addrs.len() > 0 {
                let key_hash = (anchor.clone(), current_block.clone())
                    .using_encoded(<T as system::Trait>::Hashing::hash);
                /*
                let key_hash = blake2::new()
                                .chain(&anchor)
                                .chain(&current_block)
                                .finalize()
                                .result();
                */
                AuthorizedRevokers::<T>::insert(&key_hash, addrs);
                // need an event notification for that?
            }

            // anchor reference to storage
            Anchors::<T>::insert(&anchor, (sender.clone(), current_block, revocable));
            Self::deposit_event(RawEvent::AnchorCreated(sender, anchor));

            Ok(())
        }

        // revoke the anchor iff its revokable and the request account matches
        // NOTE: if we go for compiste hash key (see create_anchor), we need to add
        // block_height.
        pub fn revoke_anchor(origin, anchor: Vec<u8>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            ensure!(Anchors::<T>::exists(&anchor), "This anchor does not exist.");

            let (acct_id, _, revokable) = Anchors::<T>::get(&anchor);
            ensure!(revokable, "Anchor is not revocable");
            ensure!(sender==acct_id, "Requester is not the owner of the anchor.");

            Self::deposit_event(RawEvent::AnchorRevoked(sender, anchor));

            Ok(())
        }

        // this is (almost) independent of the anchor since we don't have/keep leaf data on-chain
        // and merkle proof submission don't matter.
        pub fn revoke_leaf(
            origin,
            anchor_value: Vec<u8>,
            leaf_value: Vec<u8>,
            expiration: Option<T::BlockNumber>
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let current_block = <system::Module<T>>::block_number();

            if expiration.is_some() {
                let ex = expiration.unwrap();
                ensure!(ex > current_block, "Supension must end in the future.");
                RevokedLeafs::<T>::insert(
                    leaf_value.clone(),
                    (sender.clone(),current_block.clone(), anchor_value.clone(), Some(ex.clone()))
                );
                Self::deposit_event(RawEvent::LeafSuspended(sender, anchor_value, leaf_value, ex));
            }
            else {
                RevokedLeafs::<T>::insert(
                    leaf_value.clone(),
                    (
                        sender.clone(),
                        current_block.clone(),
                        anchor_value.clone(),
                        None::<T::BlockNumber>
                    )
                );
                Self::deposit_event(RawEvent::LeafRevoked(sender, anchor_value, leaf_value));
            }

            Ok(())
        }

    }
}

impl<T: Trait> Module<T> {
    // this is for revoking the anchor not any one of the leafs and directly tied to
    // the origin account at create time. Note: for (on-chain) merkle tree aggregation
    // we don't allow "root" revocation.
    pub fn is_revokable(anchor: Vec<u8>) -> Result<bool, &'static str> {
        ensure!(Anchors::<T>::exists(&anchor), "This anchor does not exist.");
        let (_, _, revokable) = Anchors::<T>::get(&anchor);
        Ok(revokable)
    }

    pub fn is_leaf_revoked(_anchor_value: Vec<u8>, _leaf_value: Vec<u8>) -> bool {
        unimplemented!()
    }
}

decl_event!(
    pub enum Event<T>
    where
        <T as system::Trait>::AccountId,
        <T as system::Trait>::BlockNumber,
    {
        AnchorCreated(AccountId, Vec<u8>),
        AnchorRevoked(AccountId, Vec<u8>),

        LeafRevoked(AccountId, Vec<u8>, Vec<u8>),
        LeafSuspended(AccountId, Vec<u8>, Vec<u8>, BlockNumber),
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
