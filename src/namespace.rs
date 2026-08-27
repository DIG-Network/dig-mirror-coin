//! The mirror namespace — turning what a mirror advertises into the value its coin is hinted under.
//!
//! A store launcher id is a public identifier, and more than one kind of collateral coin can be
//! anchored to the same store. Each kind therefore lives in its own **namespace**: the advertised
//! values are mixed with a namespace tag before they are ever used as a hint, so a coin advertised
//! for one purpose can never be mistaken for a coin advertised for another.
//!
//! This crate implements the **mirror** namespace and only the mirror namespace. The
//! store-collateral namespace its ancestor also served is deliberately absent — see the crate docs.
//!
//! ## Four terms, because a mirror bonds a ROOT and not just a store
//!
//! A store changes. A publisher who funds the latest root must be able to decline older ones, and a
//! node's mirror coin exists exactly while the `.dig` for one store **at one root** is on its disk.
//! So the hint is keyed on `(store, root, owner, epoch)`, not on `(store, epoch)`.
//!
//! The owner is in there because it is the identity axis this crate already enforces on chain —
//! [`list`](crate::list) is keyed on it and [`reclaim`](crate::reclaim) authorises against it — and
//! because, alone among the four, it is **recoverable from the coin itself**
//! ([`MirrorCoin::owner_puzzle_hash`](crate::MirrorCoin::owner_puzzle_hash)). A verifier holding a
//! coin can therefore recompute the hint without trusting whoever handed the coin over.
//!
//! ## The hint does not bind the tuple, and cannot — read [`mirror_hint`] before relying on it
//!
//! The morph is a sum, so distinct tuples land on the same hint, and the epoch term makes that
//! reachable rather than theoretical. What actually binds a coin to one tuple is the coin's own
//! declaration in its memos, cross-checked against the hint — see
//! [`MirrorCoin::advertises`](crate::MirrorCoin::advertises), which is the only sound test.

use chia_protocol::Bytes32;
use clvm_utils::ToTreeHash;
use num_bigint::BigInt;

/// The namespace tag mixed into every mirror hint.
///
/// This is a wire constant: changing it moves every mirror coin to a different hint and orphans
/// every coin already on chain.
pub const MIRROR_NAMESPACE: &str = "DIG_STORE_MIRROR_COLLATERAL";

/// Morphs a mirror advertisement's four terms into the value its coin is hinted under.
///
/// The store launcher id, the store root and the owner's puzzle hash are each read as big-endian
/// **signed** integers and added together with the epoch; the sum is hashed under
/// [`MIRROR_NAMESPACE`]. Four flat additive terms, which is the two-term construction this crate
/// shipped with, widened — the tag and the arithmetic are unchanged.
///
/// The result is a one-way value: it can be *recomputed* from candidate terms and compared, but it
/// cannot be inverted back into the advertisement it came from. Callers that need to know what a
/// coin advertises must bring candidates and compare, which is what
/// [`discover`](crate::discover) does.
///
/// # This value is an index, never evidence
///
/// Addition is not injective over four terms, so distinct tuples produce an identical hint —
/// `(store, root, owner, epoch)` and `(store + 1, root - 1, owner, epoch)` are the same value here.
/// For the three 32-byte terms that aliasing is unreachable in practice, because none of them is
/// chosen: a launcher id, a merkle root and a puzzle hash are all outputs of a hash, and steering
/// their sum onto a chosen target is a 2^256 search.
///
/// **The epoch is different, and it is why a recomputed hint is never sufficient on its own.** It is
/// an unbounded integer chosen freely by whoever builds the coin, so its author can *solve* for a
/// value that lands their own advertisement on any hint they wish: given their own `(store', root',
/// owner')`, the epoch `e' = store + root + owner + epoch - store' - root' - owner'` puts a coin
/// bonding something else exactly where a verifier looking for `(store, root, owner, epoch)` will
/// find it. That is not a lookup nuisance. The point of per-root coins is that collateral is staked
/// on a *specific* root, and a coin that can answer to any tuple is one stake backing unlimited
/// claims.
///
/// Nothing computable from the hint can close that, because the epoch the coin was really built
/// with is not in the hint — only the sum is. It is closed one level up instead: a mirror coin
/// **declares** its four terms in its memos, and
/// [`MirrorCoin::advertises`](crate::MirrorCoin::advertises) compares that declaration term by term
/// against what the caller asked about *as well as* recomputing this value. The two checks are not
/// redundant. The declaration says which tuple the collateral is staked on; this hint says the coin
/// was really published in that tuple's bucket rather than squatting in another.
pub fn mirror_hint(
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    owner_puzzle_hash: Bytes32,
    epoch: &BigInt,
) -> Bytes32 {
    let sum = BigInt::from_signed_bytes_be(store_launcher_id.as_ref())
        + BigInt::from_signed_bytes_be(root_hash.as_ref())
        + BigInt::from_signed_bytes_be(owner_puzzle_hash.as_ref())
        + epoch;

    (sum, MIRROR_NAMESPACE).tree_hash().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tag the *other* collateral namespace uses. Present only so the separation test below has
    /// something to compare against; this crate never produces coins in that namespace.
    const STORE_COLLATERAL_NAMESPACE: &str = "DIG_STORE_COLLATERAL";

    fn store_id() -> Bytes32 {
        Bytes32::new([0x11; 32])
    }

    fn root() -> Bytes32 {
        Bytes32::new([0x22; 32])
    }

    fn owner() -> Bytes32 {
        Bytes32::new([0x33; 32])
    }

    #[test]
    fn mirror_namespace_is_disjoint_from_the_store_collateral_namespace() {
        // The store-collateral morph hashes the launcher id itself under a different tag. Even at
        // epoch zero — where the offset leaves the launcher id untouched — the two must not collide,
        // or a store-collateral coin would be discoverable as a mirror.
        let store_collateral: Bytes32 = (store_id(), STORE_COLLATERAL_NAMESPACE).tree_hash().into();
        let mirror = mirror_hint(store_id(), root(), owner(), &BigInt::from(0));

        assert_ne!(mirror, store_collateral);
    }

    #[test]
    fn each_epoch_gets_its_own_hint() {
        let epoch_0 = mirror_hint(store_id(), root(), owner(), &BigInt::from(0));
        let epoch_1 = mirror_hint(store_id(), root(), owner(), &BigInt::from(1));

        assert_ne!(epoch_0, epoch_1);
    }

    #[test]
    fn distinct_stores_get_distinct_hints_within_one_epoch() {
        let epoch = BigInt::from(7);
        let a = mirror_hint(Bytes32::new([0x11; 32]), root(), owner(), &epoch);
        let b = mirror_hint(Bytes32::new([0x12; 32]), root(), owner(), &epoch);

        assert_ne!(a, b);
    }

    /// The whole reason this change exists: two roots of the same store are two different
    /// advertisements, so a publisher can fund one and decline the other.
    #[test]
    fn distinct_roots_of_the_same_store_get_distinct_hints() {
        let epoch = BigInt::from(7);
        let a = mirror_hint(store_id(), Bytes32::new([0x22; 32]), owner(), &epoch);
        let b = mirror_hint(store_id(), Bytes32::new([0x23; 32]), owner(), &epoch);

        assert_ne!(a, b);
    }

    /// The owner is an identity axis, so two owners advertising the identical store at the identical
    /// root must not share a bucket — otherwise one owner's reclaim would walk the other's coin.
    #[test]
    fn distinct_owners_of_the_same_store_and_root_get_distinct_hints() {
        let epoch = BigInt::from(7);
        let a = mirror_hint(store_id(), root(), Bytes32::new([0x33; 32]), &epoch);
        let b = mirror_hint(store_id(), root(), Bytes32::new([0x34; 32]), &epoch);

        assert_ne!(a, b);
    }

    /// The offset is arithmetic across ALL FOUR terms, so a store one unit "ahead" lands on the same
    /// sum as a root one unit "behind". This documents a real property of the construction rather
    /// than asserting a wished-for one, and it is why the hint is only ever an index.
    ///
    /// It was true of the two-term version and it is true of this one; widening the morph widened
    /// the aliasing with it rather than removing it.
    #[test]
    fn the_offset_is_arithmetic_so_hints_alias_across_all_four_terms() {
        let mut ahead = [0u8; 32];
        ahead[31] = 5;
        let mut behind = [0u8; 32];
        behind[31] = 4;

        // store+1 / root-1 — a different advertisement entirely, on an identical hint.
        let a = mirror_hint(
            Bytes32::new(ahead),
            Bytes32::new(behind),
            owner(),
            &BigInt::from(0),
        );
        let b = mirror_hint(
            Bytes32::new(behind),
            Bytes32::new(ahead),
            owner(),
            &BigInt::from(0),
        );

        assert_eq!(a, b);
    }

    /// The epoch is the term that makes the aliasing above *reachable* instead of academic: it is
    /// unbounded and freely chosen, so its author can solve for the value that lands a coin bonding
    /// their own store and root onto somebody else's hint exactly.
    ///
    /// This is the arithmetic behind the warning on [`mirror_hint`], asserted rather than merely
    /// described — it is what [`MirrorCoin::advertises`] has to defeat, and it is defeated by the
    /// declared-tuple comparison rather than by anything computed here.
    #[test]
    fn a_freely_chosen_epoch_solves_onto_any_other_advertisements_hint() {
        let victim_epoch = BigInt::from(42);
        let victim = mirror_hint(store_id(), root(), owner(), &victim_epoch);

        // The attacker's own advertisement: their store, their root, their key. All they choose is
        // the epoch they publish under.
        let their_store = Bytes32::new([0x77; 32]);
        let their_root = Bytes32::new([0x88; 32]);
        let their_owner = Bytes32::new([0x99; 32]);

        let solved_epoch = BigInt::from_signed_bytes_be(store_id().as_ref())
            + BigInt::from_signed_bytes_be(root().as_ref())
            + BigInt::from_signed_bytes_be(owner().as_ref())
            + &victim_epoch
            - BigInt::from_signed_bytes_be(their_store.as_ref())
            - BigInt::from_signed_bytes_be(their_root.as_ref())
            - BigInt::from_signed_bytes_be(their_owner.as_ref());

        assert_eq!(
            mirror_hint(their_store, their_root, their_owner, &solved_epoch),
            victim,
            "the epoch absorbs any difference between two advertisements, so a recomputed hint \
             can never be the thing that binds a coin to one tuple"
        );
    }
}
