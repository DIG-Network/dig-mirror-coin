//! The mirror namespace — turning a store launcher id into the value a mirror coin is hinted under.
//!
//! A store launcher id is a public identifier, and more than one kind of collateral coin can be
//! anchored to the same store. Each kind therefore lives in its own **namespace**: the launcher id
//! is mixed with a namespace tag before it is ever used as a hint, so a coin advertised for one
//! purpose can never be mistaken for a coin advertised for another.
//!
//! This crate implements the **mirror** namespace and only the mirror namespace. The
//! store-collateral namespace its ancestor also served is deliberately absent — see the crate docs.

use chia_protocol::Bytes32;
use clvm_utils::ToTreeHash;
use num_bigint::BigInt;

/// The namespace tag mixed into every mirror hint.
///
/// This is a wire constant: changing it moves every mirror coin to a different hint and orphans
/// every coin already on chain.
pub const MIRROR_NAMESPACE: &str = "DIG_STORE_MIRROR_COLLATERAL";

/// Morphs a DIG store launcher id into the mirror namespace for a given epoch.
///
/// The epoch is added to the launcher id (read as a big-endian signed integer) before hashing, so
/// each epoch produces a distinct hint for the same store. That is what lets a mirror advertise for
/// one epoch without its coin being discovered as current forever.
///
/// The result is a one-way value: it can be *recomputed* from a candidate store id and checked, but
/// it cannot be inverted back into the store it came from. Callers that need to know which store a
/// coin advertises must therefore bring a candidate and compare, which is exactly what
/// [`discover`](crate::discover) does.
pub fn morph_store_launcher_id(store_launcher_id: Bytes32, epoch: &BigInt) -> Bytes32 {
    let launcher_id_int = BigInt::from_signed_bytes_be(store_launcher_id.as_ref());
    let offset_launcher_id = launcher_id_int + epoch;

    (offset_launcher_id, MIRROR_NAMESPACE).tree_hash().into()
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

    #[test]
    fn mirror_namespace_is_disjoint_from_the_store_collateral_namespace() {
        // The store-collateral morph hashes the launcher id itself under a different tag. Even at
        // epoch zero — where the offset leaves the launcher id untouched — the two must not collide,
        // or a store-collateral coin would be discoverable as a mirror.
        let store_collateral: Bytes32 = (store_id(), STORE_COLLATERAL_NAMESPACE).tree_hash().into();
        let mirror = morph_store_launcher_id(store_id(), &BigInt::from(0));

        assert_ne!(mirror, store_collateral);
    }

    #[test]
    fn each_epoch_gets_its_own_hint() {
        let epoch_0 = morph_store_launcher_id(store_id(), &BigInt::from(0));
        let epoch_1 = morph_store_launcher_id(store_id(), &BigInt::from(1));

        assert_ne!(epoch_0, epoch_1);
    }

    #[test]
    fn distinct_stores_get_distinct_hints_within_one_epoch() {
        let epoch = BigInt::from(7);
        let a = morph_store_launcher_id(Bytes32::new([0x11; 32]), &epoch);
        let b = morph_store_launcher_id(Bytes32::new([0x12; 32]), &epoch);

        assert_ne!(a, b);
    }

    /// The offset is arithmetic on the launcher id, so a store one unit "ahead" at an earlier epoch
    /// lands on the same sum as a store one unit "behind" at a later epoch. This documents a real
    /// property of the construction rather than asserting a wished-for one: the hint alone does not
    /// identify a store, which is why discovery re-checks the store id it was asked about.
    #[test]
    fn the_offset_is_arithmetic_so_hints_alias_across_store_and_epoch() {
        let mut ahead = [0u8; 32];
        ahead[31] = 5;
        let mut behind = [0u8; 32];
        behind[31] = 4;

        let a = morph_store_launcher_id(Bytes32::new(ahead), &BigInt::from(0));
        let b = morph_store_launcher_id(Bytes32::new(behind), &BigInt::from(1));

        assert_eq!(a, b);
    }
}
