//! Known-answer tests for every value this crate puts on chain.
//!
//! A mirror coin is *found* by its puzzle hash and *addressed* by its namespace hint. Both are pure
//! functions of constants compiled into this crate, so a dependency bump that changed either one
//! would move every mirror coin already on chain to an address nobody looks at — and it would do so
//! silently, because nothing else in the suite compares against a fixed byte string.
//!
//! These vectors were captured on `dig-mirror-coin` 0.3.1 (chia-protocol 0.26 / chia-sdk-driver
//! 0.30) and must reproduce **unmodified** on every later dependency line. A vector that needs
//! editing is not a stale fixture: it is an on-chain output that moved.
//!
//! ## One vector has been re-baselined, exactly once
//!
//! [`mirror_coin_puzzle_hash_is_byte_identical`] carries the 0.36 value, not the 0.26/0.30 one it
//! was captured with. The reason is recorded on that test. Every other vector here still holds its
//! original captured value, and none of them may be edited: a re-baseline without a written cause
//! is indistinguishable from a fixture bent to make a test pass, and this crate exists to produce
//! deterministic hashes.

use chia_protocol::Bytes32;
use dig_mirror_coin::{mirror_coin_puzzle_hash, morph_store_launcher_id, DIG_ASSET_ID};
use num_bigint::BigInt;

/// The $DIG CAT asset id, as published in the ecosystem's canonical constants.
#[test]
fn dig_asset_id_is_the_canonical_mainnet_tail_hash() {
    assert_eq!(
        hex::encode(DIG_ASSET_ID),
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
    );
}

/// The one puzzle hash every mirror coin in existence pays to. If this moves, `discover` and
/// `list` both scan an address that holds nothing.
///
/// ## This value MOVED at the chia 0.36 uplift, and here is why
///
/// Captured as `e991be5feb583c0fc28a95294e4be949be52aa40604a482d6f66a1ef73177cff` on
/// chia-sdk-driver 0.30 (commit `a6deb1b`, green, before any manifest edit). It is now
/// `f2ed90e7…` because **upstream rewrote a shipped puzzle**, not because anything in this crate
/// changed:
///
/// - `chia-sdk-types` replaced `DEFAULT_CAT_MAKER_PUZZLE` with a Rue reimplementation — 283 bytes
///   to 217 bytes, tree hash `0370e9c0…` to `d6693f7a…`.
/// - The mirror coin's inner puzzle curries that cat-maker hash, so the inner hash moved
///   `c650f351…` to `653e776b…`, and the CAT-wrapped outer hash followed it.
/// - Everything else on the path is byte-identical across the range: `P2_PARENT_PUZZLE` and its
///   hash, `CAT_PUZZLE_HASH` (`37bef360…` on both), and `P2ParentCoin::{inner_puzzle_hash,
///   puzzle_hash}`.
///
/// The move was accepted rather than shimmed because it orphans nothing worth keeping: at the time
/// of the uplift the old hash held 4 coin records, **1 unspent, 2 mojos** — dust, not collateral —
/// the new hash held none, and no crate in the ecosystem depended on this one. Holding the old line
/// to preserve that dust would have kept a `chia-sdk-driver` that panics on attacker-authored
/// `CREATE_COIN` memos.
///
/// **Coin identity did not move.** `MIRROR_NAMESPACE` and `morph_store_launcher_id` are unchanged,
/// so the hint every mirror coin is discovered under is the same value it always was.
#[test]
fn mirror_coin_puzzle_hash_is_byte_identical() {
    assert_eq!(
        hex::encode(mirror_coin_puzzle_hash()),
        "f2ed90e749738d6167bc51470572af94695f98dc51d6ee09673aafdd54601e9d"
    );
}

/// The namespace morph, pinned across three axes at once: a non-trivial launcher id, epoch zero
/// (where the offset is a no-op and a wrong tag is most likely to hide), and a later epoch.
#[test]
fn morph_store_launcher_id_is_byte_identical() {
    let store = Bytes32::new([0x11; 32]);

    assert_eq!(
        hex::encode(morph_store_launcher_id(store, &BigInt::from(0))),
        "ba2cc6c2cf223330c94be7bee102de380dbbe8925c5629a155239b3c1c75de54"
    );
    assert_eq!(
        hex::encode(morph_store_launcher_id(store, &BigInt::from(7))),
        "0819e926f8825e14e6e5d1b58f78cf88b8d4c595e0f899562e22baf27e32aa05"
    );

    // A launcher id whose top bit is set: the morph reads the id as a *signed* big-endian integer,
    // so this vector pins the sign handling that an all-0x11 id cannot exercise.
    let high_bit = Bytes32::new([0xF0; 32]);
    assert_eq!(
        hex::encode(morph_store_launcher_id(high_bit, &BigInt::from(1))),
        "0eafd256bcf4f6bc08a25a3df478676d8f6ad6186bc2bf90313233d38b3f9902"
    );
}
