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
#[test]
fn mirror_coin_puzzle_hash_is_byte_identical() {
    assert_eq!(
        hex::encode(mirror_coin_puzzle_hash()),
        "e991be5feb583c0fc28a95294e4be949be52aa40604a482d6f66a1ef73177cff"
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
