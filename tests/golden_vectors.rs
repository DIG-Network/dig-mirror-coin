//! Known-answer tests for every value this crate puts on chain.
//!
//! A mirror coin is *found* by its puzzle hash and *addressed* by its namespace hint. Both are pure
//! functions of constants compiled into this crate, so a dependency bump that changed either one
//! would move every mirror coin already on chain to an address nobody looks at — and it would do so
//! silently, because nothing else in the suite compares against a fixed byte string.
//!
//! These vectors must reproduce **unmodified** on every later dependency line. A vector that needs
//! editing is not a stale fixture: it is an on-chain output that moved.
//!
//! ## Where these values come from
//!
//! The four-term vectors were derived from an **independent** reimplementation of the CLVM tree
//! hash — atom as `sha256(0x01 || bytes)`, pair as `sha256(0x02 || left || right)`, the sum encoded
//! as a minimal signed big-endian atom — written from that definition rather than from this crate,
//! and validated by first reproducing the three two-term vectors already committed here before it
//! was trusted for anything new. They were committed **before** `create` and `discover` adopted the
//! four-term hint, so they pin the behaviour rather than record it: a vector captured from the code
//! it is meant to check proves only that the code is self-consistent.
//!
//! ## Vectors that have been re-baselined, and why
//!
//! [`mirror_coin_puzzle_hash_is_byte_identical`] carries the 0.36 value, not the 0.26/0.30 one it
//! was captured with; the reason is recorded on that test. The namespace vectors moved once, at
//! 0.5.0, when the hint widened from `(store, epoch)` to `(store, root, owner, epoch)` — a
//! deliberate wire break, recorded on [`mirror_hint_is_byte_identical`]. No vector here may be
//! edited without a written cause: a re-baseline without one is indistinguishable from a fixture
//! bent to make a test pass, and this crate exists to produce deterministic hashes.

use chia_protocol::Bytes32;
use dig_mirror_coin::{mirror_coin_puzzle_hash, mirror_hint, DIG_ASSET_ID};
use num_bigint::BigInt;

fn store() -> Bytes32 {
    Bytes32::new([0x11; 32])
}

fn root() -> Bytes32 {
    Bytes32::new([0x22; 32])
}

fn owner() -> Bytes32 {
    Bytes32::new([0x33; 32])
}

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
/// **It did not move again at 0.5.0.** The four-term hint changed where a coin is *indexed*, not
/// what puzzle it pays to, and this hash must stay put across that change.
#[test]
fn mirror_coin_puzzle_hash_is_byte_identical() {
    assert_eq!(
        hex::encode(mirror_coin_puzzle_hash()),
        "f2ed90e749738d6167bc51470572af94695f98dc51d6ee09673aafdd54601e9d"
    );
}

/// The namespace morph, pinned across every axis the construction has.
///
/// ## This value moved at 0.5.0, deliberately
///
/// The hint widened from `(store, epoch)` to `(store, root, owner, epoch)` so that a mirror bonds a
/// specific **root** of a store rather than the store as a whole. `MIRROR_NAMESPACE` is untouched
/// and the arithmetic is untouched — the same sum under the same tag, with two more terms in it —
/// but the value a given store lands on is necessarily different, and every coin published under
/// the two-term hint is orphaned by that. The break is the point of the release and is why 0.5.0 is
/// a semver-incompatible minor.
#[test]
fn mirror_hint_is_byte_identical() {
    assert_eq!(
        hex::encode(mirror_hint(store(), root(), owner(), &BigInt::from(0))),
        "e7b9ae059be1675af68ab432bdbb715fae23b0b1bf8f902068849a3c70562709"
    );
    assert_eq!(
        hex::encode(mirror_hint(store(), root(), owner(), &BigInt::from(7))),
        "a580e12bf22602cec1072a02f46aae364595abee89dad395d96ff16712f6efee"
    );

    // A launcher id whose top bit is set: the morph reads each 32-byte term as a *signed*
    // big-endian integer, so this pins the sign handling that an all-0x11 id cannot exercise.
    let high_bit = Bytes32::new([0xF0; 32]);
    assert_eq!(
        hex::encode(mirror_hint(high_bit, root(), owner(), &BigInt::from(1))),
        "75bc65f2c41ee7f0b6a9d6ddc02a168b05f15516c777111c8f3281686dcb0571"
    );

    // All three terms negative at once. A single high-bit term is satisfied by an implementation
    // that sign-extends only the first, so the sum of three negatives is the discriminating case.
    assert_eq!(
        hex::encode(mirror_hint(high_bit, high_bit, high_bit, &BigInt::from(1))),
        "3f8575d7bd8ab2f7416e02a4a71dcb2cefedf0e280f4305e6820c088ec05af6f"
    );

    // A negative epoch. Nothing rejects one, so the encoding of the resulting sum is a shipped
    // behaviour whether or not it is ever used deliberately.
    assert_eq!(
        hex::encode(mirror_hint(store(), root(), owner(), &BigInt::from(-1))),
        "b4a4d0e79cd8ceb10314c469a4b7db319a5b27627f466664fdf694e835d438cd"
    );
}

/// Each term must reach the hash. A vector set that varies only one axis would pass against an
/// implementation that dropped any of the other three, so every term is moved once, alone.
///
/// This is a companion to the pinned vectors above rather than a substitute: the vectors catch a
/// value that *moved*, this catches a term that was never mixed in at all.
#[test]
fn every_term_reaches_the_hash() {
    let epoch = BigInt::from(3);
    let base = mirror_hint(store(), root(), owner(), &epoch);

    let moved_store = mirror_hint(Bytes32::new([0x12; 32]), root(), owner(), &epoch);
    let moved_root = mirror_hint(store(), Bytes32::new([0x23; 32]), owner(), &epoch);
    let moved_owner = mirror_hint(store(), root(), Bytes32::new([0x34; 32]), &epoch);
    let moved_epoch = mirror_hint(store(), root(), owner(), &BigInt::from(4));

    assert_ne!(base, moved_store, "the store launcher id must reach the hash");
    assert_ne!(base, moved_root, "the root must reach the hash");
    assert_ne!(base, moved_owner, "the owner puzzle hash must reach the hash");
    assert_ne!(base, moved_epoch, "the epoch must reach the hash");
}
