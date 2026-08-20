//! $DIG, and the puzzle hash every mirror coin pays to.
//!
//! $DIG is a CAT, so a mirror coin never sits at its owner's puzzle hash. It sits at the **outer**
//! hash that curries the asset id around the collateral puzzle, and is merely hinted to something a
//! wallet can search for. The outer hash is produced by the canonical CAT construction
//! ([`CatArgs::curry_tree_hash`]) reached through [`P2ParentCoin::puzzle_hash`] — never assembled by
//! hand, because a hand-rolled curry that is subtly wrong produces a puzzle hash nobody can spend.

use chia_protocol::Bytes32;
use chia_sdk_driver::P2ParentCoin;
use clvm_utils::TreeHash;
use hex_literal::hex;

/// The $DIG CAT asset id (TAIL hash) on Chia mainnet.
///
/// A wire constant. Every mirror coin's outer puzzle hash curries exactly this value, and a coin
/// currying anything else is not $DIG collateral however it is hinted.
pub const DIG_ASSET_ID: Bytes32 = Bytes32::new(hex!(
    "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
));

/// The outer puzzle hash every $DIG mirror coin pays to.
///
/// This value is the same for every mirror coin and every owner: the collateral puzzle takes its
/// authority from the coin's parent rather than from a curried key, so ownership lives in the
/// lineage proof, not in the puzzle hash. Two consequences follow, and both shape this crate's API:
/// a scan of this puzzle hash finds *everyone's* collateral coins, and telling them apart requires
/// reading each coin's creating spend.
pub fn mirror_coin_puzzle_hash() -> Bytes32 {
    P2ParentCoin::puzzle_hash(Some(DIG_ASSET_ID)).into()
}

/// The inner (pre-CAT-wrapping) collateral puzzle hash mirror coins are created against.
pub(crate) fn mirror_coin_inner_puzzle_hash() -> TreeHash {
    P2ParentCoin::inner_puzzle_hash(Some(DIG_ASSET_ID))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_puzzle_types::cat::CatArgs;

    #[test]
    fn outer_hash_is_the_canonical_cat_curry_of_dig_around_the_inner_puzzle() {
        // The property under test is that the outer hash is a CAT wrapping of $DIG specifically. The
        // discriminating comparison is therefore against the canonical construction with a
        // *different* asset id: if the outer hash ignored the asset id, both would agree.
        let canonical: Bytes32 =
            CatArgs::curry_tree_hash(DIG_ASSET_ID, mirror_coin_inner_puzzle_hash()).into();
        let other_asset: Bytes32 =
            CatArgs::curry_tree_hash(Bytes32::new([0xAB; 32]), mirror_coin_inner_puzzle_hash())
                .into();

        assert_eq!(mirror_coin_puzzle_hash(), canonical);
        assert_ne!(mirror_coin_puzzle_hash(), other_asset);
    }

    #[test]
    fn the_outer_hash_is_not_the_inner_hash() {
        // A crate that forgot to wrap the inner puzzle in the CAT layer would produce coins at a
        // puzzle hash that holds no CAT at all, and the mistake is invisible without this check.
        let inner: Bytes32 = mirror_coin_inner_puzzle_hash().into();
        assert_ne!(mirror_coin_puzzle_hash(), inner);
    }
}
