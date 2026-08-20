//! **reclaim** — release a mirror coin's collateral back to its owner.
//!
//! Reclaiming a mirror coin withdraws the advertisement and returns the locked $DIG to the wallet
//! that created it, as an ordinary spendable $DIG CAT coin. The collateral survives the operation;
//! only the claim ends. The name says the intent — the underlying mechanism is simply a spend of the
//! collateral coin.
//!
//! ## There is no path here that destroys $DIG
//!
//! A CAT can be retired through its TAIL, which permanently reduces supply — that is what *melt*
//! means in CAT terms, and it is the opposite outcome to this one. **This crate contains no such
//! path**, and [`reclaim`] must never grow one. The two operations differ in whether the money comes
//! back, which is the largest difference an API can have, and a single name covering both is exactly
//! the shape this ecosystem has already lost money to: on the singleton top layer `(51 () -113)` is
//! itself odd and occupies the one permitted odd-amount `CREATE_COIN`, so mojos melted there are
//! unrecoverable by construction. If a supply-reducing operation is ever wanted, it gets its own
//! name and its own function, reachable only by asking for it.

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_sdk_driver::{Action, Relation, SpendContext, SpendWithConditions, Spends, StandardLayer};
use chia_sdk_types::{conditions::AssertConcurrentSpend, Conditions};
use clvm_utils::ToTreeHash;
use indexmap::indexmap;

use crate::coin::MirrorCoin;
use crate::error::MirrorError;

/// Builds the coin spends that release `mirror`'s collateral back to its owner.
///
/// The full locked amount is recreated at the owner's own puzzle hash — no portion is burned, held
/// back, or paid elsewhere; `fee` is drawn from the separately supplied XCH `fee_coins`, so a
/// reclaim never quietly shaves the collateral to cover itself.
///
/// Fails with [`MirrorError::NotOwner`] when `synthetic_key` does not control the coin. That check
/// compares against the inner puzzle hash in the coin's lineage proof, which comes from the parent's
/// real puzzle reveal, so it cannot be satisfied by a coin merely hinted to the caller.
///
/// Nothing here is signed or broadcast; the caller's signer completes the returned spends.
pub fn reclaim(
    mirror: &MirrorCoin,
    synthetic_key: PublicKey,
    fee_coins: Vec<Coin>,
    fee: u64,
) -> Result<Vec<CoinSpend>, MirrorError> {
    let owner = StandardLayer::new(synthetic_key);
    let owner_puzzle_hash: Bytes32 = owner.tree_hash().into();

    if owner_puzzle_hash != mirror.owner_puzzle_hash() {
        return Err(MirrorError::NotOwner {
            coin_id: mirror.coin().coin_id(),
        });
    }

    let mut ctx = SpendContext::new();

    // The entire collateral is recreated at the owner's puzzle hash. This is the line that makes
    // reclaim a reclaim: the amount out equals the amount that was locked.
    let returned =
        Conditions::new().create_coin(owner_puzzle_hash, mirror.collateral(), Memos::None);
    let owner_spend = owner.spend_with_conditions(&mut ctx, returned)?;
    mirror.inner().spend(&mut ctx, owner_spend, ())?;

    // A fee bundle is built only when there is a fee to pay. Building one from no coins would
    // leave the required concurrency condition with nowhere to be emitted, and the spend would fail
    // to assemble — so a zero-fee reclaim, which is a perfectly ordinary thing to want, must skip it.
    if fee > 0 || !fee_coins.is_empty() {
        let mut fee_spends = Spends::new(owner_puzzle_hash);
        fee_spends
            .conditions
            .required
            .push(AssertConcurrentSpend::new(mirror.coin().coin_id()));
        for fee_coin in fee_coins {
            fee_spends.add(fee_coin);
        }

        let deltas = fee_spends.apply(&mut ctx, &[Action::fee(fee)])?;
        let keys = indexmap! { owner_puzzle_hash => synthetic_key };
        fee_spends.finish_with_keys(&mut ctx, &deltas, Relation::AssertConcurrent, &keys)?;
    }

    Ok(ctx.take())
}
