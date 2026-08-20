//! **create** — lock $DIG and publish a mirror for a store.
//!
//! Creation moves $DIG from the owner's ordinary CAT coins into the collateral puzzle, carrying the
//! store's namespace value and the advertised URLs as memos. The resulting coin is spendable again
//! only by [`reclaim`](crate::reclaim), and only by the wallet that created it.

use chia_bls::PublicKey;
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_sdk_driver::{Action, Cat, Id, Relation, SpendContext, Spends, StandardLayer};
use clvm_utils::ToTreeHash;
use indexmap::indexmap;
use num_bigint::BigInt;

use crate::asset::{mirror_coin_inner_puzzle_hash, DIG_ASSET_ID};
use crate::error::MirrorError;
use crate::namespace::morph_store_launcher_id;

/// What a mirror advertises, and what it stakes on the claim.
///
/// Grouped into one type rather than spread across a long parameter list, because these four values
/// are the advertisement — they belong together, and a caller who transposes two positional
/// arguments in a money-moving call should not be able to.
#[derive(Debug, Clone)]
pub struct MirrorAdvertisement {
    /// The store being advertised.
    pub store_launcher_id: Bytes32,
    /// The epoch the advertisement is published for.
    pub epoch: BigInt,
    /// Where the store can be fetched from. MUST be non-empty.
    pub urls: Vec<String>,
    /// The $DIG locked behind the claim, in mojos. MUST be non-zero.
    pub collateral: u64,
}

/// Builds the coin spends that lock $DIG as a mirror for the advertised store.
///
/// The caller supplies already-authenticated $DIG CAT coins to draw the collateral from, plus XCH
/// coins to pay `fee`. Change is returned to the owner's own puzzle hash. Nothing here is signed and
/// nothing is broadcast: the return value is a set of coin spends for the caller's signer to
/// complete, so this crate never touches a key.
///
/// The advertised URLs MUST be non-empty. An advertisement with nowhere to fetch from is not a
/// mirror, and the published URLs are also what distinguishes a mirror coin from a sibling
/// collateral coin sharing the same puzzle — see
/// [`MirrorCoin::from_creating_spend`](crate::MirrorCoin::from_creating_spend).
///
/// The collateral MUST be non-zero. The whole premise of a mirror coin is that a claim costs
/// something, and a claim staked on nothing is free — so zero is refused here rather than described
/// as staked. The crate deliberately sets no higher floor: what amount is *enough* is an economic
/// question for the network, and baking a number in would freeze it into a wire constant.
pub fn create(
    advertisement: MirrorAdvertisement,
    dig_coins: Vec<Cat>,
    synthetic_key: PublicKey,
    fee_coins: Vec<Coin>,
    fee: u64,
) -> Result<Vec<CoinSpend>, MirrorError> {
    let MirrorAdvertisement {
        store_launcher_id,
        epoch,
        urls,
        collateral,
    } = advertisement;

    if urls.is_empty() {
        return Err(MirrorError::Malformed(
            "a mirror must advertise at least one URL".to_string(),
        ));
    }

    // A zero-collateral mirror is a claim that cost nothing, which is the one thing this coin exists
    // to prevent. How much is enough is a policy the network sets, not this crate; that nothing is
    // never enough is structural, so it is enforced here.
    if collateral == 0 {
        return Err(MirrorError::Malformed(
            "a mirror must lock a non-zero amount of $DIG as collateral".to_string(),
        ));
    }

    let mut ctx = SpendContext::new();

    let namespace_hint = morph_store_launcher_id(store_launcher_id, &epoch);
    let mut memo_entries = Vec::with_capacity(urls.len() + 1);
    memo_entries.push(Bytes::new(namespace_hint.to_vec()));
    for url in &urls {
        memo_entries.push(Bytes::new(url.as_bytes().to_vec()));
    }

    let memos = Memos::Some(ctx.alloc(&memo_entries)?);

    let actions = [
        Action::fee(fee),
        Action::send(
            Id::Existing(DIG_ASSET_ID),
            mirror_coin_inner_puzzle_hash().into(),
            collateral,
            memos,
        ),
    ];

    let owner = StandardLayer::new(synthetic_key);
    let owner_puzzle_hash: Bytes32 = owner.tree_hash().into();

    let mut spends = Spends::new(owner_puzzle_hash);
    for dig_coin in dig_coins {
        spends.add(dig_coin);
    }
    for fee_coin in fee_coins {
        spends.add(fee_coin);
    }

    let deltas = spends.apply(&mut ctx, &actions)?;
    let keys = indexmap! { owner_puzzle_hash => synthetic_key };
    spends.finish_with_keys(&mut ctx, &deltas, Relation::AssertConcurrent, &keys)?;

    Ok(ctx.take())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::SecretKey;

    fn any_key() -> PublicKey {
        SecretKey::from_seed(&[7u8; 64]).public_key()
    }

    #[test]
    fn creation_without_urls_is_refused() {
        let error = create(
            MirrorAdvertisement {
                store_launcher_id: Bytes32::new([1u8; 32]),
                epoch: BigInt::from(0),
                urls: vec![],
                collateral: 1_000,
            },
            vec![],
            any_key(),
            vec![],
            0,
        )
        .expect_err("a mirror with no URLs must be refused");

        assert!(matches!(error, MirrorError::Malformed(_)));
    }

    /// The stake is what makes a mirror claim cost something, so a claim staked on nothing is not a
    /// mirror. The URLs are present here so the refusal can only be about the collateral.
    #[test]
    fn creation_without_collateral_is_refused() {
        let error = create(
            MirrorAdvertisement {
                store_launcher_id: Bytes32::new([1u8; 32]),
                epoch: BigInt::from(0),
                urls: vec!["https://mirror.example".to_string()],
                collateral: 0,
            },
            vec![],
            any_key(),
            vec![],
            0,
        )
        .expect_err("a mirror staked on nothing must be refused");

        assert!(matches!(error, MirrorError::Malformed(_)));
    }
}
