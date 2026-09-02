//! **create** — lock $DIG and publish a mirror for one root of a store.
//!
//! Creation moves $DIG from the owner's ordinary CAT coins into the collateral puzzle, carrying the
//! namespace value, the advertisement the coin bonds, and the advertised URLs as memos. The
//! resulting coin is spendable again only by [`reclaim`](crate::reclaim), and only by the wallet
//! that created it.

use chia_bls::PublicKey;
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_sdk_driver::{Action, Cat, Id, Relation, SpendContext, Spends, StandardLayer};
use clvm_utils::ToTreeHash;
use indexmap::indexmap;
use num_bigint::BigInt;

use crate::asset::{mirror_coin_inner_puzzle_hash, DIG_ASSET_ID};
use crate::declaration::{PeerDeclaration, PEER_DECLARATION_PREFIX};
use crate::error::MirrorError;
use crate::namespace::mirror_hint;

/// What a mirror advertises, and what it stakes on the claim.
///
/// Grouped into one type rather than spread across a long parameter list, because these values are
/// the advertisement — they belong together, and a caller who transposes two positional arguments in
/// a money-moving call should not be able to. With `store_launcher_id` and `root_hash` sitting
/// side by side and sharing a type, that stops being a style preference.
#[derive(Debug, Clone)]
pub struct MirrorAdvertisement {
    /// The store being advertised.
    pub store_launcher_id: Bytes32,
    /// The **root of that store** being advertised.
    ///
    /// A mirror bonds one root, not a store as a whole. That is what lets a publisher fund the
    /// latest root and decline the ones before it, and it is what makes a node's mirror coin
    /// correspond to a `.dig` file actually on its disk rather than to a store it once served.
    pub root_hash: Bytes32,
    /// The epoch the advertisement is published for.
    pub epoch: BigInt,
    /// Where the store can be fetched from. MUST be non-empty.
    pub urls: Vec<String>,
    /// The DIG peer this collateral stands behind, if any.
    ///
    /// An `Option` rather than a list, deliberately: the collateral is what makes a claim cost
    /// something, and one coin standing behind several peers would make each of those claims cost a
    /// fraction as much while every one still read as fully bonded. `Option` cannot represent two,
    /// so that dilution is not expressible here.
    ///
    /// This field is the ONLY way to write a declaration through this crate, and [`create`] enforces
    /// that by refusing a `urls` entry carrying the declaration prefix — the two write into the same
    /// memo tail, so without that refusal the type would guarantee nothing. An owner who wants two
    /// peers bonded creates two coins and locks the collateral twice.
    ///
    /// `None` writes no declaration, which is exactly what every coin created before this format
    /// existed carries — such a coin bonds content but names no claimant.
    pub declared_peer: Option<PeerDeclaration>,
    /// The $DIG locked behind the claim, in **DIG CAT base units** (`1 DIG = 1_000`, never
    /// mojos — see [`MirrorCoin::collateral`](crate::MirrorCoin::collateral)). MUST be non-zero.
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
        declared_peer,
        store_launcher_id,
        root_hash,
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

    // The declaration is a TYPED field, and this is what makes that mean something. `urls` entries
    // are written into the same memo tail verbatim, so without this check a caller could smuggle a
    // declaration past `declared_peer` by spelling one as a URL -- and the type-level guarantee that
    // one coin declares at most one peer would be a comment rather than a property. Refused rather
    // than filtered: a caller that passed one meant something by it, and silently dropping the entry
    // would publish an advertisement it did not ask for.
    if let Some(smuggled) = urls
        .iter()
        .find(|url| url.starts_with(PEER_DECLARATION_PREFIX))
    {
        return Err(MirrorError::Malformed(format!(
            "an advertised URL must not carry the peer-declaration prefix; use `declared_peer` instead (got {smuggled:?})"
        )));
    }

    let mut ctx = SpendContext::new();

    // The owner is one of the four terms the hint is morphed from, so it has to be known before the
    // memos are built rather than at signing time.
    let owner = StandardLayer::new(synthetic_key);
    let owner_puzzle_hash: Bytes32 = owner.tree_hash().into();

    // `[hint, store, root, epoch, url…, dig-peer:…]` — the layout `parse_memos` reads back. The coin DECLARES
    // what it bonds, because a hint cannot: see `MirrorCoin::advertises`.
    let namespace_hint = mirror_hint(store_launcher_id, root_hash, owner_puzzle_hash, &epoch);
    let mut memo_entries = Vec::with_capacity(urls.len() + 4);
    memo_entries.push(Bytes::new(namespace_hint.to_vec()));
    memo_entries.push(Bytes::new(store_launcher_id.to_vec()));
    memo_entries.push(Bytes::new(root_hash.to_vec()));
    memo_entries.push(Bytes::new(epoch.to_signed_bytes_be()));
    for url in &urls {
        memo_entries.push(Bytes::new(url.as_bytes().to_vec()));
    }
    // Appended AFTER the advertised URLs rather than before them. `MirrorCoin::urls` hands the whole
    // tail back, so a declaration written first would land at `urls()[0]` and displace the first
    // real URL for every consumer that reads the list positionally.
    if let Some(declaration) = &declared_peer {
        memo_entries.push(Bytes::new(declaration.to_term().into_bytes()));
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
                declared_peer: None,
                store_launcher_id: Bytes32::new([1u8; 32]),
                root_hash: Bytes32::new([2u8; 32]),
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
                declared_peer: None,
                store_launcher_id: Bytes32::new([1u8; 32]),
                root_hash: Bytes32::new([2u8; 32]),
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
