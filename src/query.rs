//! **list** and **discover** — the two chain reads, which are not the same read.
//!
//! | verb | question | keyed by | an empty answer means |
//! |---|---|---|---|
//! | [`list`] | which mirror coins are mine? | owner puzzle hash | you have locked no collateral |
//! | [`discover`] | who mirrors this store? | store launcher id | nobody advertises it |
//!
//! They resist collapsing into one function because their **trust** differs, not just their key.
//! `list` is about the caller's own money, so it authenticates every coin it returns and refuses to
//! answer at all if any candidate cannot be authenticated — under-reporting your own collateral is
//! worse than reporting nothing. `discover` reads an index anyone can write into, so a candidate it
//! cannot authenticate is *dropped* rather than fatal; refusing the whole query would let one dust
//! coin hide every honest mirror.
//!
//! Both preserve the same distinction at the boundary: an empty result is an answer, an `Err` is the
//! absence of one. Neither ever degrades an unreachable source into "nothing found".

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, CoinRecord};
use num_bigint::BigInt;

use crate::asset::mirror_coin_puzzle_hash;
use crate::coin::MirrorCoin;
use crate::error::MirrorError;
use crate::namespace::morph_store_launcher_id;

/// The one chain read mirror discovery needs that the canonical [`ChainSource`] does not expose.
///
/// Every mirror coin in existence shares a single puzzle hash, so a store's mirrors are separated
/// only by the hint they were published under, and finding them needs a hint index. That index is
/// **unauthenticated by nature** — anyone may hint any coin to any value — which is why the results
/// are treated as candidates and re-derived from their creating spends before being believed.
///
/// Implemented as an extension of `ChainSource` rather than a fresh trait so that the error type,
/// the `Ok(None)`-versus-`Err` contract, and the parent-walk primitive are the ecosystem's canonical
/// ones rather than a second copy that could drift.
pub trait MirrorChainSource: ChainSource {
    /// Reads the unspent coins hinted to `hint`.
    ///
    /// An empty `Vec` means the source reliably found none; `Err(_)` means it could not answer.
    fn unspent_coins_by_hint(&self, hint: Bytes32) -> Result<Vec<CoinRecord>, Self::Error>;
}

/// Everyone who advertises a store for one epoch, as answered by one chain source.
///
/// Empty [`claims`](Self::claims) is a real answer: the source was consulted and found nobody. A
/// caller that could not reach a source gets `Err` from [`discover`] instead and must not treat the
/// two alike.
///
/// The type is named for what it holds. A claim is an assertion backed by locked $DIG — it says
/// somebody staked collateral on serving this store, and nothing whatsoever about whether they do.
/// Availability is established by fetching from a mirror, never by reading this struct.
#[derive(Debug, Clone)]
pub struct MirrorSet {
    store_launcher_id: Bytes32,
    epoch: BigInt,
    namespace_hint: Bytes32,
    claims: Vec<MirrorCoin>,
    rejected: usize,
}

impl MirrorSet {
    /// The store these claims were sought for.
    pub fn store_launcher_id(&self) -> Bytes32 {
        self.store_launcher_id
    }

    /// The epoch these claims were sought for.
    pub fn epoch(&self) -> &BigInt {
        &self.epoch
    }

    /// The namespace value the store and epoch morph to — the hint that was searched.
    pub fn namespace_hint(&self) -> Bytes32 {
        self.namespace_hint
    }

    /// The authenticated claims, each backed by locked $DIG.
    ///
    /// Not a list of working mirrors. See the type's own documentation.
    pub fn claims(&self) -> &[MirrorCoin] {
        &self.claims
    }

    /// Whether the source found nobody advertising this store for this epoch.
    ///
    /// True only for a completed read. A read that failed is an `Err` and never reaches this method.
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// How many hinted candidates were dropped because they could not be authenticated as mirror
    /// coins.
    ///
    /// Non-zero is normal — the hint index is open to anyone — but a large number next to an empty
    /// claim set is worth surfacing, because it is what a deliberate flood looks like.
    pub fn rejected_candidates(&self) -> usize {
        self.rejected
    }
}

/// Answers *which mirror coins are mine*, keyed by the owner's puzzle hash.
///
/// Scans the shared mirror puzzle hash and keeps the coins whose lineage proof names
/// `owner_puzzle_hash` as the controlling wallet. Ownership therefore comes from executed on-chain
/// code, not from a hint, and no wallet can be made to see somebody else's coin as its own.
///
/// An empty `Vec` means the owner has no locked collateral. An `Err` means the answer could not be
/// established — including [`MirrorError::Unauthenticated`] when a candidate's creating spend is
/// missing, which is deliberately fatal here: silently omitting a coin from an owner's own inventory
/// would understate their money.
pub fn list<S: ChainSource>(
    source: &S,
    owner_puzzle_hash: Bytes32,
) -> Result<Vec<MirrorCoin>, MirrorError> {
    let candidates = source
        .coin_records_by_puzzle_hash(mirror_coin_puzzle_hash(), false)
        .map_err(unavailable)?;

    let mut owned = Vec::new();
    for candidate in candidates {
        let Some(mirror) = authenticate(source, &candidate)? else {
            // The coin pays to the mirror puzzle but is not a mirror coin — a sibling collateral
            // coin with no advertised URLs, most likely. Not this verb's business.
            continue;
        };

        if mirror.owner_puzzle_hash() == owner_puzzle_hash {
            owned.push(mirror);
        }
    }

    Ok(owned)
}

/// Answers *who mirrors this store*, keyed by the store launcher id and epoch.
///
/// Searches the hint index for the store's namespace value, then re-derives each candidate from its
/// creating spend and keeps only those that genuinely advertise this store. Candidates that cannot
/// be authenticated are counted in [`MirrorSet::rejected_candidates`] and dropped; a source that
/// cannot answer produces `Err`.
pub fn discover<S: MirrorChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    epoch: &BigInt,
) -> Result<MirrorSet, MirrorError> {
    let namespace_hint = morph_store_launcher_id(store_launcher_id, epoch);
    let candidates = source
        .unspent_coins_by_hint(namespace_hint)
        .map_err(unavailable)?;

    let mut claims = Vec::new();
    let mut rejected = 0usize;

    for candidate in candidates {
        // A candidate that fails to authenticate is index noise, not a failed query: the hint index
        // is writable by anyone for the price of a dust coin, so one bad entry must not be able to
        // suppress every honest mirror. A source that could not ANSWER is different, and propagates.
        match authenticate(source, &candidate) {
            Ok(Some(mirror)) if mirror.advertises(store_launcher_id, epoch) => claims.push(mirror),
            Ok(_) => rejected += 1,
            Err(MirrorError::ChainUnavailable(reason)) => {
                return Err(MirrorError::ChainUnavailable(reason))
            }
            Err(_) => rejected += 1,
        }
    }

    Ok(MirrorSet {
        store_launcher_id,
        epoch: epoch.clone(),
        namespace_hint,
        claims,
        rejected,
    })
}

/// Re-derives a candidate coin from the spend that created it.
///
/// This is where a hinted candidate stops being a rumour. `Ok(None)` means the coin is real but is
/// not a mirror coin; `Err(MirrorError::Unauthenticated)` means its creating spend is missing, so
/// nothing about it could be established.
fn authenticate<S: ChainSource>(
    source: &S,
    candidate: &CoinRecord,
) -> Result<Option<MirrorCoin>, MirrorError> {
    let coin_id = candidate.coin.coin_id();
    let creating_spend: CoinSpend = source
        .coin_spend(candidate.coin.parent_coin_info)
        .map_err(unavailable)?
        .ok_or(MirrorError::Unauthenticated { coin_id })?;

    MirrorCoin::from_creating_spend(&creating_spend, coin_id)
}

/// Maps a chain source's own error into the crate's single "could not establish" variant.
fn unavailable<E: core::fmt::Display>(error: E) -> MirrorError {
    MirrorError::ChainUnavailable(error.to_string())
}
