//! **list** and **discover** — the two chain reads, which are not the same read.
//!
//! | verb | question | keyed by | an empty answer means |
//! |---|---|---|---|
//! | [`list`] | which mirror coins are mine? | owner puzzle hash | you have locked no collateral |
//! | [`discover`] | does this peer bond this store at this root? | the full advertisement | they do not |
//!
//! ## `discover` is a check on a named peer, not a census of a store
//!
//! It used to be the latter, and since 0.5.0 it cannot be: the hint is morphed from the **owner**
//! along with the store, root and epoch, so there is no bucket holding "everyone who mirrors this
//! store" to enumerate. A caller must name whose bond it is asking about.
//!
//! That is the shape the network actually needs. Peers are found by the DHT, which is where peer
//! discovery belongs; what a peer's claim needs is a way to check that the collateral behind it is
//! real and is staked on the store **and root** being asked for. A hostile peer handing over a coin
//! id that bonds something else is the case this verb exists to reject, and it can only reject it by
//! being told what it should have bonded.
//!
//! They resist collapsing into one function because their **trust** differs, not just their key.
//! `list` is about the caller's own money, so under-reporting it is a real harm and every candidate
//! it could not resolve is named back to the caller. `discover` reads an index anyone can write
//! into, where unresolvable entries are ordinary noise, so it counts them and moves on.
//!
//! What they share is that **neither is deniable by one coin**. Both walk lists a stranger can add
//! to for the price of dust, so neither may let one candidate's contents decide the fate of the
//! whole query — an early version of `list` did, and a single 1-mojo coin carrying undecodable memos
//! took the verb away from every user of the network, permanently, along with the only supported
//! route to [`reclaim`](crate::reclaim). Both bound their work at [`MAX_CANDIDATES`] for the same
//! reason, and both disclose when that bound was reached rather than refusing or staying quiet.
//!
//! Both preserve the same distinction at the boundary: an empty result is an answer, an `Err` is the
//! absence of one. Neither ever degrades an unreachable source into "nothing found", and neither
//! ever promotes one unreadable coin into an unreachable source.

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, CoinRecord};
use num_bigint::BigInt;

use crate::asset::mirror_coin_puzzle_hash;
use crate::coin::{Candidate, MirrorCoin};
use crate::error::MirrorError;
use crate::namespace::mirror_hint;

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

/// One owner's claims over one store at one root for one epoch, as answered by one chain source.
///
/// Empty [`claims`](Self::claims) is a real answer: the source was consulted and found nothing. A
/// caller that could not reach a source gets `Err` from [`discover`] instead and must not treat the
/// two alike.
///
/// The type is named for what it holds. A claim is an assertion backed by locked $DIG — it says
/// somebody staked collateral on serving this store, and nothing whatsoever about whether they do.
/// Availability is established by fetching from a mirror, never by reading this struct.
#[derive(Debug, Clone)]
pub struct MirrorSet {
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    owner_puzzle_hash: Bytes32,
    epoch: BigInt,
    namespace_hint: Bytes32,
    claims: Vec<MirrorCoin>,
    rejected: usize,
    truncated: bool,
}

impl MirrorSet {
    /// The store these claims were sought for.
    pub fn store_launcher_id(&self) -> Bytes32 {
        self.store_launcher_id
    }

    /// The store root these claims were sought for.
    pub fn root_hash(&self) -> Bytes32 {
        self.root_hash
    }

    /// The owner whose bond was asked about.
    pub fn owner_puzzle_hash(&self) -> Bytes32 {
        self.owner_puzzle_hash
    }

    /// The epoch these claims were sought for.
    pub fn epoch(&self) -> &BigInt {
        &self.epoch
    }

    /// The namespace value the four advertised terms morph to — the hint that was searched.
    pub fn namespace_hint(&self) -> Bytes32 {
        self.namespace_hint
    }

    /// The authenticated claims, each backed by locked $DIG.
    ///
    /// Not a list of working mirrors. See the type's own documentation.
    pub fn claims(&self) -> &[MirrorCoin] {
        &self.claims
    }

    /// Whether the source found no such bond.
    ///
    /// A read that failed is an `Err` and never reaches this method. A read that stopped early does
    /// reach it, so `is_empty()` means *this owner bonds nothing here* only when
    /// [`is_truncated`](Self::is_truncated) is `false`; otherwise it means *nobody in the part that
    /// was examined*.
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Whether the hint index held more than [`MAX_CANDIDATES`] entries, so the scan stopped early.
    ///
    /// A flood large enough to trip this is visible rather than silent, which is the point: the
    /// alternative is either unbounded work or a confident "nobody mirrors this" that an attacker
    /// bought for the price of dust.
    pub fn is_truncated(&self) -> bool {
        self.truncated
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

/// A caller's own mirror coins, and an honest account of anything the scan could not resolve.
///
/// `list` scans a puzzle hash shared by every mirror coin in existence, so the overwhelming majority
/// of what it walks belongs to strangers. Most of that is resolved and discarded silently — a coin
/// that is definitively *not a mirror coin* is simply not the caller's, and saying so about every
/// sibling collateral coin on the chain would be noise.
///
/// What is **not** silent is a candidate whose nature could not be established at all. Those are
/// recorded in [`skipped`](Self::skipped), because they are the only ones that could conceivably
/// have been the caller's own money. An inventory with a non-empty `skipped` list MAY be short, and
/// [`is_complete`](Self::is_complete) says so in one call.
#[derive(Debug)]
pub struct MirrorInventory {
    owner_puzzle_hash: Bytes32,
    coins: Vec<MirrorCoin>,
    skipped: Vec<SkippedCandidate>,
    truncated: bool,
}

impl MirrorInventory {
    /// The owner these coins were sought for.
    pub fn owner_puzzle_hash(&self) -> Bytes32 {
        self.owner_puzzle_hash
    }

    /// The authenticated mirror coins this owner controls.
    pub fn coins(&self) -> &[MirrorCoin] {
        &self.coins
    }

    /// The candidates whose nature could not be established, with the reason for each.
    ///
    /// Non-empty means the scan met chain data it could not interpret — an undecodable memo, a
    /// creating spend the source could not produce. Such a coin costs one mojo to place at the
    /// shared mirror puzzle hash, so a stranger can always put one there; what a caller learns here
    /// is exactly which coin ids were affected and why, rather than either a silent omission or a
    /// denied query.
    pub fn skipped(&self) -> &[SkippedCandidate] {
        &self.skipped
    }

    /// Whether the scan reached the end of the candidate list without exceeding
    /// [`MAX_CANDIDATES`].
    ///
    /// `false` means the scan stopped early and coins beyond the limit were never examined.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Whether every candidate was resolved, so this inventory is known to be the whole of it.
    ///
    /// `false` does NOT mean a coin is missing — it means one might be. A caller that would rather
    /// refuse than under-report its own money checks this and fails closed; that decision belongs to
    /// the caller, because only the caller knows what it is about to do with the answer.
    pub fn is_complete(&self) -> bool {
        self.skipped.is_empty() && !self.truncated
    }
}

/// A candidate coin that could not be resolved into a yes-or-no answer, and why.
#[derive(Debug, Clone)]
pub struct SkippedCandidate {
    coin_id: Bytes32,
    reason: SkipReason,
}

impl SkippedCandidate {
    /// The coin that could not be resolved.
    pub fn coin_id(&self) -> Bytes32 {
        self.coin_id
    }

    /// Why it could not be resolved.
    pub fn reason(&self) -> &SkipReason {
        &self.reason
    }
}

/// Why a candidate coin could not be resolved.
///
/// `#[non_exhaustive]`: further reasons may arrive in a minor release.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// The coin's creating spend could not be produced, so nothing about it could be established.
    Unauthenticated,
    /// The coin's creating spend was produced but could not be interpreted — an undecodable memo
    /// list, a puzzle that did not run. Carries the diagnostic verbatim.
    Undecodable(String),
}

/// The most candidates either query will examine in one call.
///
/// Both queries walk lists that anyone may add to for the price of a dust coin, so the work they do
/// is driven by attacker-writable input and MUST be bounded. The bound is a stop, never a refusal:
/// refusing at the limit would hand an attacker a cheaper version of the very denial this bound
/// exists to prevent, so a query that reaches it returns what it found and says plainly that it
/// stopped early ([`MirrorInventory::is_truncated`], [`MirrorSet::is_truncated`]).
pub const MAX_CANDIDATES: usize = 10_000;

/// Answers *which mirror coins are mine*, keyed by the owner's puzzle hash.
///
/// Scans the shared mirror puzzle hash and keeps the coins whose lineage proof names
/// `owner_puzzle_hash` as the controlling wallet. Ownership therefore comes from executed on-chain
/// code, not from a hint, and no wallet can be made to see somebody else's coin as its own.
///
/// An empty [`MirrorInventory::coins`] means the owner has no locked collateral. An `Err` means the
/// **source** could not answer, and never that one coin on it was odd — see
/// [`MirrorInventory::skipped`] for that, and [`MirrorInventory::is_complete`] for whether it
/// happened at all.
pub fn list<S: ChainSource>(
    source: &S,
    owner_puzzle_hash: Bytes32,
) -> Result<MirrorInventory, MirrorError> {
    let candidates = source
        .coin_records_by_puzzle_hash(mirror_coin_puzzle_hash(), false)
        .map_err(unavailable)?;

    let truncated = candidates.len() > MAX_CANDIDATES;
    let mut coins = Vec::new();
    let mut skipped = Vec::new();

    for candidate in candidates.into_iter().take(MAX_CANDIDATES) {
        let coin_id = candidate.coin.coin_id();

        // Every mirror coin in existence shares this puzzle hash, so nearly every candidate here
        // belongs to a stranger. A per-candidate failure therefore says nothing about the caller's
        // own money, and propagating one would let a single coin — one mojo, placed by anybody —
        // deny this query to every user of the network at once. What is NOT acceptable is dropping
        // it silently, because an inventory that is quietly short understates the owner's money: an
        // unresolved candidate is recorded, and the caller is told.
        match authenticate(source, &candidate) {
            Ok(Candidate::Mirror(mirror)) if mirror.owner_puzzle_hash() == owner_puzzle_hash => {
                coins.push(mirror);
            }

            // Settled questions with the answer "not yours": somebody else's mirror coin, a coin at
            // this puzzle hash that advertises nothing (a sibling collateral coin, most likely), or
            // collateral that turns out not to be $DIG. None of them could have been this owner's.
            Ok(Candidate::Mirror(_) | Candidate::NotAMirror)
            | Err(MirrorError::NotDigCollateral { .. }) => {}

            // Memos that would not decode — and the owner is known anyway, because it comes from the
            // lineage proof rather than from the memos. So this is settled too, for everyone except
            // the one wallet that controls the coin. Reporting it to all of them instead would let a
            // stranger's single mojo hold `is_complete()` false for every caller forever, which is
            // the same denial this verb was fixed to resist, one level up and wearing the
            // completeness claim instead of the query.
            Ok(Candidate::UndecodableMemos {
                owner_puzzle_hash: owner,
                ..
            }) if owner != owner_puzzle_hash => {}

            // The caller's OWN coin, unreadable. This one is a real gap in their inventory, only
            // they can have caused it, and it is precisely what they need to be told about.
            Ok(Candidate::UndecodableMemos { detail, .. }) => skipped.push(SkippedCandidate {
                coin_id,
                reason: SkipReason::Undecodable(detail),
            }),

            // The SOURCE could not answer. That is not a fact about one coin, so it is not a skip.
            Err(MirrorError::ChainUnavailable(reason)) => {
                return Err(MirrorError::ChainUnavailable(reason))
            }

            Err(reason) => skipped.push(SkippedCandidate {
                coin_id,
                reason: skip_reason(reason),
            }),
        }
    }

    Ok(MirrorInventory {
        owner_puzzle_hash,
        coins,
        skipped,
        truncated,
    })
}

/// Answers *does this owner bond this store, at this root, for this epoch*.
///
/// Searches the hint index for the advertisement's namespace value, then re-derives each candidate
/// from its creating spend and keeps only those that genuinely advertise it — declared tuple and
/// recomputed hint both, via [`MirrorCoin::advertises`]. Candidates that cannot be authenticated are
/// counted in [`MirrorSet::rejected_candidates`] and dropped; a source that cannot answer produces
/// `Err`.
///
/// The owner is a parameter because the hint is morphed from it, so there is no store-wide bucket to
/// read without one — see the module docs. It is not a weakening: a coin's owner is re-derived from
/// its lineage proof during authentication, so naming the wrong owner yields an empty answer rather
/// than somebody else's coin.
pub fn discover<S: MirrorChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    owner_puzzle_hash: Bytes32,
    epoch: &BigInt,
) -> Result<MirrorSet, MirrorError> {
    let namespace_hint = mirror_hint(store_launcher_id, root_hash, owner_puzzle_hash, epoch);
    let candidates = source
        .unspent_coins_by_hint(namespace_hint)
        .map_err(unavailable)?;

    let truncated = candidates.len() > MAX_CANDIDATES;
    let mut claims = Vec::new();
    let mut rejected = 0usize;

    for candidate in candidates.into_iter().take(MAX_CANDIDATES) {
        // A candidate that fails to authenticate is index noise, not a failed query: the hint index
        // is writable by anyone for the price of a dust coin, so one bad entry must not be able to
        // suppress every honest mirror. A source that could not ANSWER is different, and propagates.
        match authenticate(source, &candidate) {
            Ok(Candidate::Mirror(mirror))
                if mirror.advertises(store_launcher_id, root_hash, epoch) =>
            {
                claims.push(mirror)
            }
            Ok(_) => rejected += 1,
            Err(MirrorError::ChainUnavailable(reason)) => {
                return Err(MirrorError::ChainUnavailable(reason))
            }
            Err(_) => rejected += 1,
        }
    }

    Ok(MirrorSet {
        store_launcher_id,
        root_hash,
        owner_puzzle_hash,
        epoch: epoch.clone(),
        namespace_hint,
        claims,
        rejected,
        truncated,
    })
}

/// Re-derives a candidate coin from the spend that created it.
///
/// This is where a hinted candidate stops being a rumour. It returns a [`Candidate`] rather than an
/// `Option` so that a coin whose memos would not decode still reports the owner it DID establish;
/// `Err(MirrorError::Unauthenticated)` means the creating spend is missing, so nothing about the
/// coin could be established at all — the one case where even the owner is unknown.
fn authenticate<S: ChainSource>(
    source: &S,
    candidate: &CoinRecord,
) -> Result<Candidate, MirrorError> {
    let coin_id = candidate.coin.coin_id();
    let creating_spend: CoinSpend = source
        .coin_spend(candidate.coin.parent_coin_info)
        .map_err(unavailable)?
        .ok_or(MirrorError::Unauthenticated { coin_id })?;

    MirrorCoin::classify(&creating_spend, coin_id)
}

/// Reduces a per-candidate failure to the reason a caller can act on.
///
/// The distinction that survives is the one a caller can do something about: a coin whose creating
/// spend the source simply did not have MAY appear on a better source, while a coin whose creating
/// spend could not be interpreted will read the same way everywhere.
fn skip_reason(error: MirrorError) -> SkipReason {
    match error {
        MirrorError::Unauthenticated { .. } => SkipReason::Unauthenticated,
        other => SkipReason::Undecodable(other.to_string()),
    }
}

/// Maps a chain source's own error into the crate's single "could not establish" variant.
fn unavailable<E: core::fmt::Display>(error: E) -> MirrorError {
    MirrorError::ChainUnavailable(error.to_string())
}
