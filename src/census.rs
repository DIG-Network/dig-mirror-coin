//! **census** — counting the collateralised network at one block height.
//!
//! The per-epoch collateral requirement is a recurrence: what a mirror must lock in epoch `n` is
//! derived from what the network actually locked in epoch `n-1`. [`dig_mirror_collateral`] owns the
//! arithmetic and holds no chain access at all. This module is the other half — the chain read that
//! produces the three integers that arithmetic consumes.
//!
//! # Why this cannot be taken at "some time during the epoch"
//!
//! Every node must compute the *same* requirement without talking to any other node, so the census
//! is taken at a single **block height** that consensus already agrees on, never at a wall-clock
//! instant. [`census_height`] derives it: the first **transaction** block whose timestamp is at or
//! after the epoch start. Non-transaction blocks carry no timestamp, so they are skipped entirely —
//! they are neither candidates nor do they advance the comparison. A one-block disagreement here is
//! a fork, which is why the rule is stated in the code rather than left to a reader.
//!
//! # It looks circular, and it is not
//!
//! A coin qualifies for the census of epoch `n` only if it locks at least the requirement of epoch
//! `n-1` — and that requirement was itself derived from the census of `n-2`, and so on down to
//! [`EpochRecord::bootstrap`], which is a constant. That is **well-founded induction on the epoch
//! number**, not circularity.
//!
//! This module encodes it in its signature rather than in prose: [`census`] takes the *record* for
//! epoch `n-1`, so a caller cannot ask for a census without already holding the epoch it is defined
//! against. A reader who mistakes the recurrence for circular will want to "fix" it by qualifying
//! coins against something cheaper to obtain — and that fix reopens the cheapest attack in the
//! design, described next.
//!
//! # An under-collateralised coin is invisible, not evidence of hardship
//!
//! A coin below the epoch requirement contributes to **nothing**: not the store count, not the owner
//! count, not the locked total. This is the single most important rule here. The controller reads a
//! network that is failing to meet the requirement as a signal to *lower* it, so if cheap coins
//! counted as participants, flooding the chain with dust would be the cheapest possible way to drive
//! the requirement down — the attacker would be paying nothing to weaken everyone. Under-
//! collateralised is not partially collateralised.
//!
//! # A census is complete or it is absent
//!
//! Unlike [`list`](crate::list), which tolerates individual unreadable coins because they say
//! nothing about the caller's own money, an unreachable *source* aborts a census. A census computed
//! over part of the population is not a smaller census; it is a different number from the one every
//! other node computes, arrived at silently. So a read that cannot be answered returns
//! [`MirrorError::ChainUnavailable`] and no census at all.
//!
//! A coin that is read successfully and fails a rule is the opposite case: that is an answer, it is
//! counted in [`Exclusions`], and the census proceeds.

use std::collections::{BTreeMap, HashSet};

use chia_protocol::Bytes32;
use dig_chainsource_interface::{ChainSource, CoinRecord};
use dig_mirror_collateral::{EpochCensus, EpochRecord, CENSUS_FINALITY_DEPTH_BLOCKS};
use num_bigint::BigInt;

use crate::asset::mirror_coin_puzzle_hash;
use crate::coin::Candidate;
use crate::error::MirrorError;
use crate::query::{authenticate, unavailable, MAX_CANDIDATES};

/// How far a timestamp probe will walk back through non-transaction blocks before giving up.
///
/// Chia targets a transaction block roughly every other block, so a run of this length has no
/// precedent. The bound exists because the alternative to a bound is an unbounded scan driven by
/// whatever a source chooses to answer; exhausting it is reported as an unanswerable read rather
/// than resolved by a guess, because a guessed census height is a fork.
const MAX_NON_TRANSACTION_RUN: u32 = 64;

/// The block a census is taken at.
///
/// A height, not an instant. The timestamp is carried only so a caller can show *why* this height
/// was chosen; nothing in [`census`] compares against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CensusHeight {
    /// The height of the first transaction block at or after the epoch start.
    pub height: u32,
    /// That block's Unix timestamp, in seconds.
    pub timestamp: u64,
}

/// Why candidate coins did not qualify, counted by rule.
///
/// Exclusions are not errors and not noise. A census that counts nothing is indistinguishable from a
/// census whose every candidate failed one rule unless the failures are reported, and those two
/// situations call for very different responses from an operator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Exclusions {
    /// **C2** — created after the census height, so not yet part of the network being counted.
    pub not_yet_created: u64,
    /// **C3** — already spent at or before the census height.
    pub spent_by_census_height: u64,
    /// The source knew the coin but not the height it was confirmed at, so it cannot be placed
    /// relative to the census height. Excluded rather than assumed either way.
    pub undated: u64,
    /// **C4** — declares an epoch other than the one being qualified against.
    pub wrong_epoch: u64,
    /// **C5** — locks less than that epoch's requirement. See the module docs: these are invisible,
    /// never evidence.
    pub under_collateralised: u64,
    /// **C1/C6** — not a mirror coin at all, or its memos could not be read: a sibling collateral
    /// coin, a stranger's dust, collateral in some other asset, or an absent creating spend.
    pub unreadable: u64,
    /// **C8** — the coin's declared advertisement does not reproduce the hint it was published
    /// under, so its owner attribution is unproven. Never attributed on a guess.
    pub unattributed: u64,
    /// **C9** — a qualifying coin displaced by a larger one for the same triple. Counted for
    /// transparency; the triple itself still counts exactly once.
    pub superseded: u64,
}

/// A completed census: the three controller inputs, plus an honest account of everything excluded.
#[derive(Debug, Clone)]
pub struct MirrorCensus {
    census: EpochCensus,
    height: u32,
    examined: usize,
    excluded: Exclusions,
    truncated: bool,
}

impl MirrorCensus {
    /// The three chain-derived quantities, ready for
    /// [`EpochRecord::advance`](dig_mirror_collateral::EpochRecord::advance).
    pub fn census(&self) -> EpochCensus {
        self.census
    }

    /// The block height this census was taken at.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// How many candidate coins were examined at the shared mirror puzzle hash.
    pub fn examined(&self) -> usize {
        self.examined
    }

    /// Why the candidates that did not qualify did not qualify.
    pub fn excluded(&self) -> Exclusions {
        self.excluded
    }

    /// Whether the population exceeded [`MAX_CANDIDATES`] and the scan stopped early.
    ///
    /// A truncated census is **not** a census of the network — it is a census of an arbitrary prefix
    /// of it, and two nodes reading the same chain may take different prefixes. A caller MUST NOT
    /// feed one to the controller. It is surfaced rather than hidden because a flood large enough to
    /// trip this is exactly what an attacker would want to happen quietly.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// The outcome of asking for a census: either a final one, or a refusal to be premature.
#[derive(Debug, Clone)]
pub enum CensusOutcome {
    /// The census height is too close to the tip for the answer to be safe to act on.
    ///
    /// A census taken at the tip is reorg-sensitive, and this is a money path. Waiting for
    /// [`CENSUS_FINALITY_DEPTH_BLOCKS`] costs roughly ten minutes out of a seven-day epoch, so the
    /// lag is free and the alternative is publishing a requirement that a reorg can retract.
    Pending {
        /// The height a census would be taken at.
        census_height: u32,
        /// The source's current peak.
        peak_height: u32,
    },

    /// A census taken far enough behind the tip to be acted on.
    Final(Box<MirrorCensus>),
}

/// Finds the block a census for an epoch beginning at `epoch_start_unix_secs` is taken at.
///
/// The answer is the **first transaction block whose timestamp is at or after the epoch start**.
/// Heights that report no timestamp are non-transaction blocks: they are skipped, and they never
/// become the census height themselves.
///
/// Returns `Ok(None)` when the chain has not yet reached the epoch start — a real answer, and the
/// ordinary state of a future epoch. Returns `Err` when the source could not answer, including when
/// it exposes no peak or no timestamps: without those the height cannot be established, and a census
/// height that is guessed is worse than one that is missing.
///
/// # How the search is sound over a chain with gaps
///
/// Binary search needs a monotone predicate, and "the block at `h` is a transaction block after the
/// epoch start" is not one — most heights have no timestamp at all. The predicate used instead is
/// *"the newest transaction block at or below `h` is at or after the epoch start"*, which is monotone
/// because block timestamps do not decrease. The smallest `h` satisfying it is necessarily a
/// transaction block itself: if the block witnessing it sat strictly below `h`, that lower height
/// would satisfy the predicate too, contradicting minimality.
pub fn census_height<S: ChainSource>(
    source: &S,
    epoch_start_unix_secs: u64,
) -> Result<Option<CensusHeight>, MirrorError> {
    let peak = source.peak_height().map_err(unavailable)?.ok_or_else(|| {
        MirrorError::ChainUnavailable("source exposes no peak height".to_string())
    })?;

    // The epoch has not begun on chain yet. Not an error: the ordinary state of a future epoch.
    if timestamp_at_or_below(source, peak)?
        .map_or(true, |(_, timestamp)| timestamp < epoch_start_unix_secs)
    {
        return Ok(None);
    }

    let mut low = 0u32;
    let mut high = peak;
    while low < high {
        // `low + (high - low) / 2` rather than `(low + high) / 2`: the operands are heights read
        // from a source, and their sum leaves `u32` well inside the range this loop must handle.
        let middle = low + (high - low) / 2;
        match timestamp_at_or_below(source, middle)? {
            Some((_, timestamp)) if timestamp >= epoch_start_unix_secs => high = middle,
            _ => low = middle + 1,
        }
    }

    // `low` satisfies the predicate and is minimal, so it IS the witnessing transaction block.
    let (height, timestamp) = timestamp_at_or_below(source, low)?.ok_or_else(|| {
        MirrorError::ChainUnavailable(
            "timestamps changed under the search; census height not established".to_string(),
        )
    })?;

    Ok(Some(CensusHeight { height, timestamp }))
}

/// The newest transaction block at or below `height`, with its timestamp.
///
/// `Ok(None)` means there is no transaction block at or below `height` within the search bound
/// reaching genesis. Exhausting [`MAX_NON_TRANSACTION_RUN`] without reaching genesis is an `Err`:
/// that is a source not answering timestamps, not a chain without blocks, and the two must not be
/// confused.
fn timestamp_at_or_below<S: ChainSource>(
    source: &S,
    height: u32,
) -> Result<Option<(u32, u64)>, MirrorError> {
    let mut probe = height;
    for _ in 0..=MAX_NON_TRANSACTION_RUN {
        if let Some(timestamp) = source.block_timestamp(probe).map_err(unavailable)? {
            return Ok(Some((probe, timestamp)));
        }
        let Some(next) = probe.checked_sub(1) else {
            return Ok(None);
        };
        probe = next;
    }

    Err(MirrorError::ChainUnavailable(format!(
        "no block timestamp within {MAX_NON_TRANSACTION_RUN} blocks below height {height}"
    )))
}

/// Counts the collateralised network at `at`, qualifying every coin against the epoch `prior`
/// describes.
///
/// `prior` is the record for epoch `n-1`; the census produced describes epoch `n`. Passing the
/// record rather than a bare threshold is deliberate — see the module docs on why the recurrence is
/// well founded.
///
/// # Errors
///
/// [`MirrorError::ChainUnavailable`] when any read could not be answered. A census is complete or
/// absent; see the module docs.
pub fn census<S: ChainSource>(
    source: &S,
    prior: &EpochRecord,
    at: CensusHeight,
) -> Result<CensusOutcome, MirrorError> {
    let epoch = prior.epoch.checked_add(1).ok_or_else(|| {
        MirrorError::Malformed("the terminal epoch has no successor to census".to_string())
    })?;

    let peak = source.peak_height().map_err(unavailable)?.ok_or_else(|| {
        MirrorError::ChainUnavailable("source exposes no peak height".to_string())
    })?;

    // Saturating, because a census height near `u32::MAX` must read as "not yet final" rather than
    // wrapping to a small number that every peak trivially exceeds.
    let final_at = u64::from(at.height) + CENSUS_FINALITY_DEPTH_BLOCKS;
    if u64::from(peak) < final_at {
        return Ok(CensusOutcome::Pending {
            census_height: at.height,
            peak_height: peak,
        });
    }

    // Spent coins are included in the read: C3 excludes a coin spent at or BEFORE the census height,
    // and a coin spent after it was still locked at the height being counted.
    let candidates = source
        .coin_records_by_puzzle_hash(mirror_coin_puzzle_hash(), true)
        .map_err(unavailable)?;

    let truncated = candidates.len() > MAX_CANDIDATES;
    let examined = candidates.len().min(MAX_CANDIDATES);
    let mut excluded = Exclusions::default();
    let mut selected: BTreeMap<Triple, Selection> = BTreeMap::new();
    let qualifying_epoch = BigInt::from(prior.epoch);

    for candidate in candidates.into_iter().take(MAX_CANDIDATES) {
        let Some(qualified) = qualify(
            source,
            &candidate,
            at.height,
            &qualifying_epoch,
            // The only `EpochRecord` field this crate reads whose NAME is changing:
            // `dig-mirror-collateral` is renaming its `*_mojos` fields for 0.2.0 — a mojo is XCH's
            // base unit and a DIG CAT base unit is nine orders of magnitude larger — so keeping
            // this read to one line keeps the adoption a one-line edit rather than a sweep.
            // (`prior.epoch` is read above as well, but its name is not changing.)
            prior.required_per_store_mojos,
            &mut excluded,
        )?
        else {
            continue;
        };

        // C9 — one coin per triple: the largest amount, ties broken by the lowest coin id compared
        // big-endian bytewise. Deterministic on both axes, because two nodes disagreeing about which
        // coin represents a triple would disagree about `locked`.
        match selected.entry(qualified.triple) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(qualified.selection);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                if qualified.selection.supersedes(slot.get()) {
                    slot.insert(qualified.selection);
                }
                excluded.superseded += 1;
            }
        }
    }

    let mut locked: u64 = 0;
    let mut owners: HashSet<Bytes32> = HashSet::new();
    for (triple, selection) in &selected {
        locked = locked.checked_add(selection.amount).ok_or_else(|| {
            MirrorError::Malformed(
                "locked collateral total overflows u64 DIG CAT base units".to_string(),
            )
        })?;
        owners.insert(triple.owner);
    }

    // Both counts are bounded by `MAX_CANDIDATES`, so neither conversion can be lossy.
    let census = EpochCensus {
        epoch,
        stores: selected.len() as u64,
        owners: owners.len() as u64,
        locked,
    };

    Ok(CensusOutcome::Final(Box::new(MirrorCensus {
        census,
        height: at.height,
        examined,
        excluded,
        truncated,
    })))
}

/// The unit the census counts: one owner's advertisement of one store at one root.
///
/// A coin is not the unit. A thousand coins backing one advertisement are one advertisement, or a
/// publisher could inflate every signal by splitting their stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Triple {
    owner: Bytes32,
    store: Bytes32,
    root: Bytes32,
}

/// The coin currently representing a triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Selection {
    amount: u64,
    coin_id: Bytes32,
}

impl Selection {
    /// Whether this coin displaces `incumbent` as the representative of their shared triple.
    fn supersedes(&self, incumbent: &Self) -> bool {
        match self.amount.cmp(&incumbent.amount) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            // `as_ref()` yields the 32 bytes in the order they appear on chain, so a slice
            // comparison IS the big-endian bytewise comparison the rule names.
            std::cmp::Ordering::Equal => self.coin_id.as_ref() < incumbent.coin_id.as_ref(),
        }
    }
}

/// A candidate that passed every rule, and what it contributes.
struct Qualified {
    triple: Triple,
    selection: Selection,
}

/// Applies rules C1 through C8 to one candidate.
///
/// `Ok(None)` means the coin was read and did not qualify — the reason is recorded in `excluded`.
/// `Err` means a read could not be answered, which ends the census.
fn qualify<S: ChainSource>(
    source: &S,
    candidate: &CoinRecord,
    census_height: u32,
    qualifying_epoch: &BigInt,
    required_per_store: u64,
    excluded: &mut Exclusions,
) -> Result<Option<Qualified>, MirrorError> {
    // C2 — created at or before the census height.
    let Some(confirmed) = candidate.confirmed_height else {
        excluded.undated += 1;
        return Ok(None);
    };
    if confirmed > census_height {
        excluded.not_yet_created += 1;
        return Ok(None);
    }

    // C3 — not spent at or before the census height. A coin spent AFTER it was locked at the height
    // being counted and still qualifies.
    if candidate
        .spent_height
        .is_some_and(|spent| spent <= census_height)
    {
        excluded.spent_by_census_height += 1;
        return Ok(None);
    }

    // C1/C6 — a $DIG mirror coin whose memos read, re-derived from its creating spend rather than
    // taken from an index.
    let coin = match authenticate(source, candidate) {
        Ok(Candidate::Mirror(mirror)) => *mirror,
        Ok(Candidate::NotAMirror | Candidate::UndecodableMemos { .. })
        | Err(MirrorError::NotDigCollateral { .. } | MirrorError::Unauthenticated { .. })
        | Err(MirrorError::Malformed(_)) => {
            excluded.unreadable += 1;
            return Ok(None);
        }
        Err(reason) => return Err(reason),
    };

    // C4 — declares exactly the epoch being qualified against. Not "at least": a coin posted for a
    // future epoch must not manufacture a signal in this one, and a stale coin must not pad it.
    if coin.epoch() != qualifying_epoch {
        excluded.wrong_epoch += 1;
        return Ok(None);
    }

    // C5 — meets that epoch's requirement. Read the module docs before relaxing this.
    if coin.collateral() < required_per_store {
        excluded.under_collateralised += 1;
        return Ok(None);
    }

    // C8 — the owner is PROVEN, never guessed. `advertises` recomputes the hint from the coin's
    // declared store, root and epoch together with the owner taken from the coin's LINEAGE PROOF,
    // and requires it to equal the hint the coin was actually published under. A coin whose declared
    // advertisement does not reproduce its own hint was published in someone else's bucket, and
    // attributing it anyway would hand an attacker a free way to inflate the owner count.
    if !coin.advertises(coin.store_launcher_id(), coin.root_hash(), coin.epoch()) {
        excluded.unattributed += 1;
        return Ok(None);
    }

    Ok(Some(Qualified {
        triple: Triple {
            owner: coin.owner_puzzle_hash(),
            store: coin.store_launcher_id(),
            root: coin.root_hash(),
        },
        selection: Selection {
            amount: coin.collateral(),
            coin_id: coin.coin().coin_id(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection(amount: u64, first_byte: u8) -> Selection {
        let mut id = [0u8; 32];
        id[0] = first_byte;
        Selection {
            amount,
            coin_id: Bytes32::new(id),
        }
    }

    /// The amount axis. Exercised by the census tests too, pinned here so the tie-break test below
    /// has a control that is failing for a different reason than it is.
    #[test]
    fn a_larger_coin_displaces_a_smaller_one() {
        assert!(selection(2_000, 0x01).supersedes(&selection(1_000, 0x00)));
        assert!(!selection(1_000, 0x00).supersedes(&selection(2_000, 0x01)));
    }

    /// The tie-break axis, which no census fixture can reach: two coins of equal amount for one
    /// triple would need identical creating spends to differ only in coin id.
    ///
    /// Determinism here is not cosmetic. Two nodes that broke a tie differently would attribute a
    /// different amount to the same triple and compute a different `locked` from the same chain.
    #[test]
    fn an_equal_tie_is_broken_by_the_lower_coin_id_compared_big_endian_bytewise() {
        let low = selection(1_000, 0x01);
        let high = selection(1_000, 0x02);

        assert!(low.supersedes(&high));
        assert!(!high.supersedes(&low));
    }

    /// A coin never displaces itself, so a duplicate record for one coin cannot flip the selection
    /// back and forth depending on the order a source returns it in.
    #[test]
    fn a_coin_does_not_displace_itself() {
        let only = selection(1_000, 0x01);

        assert!(!only.supersedes(&only));
    }
}
