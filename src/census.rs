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

use std::collections::{BTreeMap, BTreeSet, HashSet};

use chia_protocol::Bytes32;
use dig_chainsource_interface::{ChainSource, CoinRecord};
use dig_mirror_collateral::{EpochCensus, EpochRecord, CENSUS_FINALITY_DEPTH_BLOCKS};
use num_bigint::BigInt;

use crate::asset::mirror_coin_puzzle_hash;
use crate::coin::Candidate;
use crate::error::MirrorError;
use crate::query::{unavailable, SpendCache, MAX_CANDIDATES};

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
#[non_exhaustive]
pub struct Exclusions {
    /// **C0** — the source returned a record that is not at the mirror puzzle hash it was asked
    /// for. A fact about the source, not about the chain; nothing else here would have been safe to
    /// read off such a record.
    pub foreign_puzzle: u64,
    /// **C0b** — a block-reward coin, which has no creating spend on *any* source and therefore
    /// could never be authenticated by anyone.
    ///
    /// Distinct from [`unreadable`](Self::unreadable) and from the abort a missing spend otherwise
    /// causes: those describe what a particular source could answer, this describes the chain. A
    /// non-zero count here means someone is paying farming rewards to the mirror puzzle hash — which
    /// is free to do and says nothing about the collateralised network, so it is reported rather
    /// than allowed to end the census.
    pub block_reward: u64,
    /// **C2** — created after the census height, so not yet part of the network being counted.
    pub not_yet_created: u64,
    /// **C3** — already spent at or before the census height.
    pub spent_by_census_height: u64,
    /// The source knew the coin but not the height it was confirmed at, so it cannot be placed
    /// relative to the census height. Excluded rather than assumed either way.
    pub undated: u64,
    /// **C4** — declares an epoch other than the one being qualified against.
    pub wrong_epoch: u64,
    /// Discarded by the cheap prescreen filter for carrying a record amount below the requirement,
    /// **before** any chain read and therefore **before the asset is established**.
    ///
    /// **C5's counterpart, and deliberately not a C5 counter. There is no C5 counter, and the
    /// absence is the honest reporting choice**: every coin this crate can observe failing the
    /// requirement fails it *here*, before its asset is established, so a separate field counting
    /// authenticated shortfalls could only ever read zero. A public counter that is structurally
    /// always zero is not a measurement — an operator reading `0` would conclude "no
    /// under-collateralised stores" when the truth is "this crate cannot observe that". The
    /// invariant that makes the count impossible is still enforced, in `qualify`; it just does not
    /// pretend to be an instrument.
    ///
    /// The asset behind these amounts is unknown: an ordinary XCH `CREATE_COIN` paying the mirror
    /// puzzle hash one mojo below the requirement lands here, nine orders of magnitude cheaper per
    /// unit than a DIG base unit. Anyone can drive this counter arbitrarily high for approximately
    /// nothing, so it is a measure of noise at the shared puzzle hash and never evidence about the
    /// collateralised network.
    pub below_requirement_unauthenticated: u64,
    /// **C1/C6** — not a mirror coin at all, or its memos could not be read: a sibling collateral
    /// coin, a stranger's dust, collateral in some other asset, or an absent creating spend.
    ///
    /// Also where a record that disagrees with the chain lands: a source reporting an amount its
    /// coin's creating spend never produced has described a coin that does not exist, which is a
    /// fact about the source and not about the collateralised network.
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
    ///
    /// Every coin paying to that puzzle hash is examined: a [`CensusOutcome::Final`] is always a
    /// census of the whole population, never of a prefix of it.
    pub fn examined(&self) -> usize {
        self.examined
    }

    /// Why the candidates that did not qualify did not qualify.
    pub fn excluded(&self) -> Exclusions {
        self.excluded
    }
}

/// The outcome of asking for a census: a final one, or a refusal to answer.
///
/// The two refusals are deliberate and are the only alternatives to [`Self::Final`]. A census that
/// covered part of the population, or that was taken too close to the tip, would still be *a
/// number* — and a wrong number arrived at silently is the failure mode this enum exists to make
/// impossible. Refusing is visible; a smaller network is not.
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

    /// The population is too large to authenticate within [`MAX_CANDIDATES`], so no census was
    /// computed.
    ///
    /// This is a **refusal, not a truncation**, and the difference is the whole point. The mirror
    /// puzzle hash is a single global constant that anyone may pay a coin to, so the candidate
    /// population is attacker-writable and — because spent coins are included — never shrinks. A
    /// bound that silently kept a prefix would let anyone censor the census permanently, and two
    /// nodes keeping *different* prefixes of the same chain would fork. So the node says it cannot
    /// compute the network rather than computing a smaller one.
    ///
    /// Reaching this requires `limit` DISTINCT CREATING SPENDS among the surviving candidates, not
    /// `limit` coins. That is deliberate: the expensive pass executes each spend once and answers
    /// for every output it produced, so a thousand coins minted by one transaction cost one
    /// execution and must not be able to consume a thousand of the bound.
    ///
    /// The bound counted coins until it was shown that a coin costs nothing. The mirror puzzle hash
    /// is a CAT outer hash but still only 32 bytes, so an ordinary XCH `CREATE_COIN` puts a record
    /// there for mojos; a flood of those denied every node's census permanently, and permanently is
    /// not an exaggeration — the requirement that would price them out can only rise via a census.
    Incomplete {
        /// The height the census would have been taken at.
        census_height: u32,
        /// How many coins pay to the shared mirror puzzle hash in total.
        candidates: usize,
        /// How many distinct creating spends the surviving candidates would have needed executed.
        creating_spends: usize,
        /// The bound that was exceeded, [`MAX_CANDIDATES`].
        limit: usize,
    },

    /// A census of the **whole** candidate population, taken far enough behind the tip to be acted
    /// on.
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

/// As [`census_height`], with a caller-supplied lower bound to search from.
///
/// A caller walking every epoch since genesis already knows a height the answer must lie above: the
/// census height of the epoch it just resolved. Passing it here confines the search to
/// `[seed_height, peak]` and lets the first probe be *interpolated* from the two timestamps
/// bracketing that range rather than taken from its midpoint. On a mainnet-shaped chain that turns a
/// per-epoch cost of roughly forty-five reads, growing with chain height, into roughly ten that does
/// not grow at all.
///
/// # The seed cannot change the answer, only the work
///
/// This returns exactly what [`census_height`] returns for the same `epoch_start_unix_secs`, for
/// every seed, honest or not. That is the whole contract, and it is not a courtesy: the census
/// height is a consensus value, so a search that returned a *different* height because of a hint
/// would have the node deriving a collateral requirement no other node agrees with — the fork the
/// module docs describe.
///
/// # The seed is untrusted, and is verified rather than believed
///
/// A seed can originate outside the node — dig-node's stored census height may be adopted from a
/// sampled peer cohort, and its own guards bound that height only from below. A seed *above* the
/// true census height is therefore reachable, and believing one would confine the search above the
/// answer and return a plausible, wrong height.
///
/// So the seed is checked against the source before it is used: the seed height's own timestamp is
/// read and must be **strictly below** the epoch start. An honest seed is the previous epoch's
/// census height, whose timestamp lies a whole epoch below this instant, so it passes with an
/// enormous margin; an inflated one cannot. A seed that fails, or that exceeds the peak, is
/// discarded and the full `[0, peak]` search runs — one wasted read, and the shipped behaviour.
/// **A bad seed costs work, never correctness.**
///
/// The seed is a bare height rather than a [`CensusHeight`] for the same reason: with no
/// caller-supplied timestamp to carry, there is no caller-supplied timestamp that could lie. The
/// hazard is removed by construction instead of by a check a later reader could delete.
pub fn census_height_seeded<S: ChainSource>(
    source: &S,
    epoch_start_unix_secs: u64,
    seed_height: Option<u32>,
) -> Result<Option<CensusHeight>, MirrorError> {
    let peak = source.peak_height().map_err(unavailable)?.ok_or_else(|| {
        MirrorError::ChainUnavailable("source exposes no peak height".to_string())
    })?;

    // The epoch has not begun on chain yet. Not an error: the ordinary state of a future epoch.
    // The witness is kept rather than discarded — it is the upper anchor every interpolation below
    // is drawn against, so the seeded search pays no read the unseeded one did not already pay.
    let Some(above) = timestamp_at_or_below(source, peak)?
        .filter(|(_, timestamp)| *timestamp >= epoch_start_unix_secs)
    else {
        return Ok(None);
    };

    let mut low = 0u32;
    let mut high = peak;
    let mut above = above;
    let mut below: Option<(u32, u64)> = None;

    if let Some(seed) = seed_height.filter(|seed| *seed <= peak) {
        // Read the seed's timestamp rather than trusting the caller's claim about it. A seed whose
        // block is at or after the epoch start does not bound the answer from below and is dropped.
        // The seed is a *hint*, so every way it can fail to answer is the same failure: the hint
        // is unusable and the unhinted search runs. `?` here would propagate the probe's
        // `ChainUnavailable` — a transient read error, or a run of non-transaction blocks below the
        // seed — and fail a search that succeeds without the seed, letting a bad hint change
        // correctness rather than only work. Only this probe is swallowed; every other read below
        // is a real search read whose failure must propagate.
        if let Some((witness, timestamp)) = timestamp_at_or_below(source, seed)
            .ok()
            .flatten()
            .filter(|(_, t)| *t < epoch_start_unix_secs)
        {
            // The predicate is false at `seed` and true at `peak`, so `seed < peak` and this cannot
            // overflow or exceed `high`.
            low = seed + 1;
            below = Some((witness, timestamp));
        }
    }

    // Interpolation is dramatically better than bisection on timestamps, which are near-linear in
    // height — but only on average, and the shape of the data comes from an untrusted source. So a
    // probe that fails to shrink the bracket meaningfully forces the next one to bisect, which
    // restores the geometric guarantee without paying for it when interpolation is working.
    //
    // "Meaningfully" is measured over several probes rather than one. A single interpolated probe
    // that lands just below the answer leaves the bracket almost as wide as it was — `high` is still
    // the peak — while being an excellent guess that the next probe builds on. Forcing a bisection
    // there throws that guess away and probes the middle of the chain instead. So the guard only
    // fires after a run of probes has failed to make headway, which on chain-shaped data never
    // happens and on hostile data cannot be delayed indefinitely.
    const STALLS_BEFORE_BISECTION: u32 = 3;

    let mut stalls = 0u32;
    while low < high {
        let width = u64::from(high - low);
        let probe = if stalls >= STALLS_BEFORE_BISECTION {
            // `low + (high - low) / 2` rather than `(low + high) / 2`: the operands are heights read
            // from a source, and their sum leaves `u32` well inside the range this loop must handle.
            low + (high - low) / 2
        } else {
            interpolated_probe(low, high, below, above, epoch_start_unix_secs)
        };

        match timestamp_at_or_below(source, probe)? {
            Some((witness, timestamp)) if timestamp >= epoch_start_unix_secs => {
                high = probe;
                above = (witness, timestamp);
            }
            Some(witnessed) => {
                low = probe + 1;
                below = Some(witnessed);
            }
            None => low = probe + 1,
        }

        stalls = if u64::from(high - low) * 4 > width * 3 {
            stalls + 1
        } else {
            0
        };
    }

    // `low` satisfies the predicate and is minimal, so it IS the witnessing transaction block.
    let (height, timestamp) = timestamp_at_or_below(source, low)?.ok_or_else(|| {
        MirrorError::ChainUnavailable(
            "timestamps changed under the search; census height not established".to_string(),
        )
    })?;

    Ok(Some(CensusHeight { height, timestamp }))
}

/// Where to probe next in `[low, high)`, guessing from the timestamps bracketing the range.
///
/// Block timestamps rise at a roughly constant rate, so the height carrying a given instant can be
/// estimated by linear interpolation between a known-earlier and a known-later block. This only
/// chooses *where to look*; the bracket invariant, and therefore the height eventually returned, is
/// identical whatever this returns. Falls back to the midpoint whenever the anchors cannot support
/// an estimate — before any block below the target has been seen, or where the two anchors carry
/// the same timestamp.
///
/// Note the difference from the rule that a census height's timestamp is never interpolated: this
/// invents no timestamp and attributes none to any block. It picks a height to *ask the source*
/// about, and every timestamp it goes on to compare is one the source answered.
fn interpolated_probe(
    low: u32,
    high: u32,
    below: Option<(u32, u64)>,
    above: (u32, u64),
    target: u64,
) -> u32 {
    let midpoint = low + (high - low) / 2;

    let Some((below_height, below_timestamp)) = below else {
        return midpoint;
    };
    let (above_height, above_timestamp) = above;
    if above_height <= below_height || above_timestamp <= below_timestamp {
        return midpoint;
    }

    let heights = u64::from(above_height - below_height);
    let seconds = above_timestamp - below_timestamp;
    // `target` sits in `(below_timestamp, above_timestamp]` by the bracket invariant; the clamp
    // keeps a source that violates it from steering the estimate out of the bracket.
    let offset = target.saturating_sub(below_timestamp).min(seconds);

    // Saturating rather than wrapping: `heights` and `offset` are derived from an untrusted
    // source, and their product can exceed `u64` on absurd inputs. A release build clamps and a
    // debug build panics, so the arithmetic is made explicit. The clamp below keeps any saturated
    // estimate inside the bracket, so the answer is unchanged either way.
    let estimate = u64::from(below_height).saturating_add(heights.saturating_mul(offset) / seconds);
    estimate.clamp(u64::from(low), u64::from(high - 1)) as u32
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

    let examined = candidates.len();
    let mut excluded = Exclusions::default();
    let mut selected: BTreeMap<Triple, Selection> = BTreeMap::new();
    let qualifying_epoch = BigInt::from(prior.epoch);
    // DIG CAT base units, not mojos. `dig-mirror-collateral` 0.2.0 renamed these fields to say so:
    // a mojo is XCH's base unit at 10^-12 XCH and a DIG CAT base unit is 10^-3 DIG, nine orders of
    // magnitude apart, on a money path. No value changed in the rename.
    let required_per_store = prior.required_per_store_dig_base_units;

    // Pass one, over the ENTIRE population: the rules whose inputs are already on the coin record
    // AND whose operands have an established meaning. No chain read, no CLVM. See `prescreen` for
    // the operand table, and for why the collateral rule is NOT among them.
    let mirror_puzzle_hash = mirror_coin_puzzle_hash();
    let authenticable: Vec<CoinRecord> = candidates
        .into_iter()
        .filter(|candidate| {
            prescreen(
                candidate,
                at.height,
                mirror_puzzle_hash,
                required_per_store,
                &mut excluded,
            )
        })
        .collect();

    // The bound is on DISTINCT CREATING SPENDS, not on candidates, because that is the quantity the
    // expensive pass actually consumes: `read_parent_outputs` executes each spend once and answers
    // for every output it produced, so a thousand coins from one transaction cost one execution.
    //
    // Bounding candidates instead made the refusal reachable for the price of a thousand
    // `CREATE_COIN`s in a single spend — and, before C5 moved behind C1, for the price of dust in
    // the wrong asset. A denied census is self-sustaining, because the requirement that would price
    // the flood out can only rise via a census. Counting spends prices the refusal in transactions
    // an attacker must actually get on chain.
    //
    // It is still a REFUSAL rather than a prefix. See `CensusOutcome::Incomplete`: keeping a prefix
    // of an attacker-writable set is a censorship primitive, and a prefix two nodes may choose
    // differently is a fork.
    let creating_spends: BTreeSet<Bytes32> = authenticable
        .iter()
        .map(|candidate| candidate.coin.parent_coin_info)
        .collect();
    if creating_spends.len() > MAX_CANDIDATES {
        return Ok(CensusOutcome::Incomplete {
            census_height: at.height,
            candidates: examined,
            creating_spends: creating_spends.len(),
            limit: MAX_CANDIDATES,
        });
    }

    // Pass two: the rules that need the creating spend. `spends` holds each executed spend's outputs
    // so that the bound above genuinely bounds the work below.
    let mut spends = SpendCache::new();
    for candidate in &authenticable {
        let Some(qualified) = qualify(
            source,
            &mut spends,
            candidate,
            &qualifying_epoch,
            required_per_store,
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

    // Both counts are at most the number of candidates the source returned, which is a `usize`, so
    // neither conversion can be lossy.
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

/// Applies the rules whose inputs are already on the coin record: **C0**, **C0b**, **C2** and
/// **C3**.
///
/// `true` keeps the candidate for the expensive pass; `false` excludes it and records why.
///
/// # Every operand here has an established meaning, and that is the whole rule
///
/// A comparison is only as sound as the least-established of its two operands, and a threshold is
/// meaningless until you know what the number counts. So each comparison below is listed with what
/// establishes it:
///
/// | comparison | left operand | right operand | established? |
/// |---|---|---|---|
/// | **C0** `puzzle_hash == mirror_coin_puzzle_hash()` | the source's record | this crate's own constant | yes |
/// | **C0b** `!is_block_reward(candidate)` | the source's record and the parent's shape | the consensus coinbase construction | yes |
/// | **C2** `confirmed_height <= census_height` | a block height on the source's chain | a block height on the same chain | yes |
/// | **C3** `spent_height > census_height` | a block height on the source's chain | a block height on the same chain | yes |
/// | *(filter)* `amount >= required_per_store` | a `u64` in **an unknown asset** | DIG CAT base units | **NO** |
///
/// # The last row is why C5 no longer lives here
///
/// Nothing on a coin record establishes which asset its `amount` counts. [`mirror_coin_puzzle_hash`]
/// is a CAT outer hash, but it is still only 32 bytes: an ordinary XCH `CREATE_COIN` paying to it
/// produces a record there denominated in **mojos**, nine orders of magnitude cheaper per unit, which
/// clears any reachable requirement for approximately nothing. C0 does not rescue that comparison and
/// must not be mistaken for doing so — it establishes which puzzle **locks** the coin, never what the
/// coin **contains**. The asset is established only by the lineage proof inside the creating spend,
/// which costs the chain read this pass exists to avoid.
///
/// So the amount comparison **cannot be made sound here at any price**, and the collateral rule C5
/// lives in [`qualify`] behind **C1**, where the asset is known.
///
/// What remains here is a filter, not a rule, and the distinction is the whole finding. It is sound
/// in exactly one direction: `qualify` requires `collateral() == coin.amount`, so every coin that
/// will ultimately qualify has a record amount at or above the requirement, whatever the unit. It can
/// therefore only ever admit coins that will later be rejected — never drop one that would have
/// counted. It is kept because dropping it made a single unreadable dust record abort every census
/// (an absent creating spend fails closed, by design), which is a cheaper denial than the one this
/// rework removes.
///
/// **Nothing security-relevant may rest on it.** In particular it does not guard the bound: that is
/// denominated in distinct creating spends precisely because no cheap amount comparison can be
/// trusted to price a flood.
///
/// C0 itself is new and is worth stating plainly: the candidate list arrives from the source, and
/// nothing previously checked that the records it returned are at the puzzle hash that was asked
/// for.
fn prescreen(
    candidate: &CoinRecord,
    census_height: u32,
    mirror_puzzle_hash: Bytes32,
    required_per_store: u64,
    excluded: &mut Exclusions,
) -> bool {
    // C0 — actually at the mirror puzzle hash. The source was asked for this hash; a source that
    // answers with records at some other one has not been believed about anything yet, and every
    // rule below reads as a fact about a mirror coin.
    if candidate.coin.puzzle_hash != mirror_puzzle_hash {
        excluded.foreign_puzzle += 1;
        return false;
    }

    // C0b — a block-reward coin, which no source can ever authenticate.
    if is_block_reward(candidate) {
        excluded.block_reward += 1;
        return false;
    }

    // C2 — created at or before the census height.
    let Some(confirmed) = candidate.confirmed_height else {
        excluded.undated += 1;
        return false;
    };
    if confirmed > census_height {
        excluded.not_yet_created += 1;
        return false;
    }

    // C3 — not spent at or before the census height. A coin spent AFTER it was locked at the height
    // being counted and still qualifies.
    if candidate
        .spent_height
        .is_some_and(|spent| spent <= census_height)
    {
        excluded.spent_by_census_height += 1;
        return false;
    }

    // A one-directional filter, NOT C5, and counted separately from it for that reason. See the
    // operand table above: this number's asset is unknown, so passing it establishes nothing.
    // Failing it does, because a qualifying coin's collateral IS its record amount — so this can
    // only discard coins C5 would discard anyway.
    if candidate.coin.amount < required_per_store {
        excluded.below_requirement_unauthenticated += 1;
        return false;
    }

    true
}

/// Whether a record is a **block-reward** (coinbase) coin: farmer or pool reward.
///
/// # Why this is a rule of its own and not a case of "the source could not answer"
///
/// Everywhere else in this module an absent creating spend is treated as a gap in the *source*, and
/// it aborts the census on purpose: a pruned source that silently omits spends would otherwise
/// report a smaller network, which is the direction that lowers the requirement for everyone.
///
/// A reward coin is the one shape where that reasoning is simply false. Chia synthesises its
/// `parent_coin_info` (`chia/consensus/coinbase.py`: sixteen bytes of the genesis challenge followed
/// by the block height as a sixteen-byte big-endian integer), so it is not the coin id of any coin
/// and **no spend for it exists on a perfect, complete, unpruned node, ever**. Waiting for a better
/// source cannot help, because there is no better source. Failing closed on it therefore does not
/// protect anything; it converts a free action into a permanent denial.
///
/// Free, and permanent. `farmer_reward_target_puzzle_hash` is free-form farmer or pool config
/// validated against nothing, so pointing it at [`mirror_coin_puzzle_hash`] costs one block. The
/// resulting coin clears C0, C2 and C3, clears the amount filter by nine orders of magnitude, is
/// never spent so C3 never starts excluding it, and is very likely unspendable at all — the mirror
/// puzzle hash is a CAT-wrapped `P2ParentCoin` whose authority needs a lineage proof a reward coin
/// cannot produce. Every census at every later height, on every node, would return `Err`, and
/// `EpochRecord::advance` would never run again.
///
/// # Two detectors, because the flag is not always populated
///
/// [`CoinRecord::coinbase`] is authoritative where a source fills it in. It is not always filled in:
/// `CoinRecord::from_coin_state` sets it to `false` unconditionally, because a wallet-protocol
/// `CoinState` carries no such flag — so a light source reports every reward coin as `coinbase:
/// false` while knowing no better.
///
/// The synthetic parent's *shape* covers that case without needing the genesis challenge, and so
/// without pinning this crate to one network: whichever half of the challenge is used, the last
/// sixteen bytes are a block height, so bytes 16..28 are zero for every height below 2^96. A real
/// parent is a coin id — a SHA-256 output — so a genuine mirror coin matching this costs an attacker
/// a 96-bit grind against a hash they do not control the preimage of. That is why the test is safe
/// in the one direction that matters: it can only ever discard a coin, and the coins it discards
/// could not have qualified.
fn is_block_reward(candidate: &CoinRecord) -> bool {
    candidate.coinbase || candidate.coin.parent_coin_info[16..28] == [0u8; 12]
}

/// Applies the rules that need the coin's creating spend: **C1/C6**, **C4** and **C8**.
///
/// Only ever called on a candidate `prescreen` kept, so C0, C2 and C3 already hold.
///
/// **C5 is applied here, not in `prescreen`**, and the ordering is load-bearing rather than
/// incidental: the collateral comparison is only meaningful once C1 has established that the coin's
/// amount counts DIG CAT base units. A source-reported amount in some other asset is a number
/// without a unit, and comparing it against a threshold is the defect this ordering exists to make
/// impossible.
///
/// `Ok(None)` means the coin was read and did not qualify — the reason is recorded in `excluded`.
/// `Err` means a read could not be answered, which ends the census.
fn qualify<S: ChainSource>(
    source: &S,
    spends: &mut SpendCache,
    candidate: &CoinRecord,
    qualifying_epoch: &BigInt,
    required_per_store: u64,
    excluded: &mut Exclusions,
) -> Result<Option<Qualified>, MirrorError> {
    // C1/C6 — a $DIG mirror coin whose memos read, re-derived from its creating spend rather than
    // taken from an index.
    //
    // `Unauthenticated` is deliberately NOT tolerated here, unlike in `list`. It means the source
    // returned no creating spend — a gap in the SOURCE, not a fact about the chain, and one that
    // `skip_reason` itself documents as something a better source may answer differently. Folding it
    // into `unreadable` would let a pruned source silently report a smaller network, which is the
    // direction that lowers the requirement for everyone, with no attacker involved. A census is
    // complete or absent.
    let coin = match spends.authenticate(source, candidate) {
        Ok(Candidate::Mirror(mirror)) => *mirror,
        Ok(Candidate::NotAMirror | Candidate::UndecodableMemos { .. })
        | Err(MirrorError::NotDigCollateral { .. })
        | Err(MirrorError::Malformed(_)) => {
            excluded.unreadable += 1;
            return Ok(None);
        }
        Err(reason) => return Err(reason),
    };

    // C5, checked rather than assumed — and STRUCTURALLY UNREACHABLE, which is stated here rather
    // than left for a reader to rediscover.
    //
    // Neither disjunct can fire. `prescreen` has already discarded every record whose amount is
    // below the requirement, so the second is implied by the first. And the first compares the
    // record's amount against the coin its own creating spend produced, looked up BY COIN ID — and
    // a coin id is `sha256(parent ‖ puzzle_hash ‖ amount)`, so a record reaching here with a
    // different amount would be a SHA-256 collision. A source that simply lies about an amount
    // describes a coin whose id does not resolve, and lands in `unreadable` above.
    //
    // It is kept because it costs one comparison and is the only place the equality `prescreen`
    // depends on is written down as an executable claim. It is counted as `unreadable` rather than
    // into a C5 counter of its own: a counter no reachable path can increment reports nothing while
    // looking like a measurement.
    //
    // It must NOT be made to fail closed. A tampered record is indistinguishable from a genuine
    // stranger coin whose parent spend created no matching output, and failing closed on that
    // reinstates the dust denial this crate removed — a hostile source can already delete any coin
    // for free by omission.
    if coin.collateral() != candidate.coin.amount || coin.collateral() < required_per_store {
        excluded.unreadable += 1;
        return Ok(None);
    }

    // C4 — declares exactly the epoch being qualified against. Not "at least": a coin posted for a
    // future epoch must not manufacture a signal in this one, and a stale coin must not pad it.
    if coin.epoch() != qualifying_epoch {
        excluded.wrong_epoch += 1;
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
