//! A seed equal to the peak must not be able to skip the search and return the peak block.
//!
//! `census_height_seeded` accepts a seed by reading the seed height's own timestamp and requiring
//! it to lie strictly below the epoch start, then sets the search's lower bound to `seed + 1`. The
//! comment above that assignment argues it cannot exceed `high`: the predicate is true at `peak`
//! and false at `seed`, so `seed < peak`. That argument holds only if the source answers the two
//! reads consistently, and it is the source — not this crate — that decides.
//!
//! A pooled multi-peer chain source answers successive reads from whichever peer is available, so
//! two reads of the *same* height can be answered from two different chain views. The peak probe
//! and the seed probe are exactly such a pair when the seed equals the peak, and a seed equal to
//! the peak is reachable without any privileged position: dig-node re-offers the census height it
//! stored, and a hint planted a little ahead becomes exactly the peak one block-time later.
//!
//! When that happens `low` becomes `peak + 1`, which is above `high`. The bisection loop is
//! `while low < high`, so it never runs at all, and the final read probes `peak + 1` — above the
//! peak — whose walk-down lands on the peak block. The function then returns the **peak** as the
//! census height: a collateral requirement no other node derives, from a chain the unseeded search
//! reads correctly.
//!
//! SPEC.md §8.1.1 states that a hint bounds the search and never the answer, and that for every
//! hint the height returned MUST equal the height returned with no hint. This test holds the
//! seeded search to that against a source that answers inconsistently, which is the only condition
//! under which the bracket can break.
//!
//! # Why the other seeded fixtures cannot see this
//!
//! `census_height_seeded.rs` and `census_height_seeded_unreadable_seed.rs` both answer every read
//! of a given height identically, so `seed < peak` holds by construction in both and `low` can
//! never pass `high`. The inconsistency has to be built deliberately, and it has to land on the
//! seed probe specifically, or the search simply re-reads a block it already knows.

use std::cell::Cell;

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_mirror_coin::{census_height, census_height_seeded};

/// Genesis instant of the fixture chain. Pinned, so no assertion here depends on the wall clock.
const GENESIS: u64 = 1_600_000_000;
/// Seconds per block. Every height in this fixture carries a transaction block.
const SPACING: u64 = 18;
const PEAK: u32 = 1_500_000;
/// The height the epoch starts just after, chosen far below the peak so that returning the peak is
/// unmistakably wrong rather than a rounding difference.
const EPOCH_START_HEIGHT: u32 = 1_000_000;

/// The timestamp the honest majority of the pool reports for `height`.
fn canonical_timestamp(height: u32) -> u64 {
    GENESIS + u64::from(height) * SPACING
}

/// The epoch begins one second after the block at `EPOCH_START_HEIGHT`, so that height is below the
/// epoch and the next one is the first at or after it.
fn epoch_start() -> u64 {
    canonical_timestamp(EPOCH_START_HEIGHT) + 1
}

/// A chain whose peak height is answered from two different views.
///
/// The first read of `PEAK` is answered by a peer on the canonical chain; every later read of that
/// same height is answered by a peer on a shorter fork, whose block at that height predates the
/// epoch. Every other height is answered canonically by both, so nothing but the disagreement at
/// the peak distinguishes this source from an honest one.
struct ForkedPeakChain {
    /// Reads of `PEAK` specifically — the disagreement is confined to that height.
    peak_reads: Cell<u64>,
    /// Every `block_timestamp` call, so the fixture stays observable.
    reads: Cell<u64>,
}

impl ForkedPeakChain {
    fn new() -> Self {
        Self {
            peak_reads: Cell::new(0),
            reads: Cell::new(0),
        }
    }
}

#[derive(Debug)]
struct NeverFails;

impl std::fmt::Display for NeverFails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this fixture never fails a read")
    }
}

impl std::error::Error for NeverFails {}

impl ChainSource for ForkedPeakChain {
    type Error = NeverFails;

    fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        unreachable!("this fixture answers only peak height and block timestamps")
    }

    fn coin_records_by_puzzle_hash(
        &self,
        _puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        unreachable!("this fixture answers only peak height and block timestamps")
    }

    fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        unreachable!("this fixture answers only peak height and block timestamps")
    }

    fn coin_spend(&self, _coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        unreachable!("this fixture answers only peak height and block timestamps")
    }

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        unreachable!("this fixture answers only peak height and block timestamps")
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(Some(PEAK))
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.reads.set(self.reads.get() + 1);

        // Above the peak the pool has nothing to offer, which is what sends a probe of `peak + 1`
        // walking back down onto the peak block itself.
        if height > PEAK {
            return Ok(None);
        }

        if height == PEAK {
            let seen = self.peak_reads.get();
            self.peak_reads.set(seen + 1);
            if seen > 0 {
                // The shorter fork's block at this height, which predates the epoch.
                return Ok(Some(canonical_timestamp(EPOCH_START_HEIGHT - 1)));
            }
        }

        Ok(Some(canonical_timestamp(height)))
    }
}

/// A seed equal to the peak must not be able to bound the search above the peak.
#[test]
fn a_seed_equal_to_the_peak_cannot_return_the_peak_block() {
    let start = epoch_start();

    // Fixture guards. Without these an assertion below could hold because the disagreement never
    // happened, rather than because the search survived it.
    let probe = ForkedPeakChain::new();
    assert!(
        matches!(probe.block_timestamp(PEAK), Ok(Some(t)) if t == canonical_timestamp(PEAK)),
        "the first read of the peak must come from the canonical view"
    );
    assert!(
        canonical_timestamp(PEAK) >= start,
        "the canonical peak must lie at or after the epoch start, or the search returns None"
    );
    let forked = probe
        .block_timestamp(PEAK)
        .expect("the fixture never fails a read")
        .expect("the forked view answers this height");
    assert!(
        forked < start,
        "the second read of the peak must lie below the epoch start, or the seed is rejected \
         and the bracket never breaks"
    );
    assert!(
        matches!(probe.block_timestamp(PEAK + 1), Ok(None)),
        "the pool must have no block above the peak, or a probe above it would not walk down"
    );

    let unseeded_chain = ForkedPeakChain::new();
    let expected = census_height(&unseeded_chain, start)
        .expect("the unseeded search answers this chain")
        .expect("the epoch is reachable on this chain");
    assert_eq!(
        unseeded_chain.peak_reads.get(),
        1,
        "the unseeded search must read the peak exactly once, or it too sees the disagreement \
         and the comparison below is between two wrong answers"
    );
    assert!(
        expected.height < PEAK,
        "the census height must lie below the peak, or returning the peak would be correct"
    );

    let seeded_chain = ForkedPeakChain::new();
    let actual = census_height_seeded(&seeded_chain, start, Some(PEAK))
        .expect("a seed equal to the peak must not fail the search")
        .expect("the epoch is reachable on this chain");

    assert_ne!(
        actual.height, PEAK,
        "the seeded search bounded itself above the peak and returned the peak block as the \
         census height"
    );
    assert_eq!(
        actual, expected,
        "the seeded search returned a different height than the unseeded one on the same source"
    );
}
