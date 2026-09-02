//! A seed the source cannot answer for must cost work, never correctness.
//!
//! `census_height_seeded` reads the seed height's own timestamp before it will trust it. That read
//! has three outcomes, not two: a timestamp, no timestamp, and **the source declining to answer**.
//! The third is not exotic. dig-node's census task drives this search from a live HTTP chain
//! source, so a single network blip on the seed probe is a routine outcome; and dig-node persists
//! the census height it computes and re-offers it as the next epoch's seed, so a seed whose
//! neighbourhood is unreadable is re-read on every wake rather than once.
//!
//! SPEC.md §8.1.1 says a hint the source cannot answer for MUST be discarded and the unhinted
//! search MUST then run, and that for every hint — valid or not — the height returned MUST equal
//! the height returned with no hint. These tests hold the search to that for both ways the seed
//! probe can decline.
//!
//! # Why the generated chains in `census_height_seeded.rs` cannot see this
//!
//! Those chains draw transaction blocks at 30-70%, which puts a run of 65 consecutive
//! non-transaction blocks — the length that exhausts the walk-down — at roughly 1e-10 per site.
//! The hole here is therefore placed by hand, at exactly the width that makes the seed probe, and
//! only the seed probe, unanswerable: 65 heights ending at the seed. A probe anywhere below the
//! seed reaches the block under the hole within the walk bound and is unaffected, so the fixture
//! isolates the seed read from every search read.

use std::cell::Cell;

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_mirror_coin::{census_height, census_height_seeded};

/// Genesis instant of the fixture chain. Pinned, so no assertion here depends on the wall clock.
const GENESIS: u64 = 1_600_000_000;
/// Seconds per block. Every height is a transaction block except inside the hole.
const SPACING: u64 = 18;
const PEAK: u32 = 1_500_000;
/// The seed a node would carry forward from the previous epoch: an honest height, below the answer,
/// which the search would use as a lower bound if it could read it.
const SEED: u32 = 900_000;
/// The walk-down bound the crate uses. A hole of `WALK_BOUND + 1` heights ending at the seed is
/// exactly wide enough to exhaust the walk from the seed and no wider.
const WALK_BOUND: u32 = 64;
const HOLE_LOW: u32 = SEED - WALK_BOUND;

/// How the source declines to answer inside the hole. These are two different code paths in the
/// crate's walk-down — an exhausted walk versus a failed read — so both are exercised.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Hole {
    /// The heights carry no transaction block. The walk-down exhausts its bound and errors.
    Silent,
    /// The source itself fails on those heights. The first read errors.
    Failing,
}

/// A chain that is uniform everywhere except for one deliberately unreadable window.
struct HolePunchedChain {
    hole: Hole,
    /// Every `block_timestamp` call, of any kind, so the fixture stays observable.
    reads: Cell<u64>,
}

impl HolePunchedChain {
    fn new(hole: Hole) -> Self {
        Self {
            hole,
            reads: Cell::new(0),
        }
    }

    fn in_hole(height: u32) -> bool {
        (HOLE_LOW..=SEED).contains(&height)
    }
}

#[derive(Debug)]
struct SourceDeclined(u32);

impl std::fmt::Display for SourceDeclined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the source declined to answer for height {}", self.0)
    }
}

impl std::error::Error for SourceDeclined {}

impl ChainSource for HolePunchedChain {
    type Error = SourceDeclined;

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
        if Self::in_hole(height) {
            return match self.hole {
                Hole::Silent => Ok(None),
                Hole::Failing => Err(SourceDeclined(height)),
            };
        }
        Ok(Some(GENESIS + u64::from(height) * SPACING))
    }
}

/// An epoch start well above the seed, so an accepted seed really would bound the search from
/// below and the hint is not idle.
fn epoch_start() -> u64 {
    GENESIS + u64::from(1_000_000u32) * SPACING + 1
}

/// The property, run for one way of declining.
///
/// Equality of the whole `CensusHeight`, not merely `is_ok`: a search that answered without failing
/// but answered *differently* is the fork this crate exists to prevent, and `is_ok` cannot see it.
fn seed_the_source_cannot_answer_for_is_discarded(hole: Hole) {
    let chain = HolePunchedChain::new(hole);
    let start = epoch_start();

    // Fixture guards. Without these, a hole that had silently moved — or a walk bound that had
    // changed — would leave both searches reading an ordinary chain and every assertion below
    // would hold for the wrong reason.
    assert!(
        HolePunchedChain::in_hole(SEED) && !HolePunchedChain::in_hole(HOLE_LOW - 1),
        "the hole must end exactly at the seed"
    );
    assert_eq!(
        SEED - HOLE_LOW + 1,
        WALK_BOUND + 1,
        "the hole must be exactly wide enough to exhaust the walk-down from the seed"
    );
    match hole {
        Hole::Silent => assert!(
            matches!(chain.block_timestamp(SEED), Ok(None)),
            "a silent hole must answer no timestamp at the seed"
        ),
        Hole::Failing => assert!(
            chain.block_timestamp(SEED).is_err(),
            "a failing hole must error at the seed"
        ),
    }
    // The block immediately under the hole is readable, which is what confines the damage to the
    // seed probe alone.
    assert!(
        matches!(chain.block_timestamp(HOLE_LOW - 1), Ok(Some(_))),
        "the block below the hole must be readable"
    );
    assert!(chain.reads.get() >= 2, "the fixture answered no reads");

    let expected = census_height(&chain, start).expect("the unseeded search answers this chain");
    let expected_height = expected
        .expect("the epoch must be reachable, or the comparison below is between two None")
        .height;
    assert!(
        expected_height > SEED,
        "the seed must sit below the answer, or accepting it would bound nothing"
    );

    let actual = census_height_seeded(&chain, start, Some(SEED)).unwrap_or_else(|error| {
        panic!("an unreadable seed failed the whole search instead of being discarded: {error}")
    });

    assert_eq!(
        actual, expected,
        "the seeded search returned a different height than the unseeded one on the same source"
    );
}

/// The seed's neighbourhood carries no transaction block, so the walk-down exhausts its bound.
#[test]
fn a_seed_whose_walk_down_exhausts_is_discarded_not_propagated() {
    seed_the_source_cannot_answer_for_is_discarded(Hole::Silent);
}

/// The source fails outright on the seed's height — the routine transient of a live HTTP read.
#[test]
fn a_seed_whose_read_fails_is_discarded_not_propagated() {
    seed_the_source_cannot_answer_for_is_discarded(Hole::Failing);
}
