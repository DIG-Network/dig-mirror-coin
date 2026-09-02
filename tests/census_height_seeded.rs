//! The seeded census-height search: it must look in fewer places, and find the same block.
//!
//! A census height is a consensus value — every node derives the epoch's collateral requirement
//! from the census taken at it, so two nodes that disagree by one block derive different money.
//! That makes the interesting property of a *faster* search not its speed but its **agreement**:
//! the seed is allowed to change where the search looks and is never allowed to change what it
//! returns. The equivalence test below is therefore the load-bearing one here, and the read-budget
//! test is the reason the change exists at all.
//!
//! The chains are generated rather than tabulated. A tabulated chain cannot reach the peaks that
//! matter — the defect being fixed is that per-epoch cost grows with chain height, and it is only
//! visible across peaks differing by an order of magnitude.

use std::cell::Cell;

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_mirror_coin::{census_height, census_height_seeded};

/// Genesis instant of every generated chain. Arbitrary, but pinned: a chain whose timestamps are
/// derived from the wall clock would make every assertion here depend on when it ran.
const GENESIS: u64 = 1_600_000_000;

/// A deterministic mainnet-shaped chain, computed rather than stored.
///
/// Chia's real shape is what matters to the search: timestamps rise monotonically, and only
/// *transaction* blocks carry one at all. Both are reproduced here. `spacing` is the mean seconds
/// per block and `tx_percent` the share of heights that are transaction blocks; jitter is bounded
/// strictly below `spacing` so timestamps stay strictly increasing, which is the property the
/// search's monotone predicate rests on.
struct GeneratedChain {
    peak: u32,
    spacing: u64,
    tx_percent: u32,
    salt: u64,
    /// Every `block_timestamp` call this source has answered, of any kind.
    reads: Cell<u64>,
}

/// SplitMix64. Used only to shape a fixture; it needs to be reproducible, not unpredictable.
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl GeneratedChain {
    fn new(peak: u32, spacing: u64, tx_percent: u32, salt: u64) -> Self {
        Self {
            peak,
            spacing,
            tx_percent,
            salt,
            reads: Cell::new(0),
        }
    }

    /// The timestamp of `height`, or `None` where the height is a non-transaction block.
    ///
    /// Height 0 always carries one so that every chain has a floor the walk-down can terminate on.
    fn timestamp_of(&self, height: u32) -> Option<u64> {
        let noise = mix(u64::from(height) ^ self.salt);
        if height != 0 && (noise % 100) as u32 >= self.tx_percent {
            return None;
        }
        let jitter = noise % (self.spacing - 1);
        Some(GENESIS + u64::from(height) * self.spacing + jitter)
    }

    fn peak_timestamp(&self) -> u64 {
        let mut height = self.peak;
        loop {
            if let Some(timestamp) = self.timestamp_of(height) {
                return timestamp;
            }
            height -= 1;
        }
    }

    fn take_reads(&self) -> u64 {
        let count = self.reads.get();
        self.reads.set(0);
        count
    }
}

#[derive(Debug)]
struct Unsupported;

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("this fixture answers only peak height and block timestamps")
    }
}

impl std::error::Error for Unsupported {}

impl ChainSource for GeneratedChain {
    type Error = Unsupported;

    fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Err(Unsupported)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        _puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(Unsupported)
    }

    fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(Unsupported)
    }

    fn coin_spend(&self, _coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        Err(Unsupported)
    }

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Err(Unsupported)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(Some(self.peak))
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.timestamp_of(height))
    }
}

/// The instants at which each of `count` consecutive epochs begins, spread across the chain.
fn epoch_starts(chain: &GeneratedChain, count: u32) -> Vec<u64> {
    let span = chain.peak_timestamp() - GENESIS;
    let epoch = span / u64::from(count + 1);
    (1..=count).map(|n| GENESIS + epoch * u64::from(n)).collect()
}

/// The shapes worth covering: dense and sparse transaction blocks, fast and slow chains.
fn chain_shapes(peak: u32) -> Vec<GeneratedChain> {
    vec![
        GeneratedChain::new(peak, 18, 50, 0x1111),
        GeneratedChain::new(peak, 12, 30, 0x2222),
        GeneratedChain::new(peak, 30, 70, 0x3333),
        GeneratedChain::new(peak, 52, 45, 0x4444),
    ]
}

/// **The consensus property.** A seed changes where the search looks, never what it returns.
///
/// Run over four chain shapes and three peaks spanning two orders of magnitude, walking epochs the
/// way a cold-starting node does: each epoch seeded with the height the previous epoch resolved to.
/// Any disagreement with the unseeded search is a fork in the making, so the assertion is equality
/// of the whole `CensusHeight`, not merely of the height.
#[test]
fn seeded_and_unseeded_searches_agree_on_every_epoch_of_every_chain() {
    let mut compared = 0u32;

    for peak in [200_000u32, 2_300_000, 9_200_000] {
        for chain in chain_shapes(peak) {
            let mut seed: Option<u32> = None;

            for start in epoch_starts(&chain, 103) {
                let expected = census_height(&chain, start).expect("unseeded search answers");
                let actual =
                    census_height_seeded(&chain, start, seed).expect("seeded search answers");

                assert_eq!(
                    actual, expected,
                    "seeded search disagreed at epoch start {start} on a chain of \
                     spacing {} tx% {} peak {peak}",
                    chain.spacing, chain.tx_percent
                );

                assert!(expected.is_some(), "epoch {start} should be reachable");
                seed = actual.map(|found| found.height);
                compared += 1;
            }
        }
    }

    // A guard on the fixture itself: an empty or short loop would satisfy every assertion above.
    assert_eq!(compared, 3 * 4 * 103);
}

/// Walks `count` epochs seeded, returning total `block_timestamp` reads.
fn seeded_reads(chain: &GeneratedChain, count: u32) -> u64 {
    chain.take_reads();
    let mut seed = None;
    for start in epoch_starts(chain, count) {
        seed = census_height_seeded(chain, start, seed)
            .expect("seeded search answers")
            .map(|found| found.height);
    }
    chain.take_reads()
}

/// Walks `count` epochs unseeded, returning total `block_timestamp` reads.
fn unseeded_reads(chain: &GeneratedChain, count: u32) -> u64 {
    chain.take_reads();
    for start in epoch_starts(chain, count) {
        census_height(chain, start).expect("unseeded search answers");
    }
    chain.take_reads()
}

/// **The reason the change exists.** Seeded cost per epoch must not grow with the chain.
///
/// The peak is multiplied by four and then by sixteen. The unseeded search pays `O(log peak)` per
/// epoch, so its per-epoch cost must visibly rise across that range; the seeded search's must not.
/// The budget is asserted as a count of reads, never as elapsed time — a wall-clock assertion here
/// would measure the machine rather than the algorithm.
#[test]
fn seeded_reads_per_epoch_do_not_grow_with_the_chain() {
    const EPOCHS: u32 = 103;
    // Simulation puts the seeded search at ~9-11 reads per epoch. The budget sits above the observed
    // figure but far below the unseeded ~44, so it fails on a regression to bisection while
    // tolerating the jitter of a differently-shaped chain.
    const BUDGET: u64 = 16;

    let base = 575_000u32;
    let mut seeded_per_epoch = Vec::new();
    let mut unseeded_per_epoch = Vec::new();

    for multiple in [1u32, 4, 16] {
        let chain = GeneratedChain::new(base * multiple, 18, 50, 0x5EED);

        let seeded = seeded_reads(&chain, EPOCHS) / u64::from(EPOCHS);
        let unseeded = unseeded_reads(&chain, EPOCHS) / u64::from(EPOCHS);

        assert!(
            seeded <= BUDGET,
            "seeded search spent {seeded} reads per epoch at peak {} (budget {BUDGET})",
            chain.peak
        );

        seeded_per_epoch.push(seeded);
        unseeded_per_epoch.push(unseeded);
    }

    assert!(
        seeded_per_epoch[2] <= seeded_per_epoch[0] + 1,
        "seeded per-epoch cost grew with the chain: {seeded_per_epoch:?}"
    );
    assert!(
        unseeded_per_epoch[2] >= unseeded_per_epoch[0] + 4,
        "the unseeded search was expected to grow with the chain; it did not: \
         {unseeded_per_epoch:?} — the fixture, not the fix, is suspect"
    );
    assert!(
        seeded_per_epoch[2] * 3 < unseeded_per_epoch[2],
        "seeded {seeded_per_epoch:?} vs unseeded {unseeded_per_epoch:?}"
    );
}

/// **A hostile seed must fail closed**, and the hostile seed is a real path rather than a
/// hypothesis.
///
/// dig-node persists a census height that can originate from a sampled peer cohort, and its guards
/// bound that height only from *below* — nothing but cohort agreement bounds it from above. So a
/// sufficiently large hostile cohort can plant an inflated height in a node's store, and the next
/// epoch's walk would offer it here as a seed. Believed, the search would begin above the answer,
/// never see it, and return a height no other node computes: a fork on the money path.
///
/// The check that stops it is reading the seed height's own timestamp from the source and requiring
/// it strictly below the epoch start. An honest seed is the *previous* epoch's census height, so its
/// timestamp sits a full epoch below this instant and passes with an enormous margin; only an
/// inflated one fails. The three seeds below are each rejected, and each must still produce exactly
/// the unseeded answer.
#[test]
fn a_seed_above_the_true_height_is_discarded_and_the_correct_height_still_returned() {
    let chain = GeneratedChain::new(2_300_000, 18, 50, 0xBAD5);

    for start in epoch_starts(&chain, 17) {
        let truth = census_height(&chain, start)
            .expect("unseeded search answers")
            .expect("the epoch has begun");

        // The planted-by-a-cohort case: a height well above the true one, whose block was mined
        // after the epoch began. This is the seed that would silently move the census.
        assert_eq!(
            census_height_seeded(&chain, start, Some(truth.height + 40_000)),
            Ok(Some(truth)),
            "a seed above the true height changed the answer at {start}"
        );

        // One block above the answer — the smallest inflation that still changes the census, and
        // the one a bound checked loosely would wave through.
        assert_eq!(
            census_height_seeded(&chain, start, Some(truth.height + 1)),
            Ok(Some(truth)),
            "a seed one block above the true height changed the answer at {start}"
        );

        // A seed above the peak entirely: nothing about the chain corroborates it.
        assert_eq!(
            census_height_seeded(&chain, start, Some(chain.peak + 1)),
            Ok(Some(truth)),
            "a seed beyond the peak changed the answer at {start}"
        );
    }
}

/// A seed at the answer is common and benign at the chain's edge: the previous epoch's census
/// height equals this one's when the chain has not moved between them. It fails the strictly-below
/// check and is discarded, which is the correct outcome — it is not a valid *lower* bound.
#[test]
fn a_seed_equal_to_the_answer_is_not_used_as_a_bound() {
    let chain = GeneratedChain::new(400_000, 18, 50, 0x0FF0);
    let start = epoch_starts(&chain, 7)[3];
    let truth = census_height(&chain, start).unwrap().unwrap();

    assert_eq!(
        census_height_seeded(&chain, start, Some(truth.height)),
        Ok(Some(truth))
    );
}

/// An epoch the chain has not reached is `None` seeded or not — a real answer, not an error.
#[test]
fn a_future_epoch_answers_none_with_a_seed_as_without_one() {
    let chain = GeneratedChain::new(100_000, 18, 50, 0xFEED);
    let future = chain.peak_timestamp() + 10_000;
    let seed = census_height(&chain, GENESIS + 1_000)
        .unwrap()
        .map(|found| found.height);

    assert_eq!(census_height_seeded(&chain, future, seed), Ok(None));
    assert_eq!(census_height(&chain, future), Ok(None));
}
