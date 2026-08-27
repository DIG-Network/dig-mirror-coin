//! Behavioural tests for the census — the chain read the collateral recurrence consumes.
//!
//! Every coin here is created by a genuine CAT spend, for the same reason the query tests are: the
//! census authenticates coins by executing their creating spend, and a hand-written struct cannot
//! exhibit the property being tested.
//!
//! # Every fixture keeps an honest control
//!
//! Most of these tests are about a coin being **excluded**, and "excluded" is easy to assert
//! vacuously: a census of one hostile coin reports zero, and so does a census that dropped every
//! coin for the wrong reason, and so does a census whose rule sits at the wrong layer. So the
//! hostile fixtures vary exactly one actor and keep a qualifying coin beside it. The assertions then
//! pin the survivor as well as the exclusion, and a rule that over-reaches fails just as loudly as
//! one that under-reaches.

mod support;

use std::collections::HashMap;

use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use dig_chainsource_interface::{ChainSource, ChainSourceError, CoinRecord, SingletonLineage};
use dig_mirror_coin::{
    census, census_height, mirror_coin_puzzle_hash, CensusOutcome, MirrorCensus, MirrorError,
};
use dig_mirror_collateral::{EpochCensus, EpochRecord, CENSUS_FINALITY_DEPTH_BLOCKS};
use num_bigint::BigInt;
use support::{
    creating_spend_of_amount, declared_memos, epoch, hint_of, mirror_memos, root_1, root_2,
    store_a, store_b, wallet, Wallet,
};

/// The height every census in this file is taken at.
const CENSUS_AT: u32 = 1_000;

/// The requirement coins are qualified against. Chosen so [`AT_REQUIREMENT`] sits exactly on it and
/// [`BELOW_REQUIREMENT`] sits exactly one DIG CAT base unit under, which is what makes the bound
/// testable from
/// both sides rather than only from the side that happens to pass.
const REQUIREMENT: u64 = 1_000_000;
const AT_REQUIREMENT: u64 = REQUIREMENT;
const BELOW_REQUIREMENT: u64 = REQUIREMENT - 1;
const ABOVE_REQUIREMENT: u64 = REQUIREMENT + 500;

/// The record for the epoch a census qualifies against — epoch 42, the one `support::epoch()`
/// builds coins for. The census it produces therefore describes epoch 43.
///
/// Built field by field rather than by running the controller forward, so the C5 threshold this
/// suite pins is the literal above and not whatever the recurrence happens to produce today. A test
/// that reads its own threshold out of the code under test cannot fail when that threshold moves.
fn prior_record() -> EpochRecord {
    EpochRecord {
        epoch: 42,
        census: EpochCensus {
            epoch: 42,
            stores: 0,
            owners: 0,
            locked: 0,
        },
        signals: None,
        band: None,
        multiplier_micros: 1_000_000,
        handicap_mojos: 0,
        base_mojos: REQUIREMENT,
        required_per_store_mojos: REQUIREMENT,
    }
}

fn at(height: u32) -> dig_mirror_coin::CensusHeight {
    dig_mirror_coin::CensusHeight {
        height,
        timestamp: 1_700_000_000,
    }
}

/// A chain whose every coin carries its own confirmation and spend heights, and whose timestamps
/// are sparse.
///
/// Both of those matter. A double that stamps one height on every coin cannot express "created
/// after the census height" beside "created before" in one fixture, and a double that answers a
/// timestamp for every height cannot express a non-transaction block at all — so neither could
/// witness the rules those cases exist to test.
#[derive(Default)]
struct CensusChain {
    coins: Vec<CoinRecord>,
    creating_spends: HashMap<Bytes32, CoinSpend>,
    timestamps: HashMap<u32, u64>,
    peak: Option<u32>,
    spend_read_fails_for: Option<Bytes32>,
}

impl CensusChain {
    fn new() -> Self {
        Self {
            peak: Some(CENSUS_AT + CENSUS_FINALITY_DEPTH_BLOCKS as u32),
            ..Self::default()
        }
    }

    /// Records a coin at the shared mirror puzzle hash, confirmed at `confirmed` and spent at
    /// `spent`, with its creating spend available.
    fn publish(&mut self, spend: CoinSpend, coin: Coin, confirmed: u32, spent: Option<u32>) {
        self.coins.push(CoinRecord {
            coin,
            confirmed_height: Some(confirmed),
            spent_height: spent,
            timestamp: None,
            coinbase: false,
        });
        self.creating_spends.insert(spend.coin.coin_id(), spend);
    }

    /// A coin whose creating spend is absent — a stranger's dust sitting at the shared puzzle hash.
    fn publish_without_creating_spend(&mut self, coin: Coin) {
        self.coins.push(CoinRecord {
            coin,
            confirmed_height: Some(1),
            spent_height: None,
            timestamp: None,
            coinbase: false,
        });
    }
}

impl ChainSource for CensusChain {
    type Error = ChainSourceError;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Ok(self
            .coins
            .iter()
            .find(|record| record.coin.coin_id() == coin_id)
            .cloned())
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        // The flag is HONOURED rather than ignored, so a census that asked for unspent coins only
        // would genuinely lose the coins spent after its census height — which is the failure the
        // spend-height tests below exist to catch.
        Ok(self
            .coins
            .iter()
            .filter(|record| record.coin.puzzle_hash == puzzle_hash)
            .filter(|record| include_spent || !record.is_spent())
            .cloned()
            .collect())
    }

    fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(ChainSourceError::Unsupported("coin_records_by_parent"))
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        if self.spend_read_fails_for == Some(coin_id) {
            return Err(ChainSourceError::Timeout);
        }
        Ok(self.creating_spends.get(&coin_id).cloned())
    }

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Err(ChainSourceError::Unsupported("resolve_singleton_lineage"))
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(self.peak)
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(self.timestamps.get(&height).copied())
    }
}

/// Publishes an honest, fully qualifying mirror coin. Present in almost every fixture as the
/// control the hostile coin is measured against.
fn publish_qualifying(
    chain: &mut CensusChain,
    owner: &Wallet,
    store: Bytes32,
    root: Bytes32,
    amount: u64,
) -> Coin {
    let memos = mirror_memos(owner, store, root, &["https://mirror.example"]);
    let (spend, coin) = creating_spend_of_amount(owner, &memos, amount);
    chain.publish(spend, coin, CENSUS_AT - 10, None);
    coin
}

fn take_final(outcome: CensusOutcome) -> MirrorCensus {
    match outcome {
        CensusOutcome::Final(census) => *census,
        CensusOutcome::Pending {
            census_height,
            peak_height,
        } => panic!(
            "expected a final census; got Pending at {census_height} with peak {peak_height}"
        ),
    }
}

fn run(chain: &CensusChain) -> MirrorCensus {
    take_final(census(chain, &prior_record(), at(CENSUS_AT)).expect("the census must complete"))
}

// ---------------------------------------------------------------------------
// The census height
// ---------------------------------------------------------------------------

/// A chain whose transaction blocks sit at every EVEN height up to its peak of 105, so the odd
/// heights carry no timestamp at all — the shape a real chain has, and the one a dense double
/// cannot produce.
///
/// The blocks below 100 are ordinary history rather than padding. A fixture that began at 100 with
/// nothing beneath it would be a chain whose first hundred blocks are all non-transaction blocks,
/// which is not a chain the census can safely reason about — and refusing that is a property the
/// timestamp guard has its own test for.
fn sparse_chain() -> CensusChain {
    let mut chain = CensusChain::new();
    for height in (0..=98).step_by(2) {
        chain
            .timestamps
            .insert(height, 1_000 - u64::from(100 - height) / 2 * 10);
    }
    chain.timestamps.insert(100, 1_000);
    chain.timestamps.insert(102, 1_100);
    chain.timestamps.insert(104, 1_200);
    chain.peak = Some(105);
    chain
}

#[test]
fn the_census_height_is_the_first_transaction_block_at_or_after_the_epoch_start() {
    let found = census_height(&sparse_chain(), 1_100)
        .expect("the search must answer")
        .expect("the chain has reached this epoch");

    assert_eq!(found.height, 102);
    assert_eq!(found.timestamp, 1_100);
}

/// The bound from the other side. A start one second later cannot be served by block 102, so the
/// answer must move on to the next transaction block — 104, never 103.
#[test]
fn one_second_past_a_blocks_timestamp_moves_the_census_height_to_the_next_transaction_block() {
    let found = census_height(&sparse_chain(), 1_101)
        .expect("the search must answer")
        .expect("the chain has reached this epoch");

    assert_eq!(found.height, 104);
}

/// A non-transaction block is skipped entirely: it is never a candidate, and it never becomes the
/// census height by being the first height at or after the epoch start.
#[test]
fn a_non_transaction_block_is_never_chosen_as_the_census_height() {
    let found = census_height(&sparse_chain(), 1_050)
        .expect("the search must answer")
        .expect("the chain has reached this epoch");

    assert_eq!(
        found.height, 102,
        "101 has no timestamp, so it is not a block a census can be taken at"
    );
}

#[test]
fn an_epoch_the_chain_has_not_reached_is_an_answer_and_not_an_error() {
    let found =
        census_height(&sparse_chain(), 9_999).expect("this is a real answer, not a failure");

    assert!(found.is_none());
}

/// A source answering no timestamps at all is not a chain without blocks. Guessing a census height
/// is a fork, so the read is reported as unanswerable.
#[test]
fn a_source_that_answers_no_timestamps_is_unanswerable_rather_than_guessed() {
    let mut chain = CensusChain::new();
    chain.peak = Some(500);

    let error = census_height(&chain, 1_000).expect_err("a guessed census height is a fork");

    assert!(matches!(error, MirrorError::ChainUnavailable(_)));
}

#[test]
fn a_source_exposing_no_peak_cannot_establish_a_census_height() {
    let mut chain = sparse_chain();
    chain.peak = None;

    let error =
        census_height(&chain, 1_000).expect_err("without a peak there is nothing to search");

    assert!(matches!(error, MirrorError::ChainUnavailable(_)));
}

// ---------------------------------------------------------------------------
// Finality
// ---------------------------------------------------------------------------

#[test]
fn a_census_one_block_short_of_the_finality_depth_is_pending() {
    let mut chain = CensusChain::new();
    chain.peak = Some(CENSUS_AT + CENSUS_FINALITY_DEPTH_BLOCKS as u32 - 1);
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let outcome = census(&chain, &prior_record(), at(CENSUS_AT)).expect("the read must answer");

    assert!(
        matches!(outcome, CensusOutcome::Pending { .. }),
        "a census this close to the tip is reorg-sensitive and must not be acted on"
    );
}

/// The bound from the other side: exactly at the depth, the census is final. Without this the
/// pending test alone is satisfied by a census that is never final at all.
#[test]
fn a_census_exactly_at_the_finality_depth_is_final() {
    let mut chain = CensusChain::new();
    chain.peak = Some(CENSUS_AT + CENSUS_FINALITY_DEPTH_BLOCKS as u32);
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
}

// ---------------------------------------------------------------------------
// The three outputs
// ---------------------------------------------------------------------------

#[test]
fn a_qualifying_coin_is_one_store_one_owner_and_its_full_amount_locked() {
    let mut chain = CensusChain::new();
    publish_qualifying(
        &mut chain,
        &wallet(1),
        store_a(),
        root_1(),
        ABOVE_REQUIREMENT,
    );

    let census = run(&chain);

    assert_eq!(
        census.census().epoch,
        43,
        "the census describes the epoch AFTER the record it qualified against"
    );
    assert_eq!(census.census().stores, 1);
    assert_eq!(census.census().owners, 1);
    assert_eq!(census.census().locked, ABOVE_REQUIREMENT);
}

#[test]
fn one_owner_advertising_two_roots_of_one_store_is_two_stores_and_one_owner() {
    let mut chain = CensusChain::new();
    let owner = wallet(1);
    publish_qualifying(&mut chain, &owner, store_a(), root_1(), AT_REQUIREMENT);
    publish_qualifying(&mut chain, &owner, store_a(), root_2(), ABOVE_REQUIREMENT);

    let census = run(&chain);

    assert_eq!(
        census.census().stores,
        2,
        "each root is paid for in full and counts in full"
    );
    assert_eq!(
        census.census().owners,
        1,
        "one owner hash, however many advertisements"
    );
    assert_eq!(census.census().locked, AT_REQUIREMENT + ABOVE_REQUIREMENT);
}

#[test]
fn two_owners_advertising_the_same_store_are_two_stores_and_two_owners() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);
    publish_qualifying(&mut chain, &wallet(2), store_a(), root_1(), AT_REQUIREMENT);

    let census = run(&chain);

    assert_eq!(census.census().stores, 2);
    assert_eq!(census.census().owners, 2);
}

/// The counted unit is the triple, never a coin. Two coins backing one advertisement are one
/// advertisement, and only the larger enters `locked` — otherwise splitting a stake inflates every
/// signal it feeds.
#[test]
fn two_coins_for_one_triple_count_once_and_only_the_larger_is_locked() {
    let mut chain = CensusChain::new();
    let owner = wallet(1);
    publish_qualifying(&mut chain, &owner, store_a(), root_1(), AT_REQUIREMENT);
    publish_qualifying(&mut chain, &owner, store_a(), root_1(), ABOVE_REQUIREMENT);

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(census.census().owners, 1);
    assert_eq!(census.census().locked, ABOVE_REQUIREMENT);
    assert_eq!(census.excluded().superseded, 1);
}

/// The same pair in the opposite publication order. A selection that simply kept the last coin
/// seen would pass the test above and fail this one.
#[test]
fn the_larger_coin_wins_a_triple_whichever_order_the_chain_returns_them_in() {
    let mut chain = CensusChain::new();
    let owner = wallet(1);
    publish_qualifying(&mut chain, &owner, store_a(), root_1(), ABOVE_REQUIREMENT);
    publish_qualifying(&mut chain, &owner, store_a(), root_1(), AT_REQUIREMENT);

    assert_eq!(run(&chain).census().locked, ABOVE_REQUIREMENT);
}

// ---------------------------------------------------------------------------
// C5 — the anti-spam rule, from both sides
// ---------------------------------------------------------------------------

/// An under-collateralised coin is **invisible**, not partially counted and not evidence of
/// hardship. The honest coin beside it is the control: a rule that over-reached and dropped both
/// would report zero stores, which is exactly what a rule that silently counted the dust in the
/// denominator also cannot be distinguished from without it.
#[test]
fn a_coin_below_the_requirement_contributes_to_nothing_while_an_honest_one_still_counts() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);
    publish_qualifying(
        &mut chain,
        &wallet(2),
        store_b(),
        root_1(),
        BELOW_REQUIREMENT,
    );

    let census = run(&chain);

    assert_eq!(census.census().stores, 1, "the dust coin is not a store");
    assert_eq!(
        census.census().owners,
        1,
        "and its owner is not a collateralised owner"
    );
    assert_eq!(
        census.census().locked,
        AT_REQUIREMENT,
        "and its collateral is not locked collateral"
    );
    assert_eq!(census.excluded().under_collateralised, 1);
}

/// The bound from the passing side. `BELOW_REQUIREMENT` is one base unit under and
/// `AT_REQUIREMENT` is exactly on it, so a comparison that drifted by one in either direction
/// fails one of this pair.
#[test]
fn a_coin_exactly_at_the_requirement_qualifies() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    assert_eq!(run(&chain).census().stores, 1);
    assert_eq!(run(&chain).excluded().under_collateralised, 0);
}

/// A flood of dust cannot move any of the three outputs. This is the attack C5 exists to stop,
/// stated as a property rather than as a single coin.
#[test]
fn flooding_dust_coins_moves_none_of_the_three_outputs() {
    let mut honest_only = CensusChain::new();
    publish_qualifying(
        &mut honest_only,
        &wallet(1),
        store_a(),
        root_1(),
        AT_REQUIREMENT,
    );
    let baseline = run(&honest_only).census();

    let mut flooded = CensusChain::new();
    publish_qualifying(
        &mut flooded,
        &wallet(1),
        store_a(),
        root_1(),
        AT_REQUIREMENT,
    );
    for seed in 10..40u8 {
        publish_qualifying(
            &mut flooded,
            &wallet(seed),
            store_b(),
            root_2(),
            BELOW_REQUIREMENT,
        );
    }

    assert_eq!(run(&flooded).census(), baseline);
}

// ---------------------------------------------------------------------------
// C2, C3 — the census height is a cut through time
// ---------------------------------------------------------------------------

#[test]
fn a_coin_created_after_the_census_height_is_not_yet_part_of_the_network() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let memos = mirror_memos(&wallet(2), store_b(), root_1(), &["https://later.example"]);
    let (spend, coin) = creating_spend_of_amount(&wallet(2), &memos, ABOVE_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT + 1, None);

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(census.excluded().not_yet_created, 1);
}

/// Created exactly AT the census height, which is inside the cut. Pairs with the test above so a
/// comparison that drifted by one block fails one of them.
#[test]
fn a_coin_created_exactly_at_the_census_height_counts() {
    let mut chain = CensusChain::new();
    let owner = wallet(1);
    let memos = mirror_memos(&owner, store_a(), root_1(), &["https://mirror.example"]);
    let (spend, coin) = creating_spend_of_amount(&owner, &memos, AT_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT, None);

    assert_eq!(run(&chain).census().stores, 1);
}

#[test]
fn a_coin_spent_at_the_census_height_is_no_longer_locked() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let memos = mirror_memos(&wallet(2), store_b(), root_1(), &["https://gone.example"]);
    let (spend, coin) = creating_spend_of_amount(&wallet(2), &memos, ABOVE_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT - 5, Some(CENSUS_AT));

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(census.excluded().spent_by_census_height, 1);
}

/// Spent one block AFTER the cut, so it was still locked at the height being counted. The other
/// side of the same bound — and the test that fails if the population read ever stops asking for
/// spent coins.
#[test]
fn a_coin_spent_after_the_census_height_was_still_locked_at_it() {
    let mut chain = CensusChain::new();
    let owner = wallet(1);
    let memos = mirror_memos(&owner, store_a(), root_1(), &["https://mirror.example"]);
    let (spend, coin) = creating_spend_of_amount(&owner, &memos, AT_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT - 5, Some(CENSUS_AT + 1));

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(census.census().locked, AT_REQUIREMENT);
    assert_eq!(census.excluded().spent_by_census_height, 0);
}

#[test]
fn a_coin_the_source_cannot_place_in_time_is_excluded_rather_than_assumed() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let memos = mirror_memos(
        &wallet(2),
        store_b(),
        root_1(),
        &["https://undated.example"],
    );
    let (spend, coin) = creating_spend_of_amount(&wallet(2), &memos, ABOVE_REQUIREMENT);
    chain.coins.push(CoinRecord {
        coin,
        confirmed_height: None,
        spent_height: None,
        timestamp: None,
        coinbase: false,
    });
    chain.creating_spends.insert(spend.coin.coin_id(), spend);

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(census.excluded().undated, 1);
}

// ---------------------------------------------------------------------------
// C4 — the declared epoch
// ---------------------------------------------------------------------------

#[test]
fn a_coin_declaring_a_different_epoch_is_excluded_from_all_three_outputs() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let stale = wallet(2);
    let stale_epoch = epoch() - 1;
    let memos = declared_memos(
        support::mirror_hint_for(&stale, store_b(), root_1(), &stale_epoch),
        store_b(),
        root_1(),
        &stale_epoch,
        &["https://stale.example"],
    );
    let (spend, coin) = creating_spend_of_amount(&stale, &memos, ABOVE_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT - 10, None);

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(
        census.census().locked,
        AT_REQUIREMENT,
        "a stale coin's collateral is not this epoch's"
    );
    assert_eq!(census.excluded().wrong_epoch, 1);
}

/// A coin posted for a FUTURE epoch is excluded by the same rule. Stated separately because
/// pre-posting to manufacture a signal is a different attack from a stale coin padding one, and a
/// rule written as "at most `n-1`" would stop only the second.
#[test]
fn a_coin_posted_for_a_future_epoch_is_excluded_too() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let early = wallet(2);
    let future = epoch() + 1;
    let memos = declared_memos(
        support::mirror_hint_for(&early, store_b(), root_1(), &future),
        store_b(),
        root_1(),
        &future,
        &["https://early.example"],
    );
    let (spend, coin) = creating_spend_of_amount(&early, &memos, ABOVE_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT - 10, None);

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(census.excluded().wrong_epoch, 1);
}

// ---------------------------------------------------------------------------
// C8 — attribution is proven, never guessed
// ---------------------------------------------------------------------------

/// A coin that declares an advertisement it was not published under. Its owner is perfectly
/// readable from its lineage proof, and it is still excluded: attributing it would let anybody
/// inflate the owner count for the price of a coin, which is what suppresses the handicap.
#[test]
fn a_coin_whose_declaration_does_not_reproduce_its_hint_is_excluded() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let liar = wallet(2);
    let memos = declared_memos(
        hint_of(&liar, store_a(), root_1()),
        store_b(),
        root_2(),
        &epoch(),
        &["https://squatting.example"],
    );
    let (spend, coin) = creating_spend_of_amount(&liar, &memos, ABOVE_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT - 10, None);

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(
        census.census().owners,
        1,
        "an unattributable coin never becomes an owner"
    );
    assert_eq!(census.excluded().unattributed, 1);
}

/// The same coin's owner is NOT taken from a memo. This fixture claims a stranger's puzzle hash as
/// the owner in the store slot of an otherwise consistent declaration; the census must attribute by
/// lineage proof, so the claim buys nothing.
#[test]
fn attribution_follows_the_lineage_proof_and_not_the_declaration() {
    let mut chain = CensusChain::new();
    let real = wallet(1);
    let stranger = wallet(9);
    publish_qualifying(&mut chain, &real, store_a(), root_1(), AT_REQUIREMENT);

    // Declared consistently, so the hint check passes — the only question left is WHOSE coin it is.
    let memos = mirror_memos(
        &real,
        stranger.puzzle_hash,
        root_2(),
        &["https://claimed.example"],
    );
    let (spend, coin) = creating_spend_of_amount(&real, &memos, ABOVE_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT - 10, None);

    let census = run(&chain);

    assert_eq!(
        census.census().owners,
        1,
        "naming a stranger in the memos does not make the network one owner larger"
    );
    assert_eq!(census.census().stores, 2);
}

// ---------------------------------------------------------------------------
// C1/C6 — unreadable coins, and the difference between an answer and its absence
// ---------------------------------------------------------------------------

#[test]
fn a_coin_with_no_creating_spend_is_excluded_and_the_census_still_completes() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);
    chain.publish_without_creating_spend(Coin::new(
        Bytes32::new([0xEE; 32]),
        mirror_coin_puzzle_hash(),
        1,
    ));

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(census.excluded().unreadable, 1);
}

#[test]
fn a_coin_with_undecodable_memos_is_excluded_and_the_census_still_completes() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let garbage = vec![Bytes::new(vec![0x01, 0x02])];
    let (spend, coin) = creating_spend_of_amount(&wallet(2), &garbage, ABOVE_REQUIREMENT);
    chain.publish(spend, coin, CENSUS_AT - 10, None);

    let census = run(&chain);

    assert_eq!(census.census().stores, 1);
    assert_eq!(census.excluded().unreadable, 1);
}

/// A source that cannot answer aborts the census. A partial census is not a smaller census: it is a
/// different number from the one every other node computes, produced silently.
#[test]
fn an_unanswerable_read_aborts_the_census_rather_than_shrinking_it() {
    let mut chain = CensusChain::new();
    let coin = publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);
    chain.spend_read_fails_for = Some(coin.parent_coin_info);

    let error = census(&chain, &prior_record(), at(CENSUS_AT))
        .expect_err("a census over part of the population is a wrong answer, not a small one");

    assert!(matches!(error, MirrorError::ChainUnavailable(_)));
}

#[test]
fn a_source_exposing_no_peak_cannot_establish_finality_and_so_cannot_census() {
    let mut chain = CensusChain::new();
    chain.peak = None;
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let error = census(&chain, &prior_record(), at(CENSUS_AT))
        .expect_err("finality cannot be established without a peak");

    assert!(matches!(error, MirrorError::ChainUnavailable(_)));
}

// ---------------------------------------------------------------------------
// The census is what the controller consumes
// ---------------------------------------------------------------------------

/// The whole point of the module: a census taken here advances the record it was qualified
/// against. If the epoch it reports were off by one, this would refuse.
#[test]
fn a_census_advances_the_record_it_was_qualified_against() {
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    let prior = prior_record();
    let next = prior
        .advance(run(&chain).census())
        .expect("the census must describe exactly the epoch after the record");

    assert_eq!(next.epoch, 43);
}

/// An epoch whose coins all failed C5 produces a census of zeros — and that is the honest input,
/// because the controller's response to a network that genuinely cannot afford the requirement is
/// to lower it. What must never happen is dust *causing* that reading, which is the test above.
#[test]
fn an_epoch_with_no_qualifying_coins_censuses_as_zero() {
    let mut chain = CensusChain::new();
    publish_qualifying(
        &mut chain,
        &wallet(1),
        store_a(),
        root_1(),
        BELOW_REQUIREMENT,
    );

    let census = run(&chain);

    assert_eq!(census.census().stores, 0);
    assert_eq!(census.census().owners, 0);
    assert_eq!(census.census().locked, 0);
    assert_eq!(
        census.examined(),
        1,
        "examined counts what was looked at, not what qualified"
    );
}

#[test]
fn a_bigint_epoch_is_compared_against_the_records_epoch_and_not_its_length() {
    // `BigInt` epochs are encoded as signed big-endian bytes in the memos, so a comparison done on
    // the encoded bytes rather than the value would confuse 42 with a differently-encoded 42. This
    // fixture pins the honest case so that any such regression shows up as a coin vanishing.
    let mut chain = CensusChain::new();
    publish_qualifying(&mut chain, &wallet(1), store_a(), root_1(), AT_REQUIREMENT);

    assert_eq!(run(&chain).census().stores, 1);
    assert_eq!(
        epoch(),
        BigInt::from(42),
        "the fixture epoch is the record's epoch"
    );
}
