//! Behavioural tests for the four verbs, built on real coin spends.
//!
//! Every mirror coin in these tests is created by a genuine CAT spend whose puzzle is executed to
//! produce its conditions — the same execution `MirrorCoin::from_creating_spend` performs. Nothing
//! here asserts against a hand-written struct, because a hand-written struct cannot exhibit the
//! property most of these tests are about: whether a claim survives being re-derived from chain
//! evidence rather than being taken from an index.

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::{cat::CatArgs, LineageProof, Memos};
use chia_sdk_driver::{
    Cat, CatInfo, CatSpend, P2ParentCoin, Puzzle, SpendContext, SpendWithConditions, StandardLayer,
};
use chia_sdk_types::{run_puzzle, Condition, Conditions};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::{ToTreeHash, TreeHash};
use clvmr::Allocator;
use dig_chainsource_interface::{ChainSource, ChainSourceError, CoinRecord, SingletonLineage};
use dig_mirror_coin::{
    create, discover, list, mirror_coin_puzzle_hash, morph_store_launcher_id,
    query::MirrorChainSource, reclaim, MirrorAdvertisement, MirrorError, SkipReason, DIG_ASSET_ID,
    MAX_CANDIDATES,
};
use num_bigint::BigInt;

const COLLATERAL: u64 = 1_000_000;

fn store_a() -> Bytes32 {
    Bytes32::new([0xA1; 32])
}

fn store_b() -> Bytes32 {
    Bytes32::new([0xB2; 32])
}

fn epoch() -> BigInt {
    BigInt::from(42)
}

/// A wallet: the key that signs, and the puzzle hash that owns.
struct Wallet {
    public_key: PublicKey,
    puzzle_hash: Bytes32,
}

fn wallet(seed: u8) -> Wallet {
    let public_key = SecretKey::from_seed(&[seed; 64]).public_key();
    let puzzle_hash: Bytes32 = StandardLayer::new(public_key).tree_hash().into();
    Wallet {
        public_key,
        puzzle_hash,
    }
}

/// Builds the real CAT spend that creates a mirror coin, and the coin it creates.
///
/// The parent is a $DIG CAT whose lineage proof is internally consistent, so the CAT puzzle runs
/// through to its conditions rather than raising — which is what makes these fixtures able to
/// exercise the authentication path at all.
fn creating_spend(owner: &Wallet, memo_entries: &[Bytes]) -> (CoinSpend, Coin) {
    creating_spend_of_asset(owner, memo_entries, DIG_ASSET_ID)
}

/// As [`creating_spend`], but for an arbitrary CAT — so a test can present collateral that is not
/// $DIG and watch it be refused.
fn creating_spend_of_asset(
    owner: &Wallet,
    memo_entries: &[Bytes],
    asset_id: Bytes32,
) -> (CoinSpend, Coin) {
    let entries = memo_entries.to_vec();
    let (spend, children) = creating_spend_of_children(owner, asset_id, COLLATERAL, |ctx| {
        vec![(COLLATERAL, Memos::Some(ctx.alloc(&entries).unwrap()))]
    });

    (spend, children[0])
}

/// The general fixture: one real CAT spend that creates any number of coins at the mirror puzzle
/// hash, each with memos of the test's choosing.
///
/// `children` returns one `(amount, memos)` per `CREATE_COIN` the parent emits. The amounts MUST
/// sum to `parent_amount` or the CAT puzzle refuses to run, and the memos are allocated inside the
/// spend's own allocator so a test can shape them freely — including into shapes no honest writer
/// produces, which is the only way to exercise what happens when a stranger writes them.
fn creating_spend_of_children(
    owner: &Wallet,
    asset_id: Bytes32,
    parent_amount: u64,
    children: impl FnOnce(&mut SpendContext) -> Vec<(u64, Memos)>,
) -> (CoinSpend, Vec<Coin>) {
    let mut ctx = SpendContext::new();

    let cat_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(asset_id, TreeHash::from(owner.puzzle_hash)).into();
    let grandparent_parent = Bytes32::new([0x99; 32]);
    let grandparent = Coin::new(grandparent_parent, cat_puzzle_hash, parent_amount);
    let parent = Coin::new(grandparent.coin_id(), cat_puzzle_hash, parent_amount);

    let lineage_proof = LineageProof {
        parent_parent_coin_info: grandparent_parent,
        parent_inner_puzzle_hash: owner.puzzle_hash,
        parent_amount,
    };
    let cat = Cat::new(
        parent,
        Some(lineage_proof),
        CatInfo::new(asset_id, None, owner.puzzle_hash),
    );

    let inner_puzzle_hash: Bytes32 = P2ParentCoin::inner_puzzle_hash(Some(asset_id)).into();
    let requested = children(&mut ctx);
    let mut conditions = Conditions::new();
    for (amount, memos) in &requested {
        conditions = conditions.create_coin(inner_puzzle_hash, *amount, *memos);
    }

    let inner_spend = StandardLayer::new(owner.public_key)
        .spend_with_conditions(&mut ctx, conditions)
        .unwrap();
    Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner_spend)]).unwrap();

    let spend = ctx
        .take()
        .into_iter()
        .find(|spend| spend.coin == parent)
        .expect("the parent CAT spend");
    let outer_puzzle_hash: Bytes32 = P2ParentCoin::puzzle_hash(Some(asset_id)).into();
    let coins = requested
        .iter()
        .map(|(amount, _)| Coin::new(parent.coin_id(), outer_puzzle_hash, *amount))
        .collect();

    (spend, coins)
}

/// Memos for a mirror advertising `store` in the current epoch.
fn mirror_memos(store: Bytes32, urls: &[&str]) -> Vec<Bytes> {
    let mut entries = vec![Bytes::new(
        morph_store_launcher_id(store, &epoch()).to_vec(),
    )];
    entries.extend(urls.iter().map(|url| Bytes::new(url.as_bytes().to_vec())));
    entries
}

/// A chain that answers exactly what a test puts in it, and fails exactly where a test says.
#[derive(Default)]
struct FakeChain {
    at_mirror_puzzle: Vec<CoinRecord>,
    by_hint: HashMap<Bytes32, Vec<CoinRecord>>,
    creating_spends: HashMap<Bytes32, CoinSpend>,
    hint_read_fails: bool,
    spend_read_fails_for: Option<Bytes32>,
}

impl FakeChain {
    /// Records a coin as findable both by the shared mirror puzzle hash and under `hint`, with its
    /// creating spend available.
    fn publish(&mut self, spend: CoinSpend, coin: Coin, hint: Bytes32) {
        let record = CoinRecord {
            coin,
            confirmed_height: Some(100),
            spent_height: None,
            timestamp: Some(1_700_000_000),
            coinbase: false,
        };
        self.at_mirror_puzzle.push(record.clone());
        self.by_hint.entry(hint).or_default().push(record);
        self.creating_spends.insert(spend.coin.coin_id(), spend);
    }

    /// Records a coin findable under `hint` whose creating spend is NOT available — what a dust coin
    /// hinted by a stranger looks like from a query's point of view.
    fn publish_without_creating_spend(&mut self, coin: Coin, hint: Bytes32) {
        let record = CoinRecord {
            coin,
            confirmed_height: Some(100),
            spent_height: None,
            timestamp: Some(1_700_000_000),
            coinbase: false,
        };
        self.at_mirror_puzzle.push(record.clone());
        self.by_hint.entry(hint).or_default().push(record);
    }
}

impl ChainSource for FakeChain {
    type Error = ChainSourceError;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Ok(self
            .at_mirror_puzzle
            .iter()
            .find(|record| record.coin.coin_id() == coin_id)
            .cloned())
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(self
            .at_mirror_puzzle
            .iter()
            .filter(|record| record.coin.puzzle_hash == puzzle_hash)
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
        Ok(Some(100))
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(Some(1_700_000_000))
    }
}

impl MirrorChainSource for FakeChain {
    fn unspent_coins_by_hint(&self, hint: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        if self.hint_read_fails {
            return Err(ChainSourceError::Transport("socket closed".to_string()));
        }
        Ok(self.by_hint.get(&hint).cloned().unwrap_or_default())
    }
}

/// A chain holding `count` dust coins at the shared mirror puzzle hash, all hinted to store A and
/// none of them resolvable — what a deliberate flood looks like to either query.
fn flooded_chain(count: usize) -> FakeChain {
    let mut chain = FakeChain::default();
    let hint = morph_store_launcher_id(store_a(), &epoch());

    for index in 0..count {
        let mut parent = [0u8; 32];
        parent[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let dust = Coin::new(Bytes32::new(parent), mirror_coin_puzzle_hash(), 1);
        chain.publish_without_creating_spend(dust, hint);
    }

    chain
}

/// Publishes an honest mirror for `store`, owned by `owner`, and returns its coin.
fn publish_mirror(chain: &mut FakeChain, owner: &Wallet, store: Bytes32, url: &str) -> Coin {
    let (spend, coin) = creating_spend(owner, &mirror_memos(store, &[url]));
    chain.publish(spend, coin, morph_store_launcher_id(store, &epoch()));
    coin
}

// ---------------------------------------------------------------------------------------------
// discover — an empty answer, and the thing it must never be confused with
// ---------------------------------------------------------------------------------------------

#[test]
fn discover_reports_an_empty_set_when_the_source_finds_nobody() {
    let chain = FakeChain::default();

    let found = discover(&chain, store_a(), &epoch()).expect("a reachable source answers");

    assert!(found.is_empty());
    assert_eq!(found.rejected_candidates(), 0);
    assert_eq!(found.store_launcher_id(), store_a());
}

#[test]
fn discover_errors_rather_than_reporting_an_empty_set_when_the_index_cannot_answer() {
    let chain = FakeChain {
        hint_read_fails: true,
        ..FakeChain::default()
    };

    let error = discover(&chain, store_a(), &epoch())
        .expect_err("an unanswerable read is not an answer of 'nobody'");

    assert!(matches!(error, MirrorError::ChainUnavailable(_)));
}

/// The discriminating case for the whole `Ok(empty)` / `Err` split, and the reason this fixture has
/// **two** candidates rather than one.
///
/// An implementation that swallows a per-candidate read failure returns `Ok` with the honest mirror
/// still in it — a plausible, useful-looking, wrong answer. Only a fixture holding one honest
/// candidate beside one unreachable candidate can tell that apart from the correct `Err`: with a
/// single hostile candidate both implementations produce an empty-ish result and the test proves
/// nothing.
#[test]
fn discover_propagates_an_unreachable_read_even_when_another_candidate_would_have_answered() {
    let owner = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &owner, store_a(), "https://honest.example");

    let stranger = wallet(2);
    let (_spend, unreadable) = creating_spend(&stranger, &mirror_memos(store_a(), &["https://x"]));
    chain.publish_without_creating_spend(unreadable, morph_store_launcher_id(store_a(), &epoch()));
    chain.spend_read_fails_for = Some(unreadable.parent_coin_info);

    let error = discover(&chain, store_a(), &epoch())
        .expect_err("a source that could not answer must not be reported as a partial answer");

    assert!(matches!(error, MirrorError::ChainUnavailable(_)));
}

#[test]
fn discover_drops_a_candidate_with_no_creating_spend_and_keeps_the_honest_one() {
    let owner = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &owner, store_a(), "https://honest.example");

    // Anyone can hint a coin to anyone's namespace value for the price of a dust coin. One such coin
    // must not be able to suppress every honest mirror, so this is dropped rather than fatal.
    let noise = Coin::new(Bytes32::new([0x77; 32]), mirror_coin_puzzle_hash(), 1);
    chain.publish_without_creating_spend(noise, morph_store_launcher_id(store_a(), &epoch()));

    let found = discover(&chain, store_a(), &epoch()).expect("the source answered");

    assert_eq!(found.claims().len(), 1);
    assert_eq!(found.rejected_candidates(), 1);
    assert_eq!(found.claims()[0].urls(), ["https://honest.example"]);
}

/// A hint says where to look and nothing more.
///
/// This coin is a perfectly real, perfectly valid mirror coin — it just advertises a different
/// store. It is placed in store A's hint bucket, which anyone can do. An implementation that
/// believed the index would return it; the correct one re-derives the advertised store from the
/// coin's own creating spend and rejects it.
#[test]
fn discover_rejects_a_coin_hinted_here_that_actually_advertises_another_store() {
    let stranger = wallet(3);
    let mut chain = FakeChain::default();

    let (spend, coin) = creating_spend(&stranger, &mirror_memos(store_b(), &["https://elsewhere"]));
    chain.publish(spend, coin, morph_store_launcher_id(store_a(), &epoch()));

    let found = discover(&chain, store_a(), &epoch()).expect("the source answered");

    assert!(found.is_empty());
    assert_eq!(found.rejected_candidates(), 1);
}

#[test]
fn discover_ignores_a_mirror_published_for_a_different_epoch() {
    let owner = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &owner, store_a(), "https://honest.example");

    let other_epoch = BigInt::from(43);
    let found = discover(&chain, store_a(), &other_epoch).expect("the source answered");

    assert!(found.is_empty());
}

// ---------------------------------------------------------------------------------------------
// list — the caller's own collateral, and why it fails closed
// ---------------------------------------------------------------------------------------------

#[test]
fn list_returns_only_the_coins_the_caller_controls() {
    let mine = wallet(1);
    let theirs = wallet(2);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &mine, store_a(), "https://mine.example");
    publish_mirror(&mut chain, &theirs, store_a(), "https://theirs.example");

    let owned = list(&chain, mine.puzzle_hash).expect("the source answered");

    assert_eq!(owned.coins().len(), 1);
    assert_eq!(owned.coins()[0].owner_puzzle_hash(), mine.puzzle_hash);
    assert_eq!(owned.coins()[0].urls(), ["https://mine.example"]);
    assert_eq!(owned.coins()[0].collateral(), COLLATERAL);
}

#[test]
fn list_reports_no_coins_for_an_owner_who_has_locked_nothing() {
    let mine = wallet(1);
    let theirs = wallet(2);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &theirs, store_a(), "https://theirs.example");

    let owned = list(&chain, mine.puzzle_hash).expect("the source answered");

    assert!(owned.coins().is_empty());
}

/// `list` is an inventory of the caller's own money, so it MUST NOT be quietly short — but it also
/// MUST NOT be deniable by a coin the caller does not own.
///
/// It resolves both by *disclosing*: the honest coin is returned, and the candidate that could not
/// be resolved is named, with its reason, so a caller that would rather refuse than under-report can
/// fail closed on `is_complete()` itself. The honest coin in this fixture is what makes the
/// behaviours distinguishable — a silently-dropping implementation returns exactly the same coins
/// and is caught only by the disclosure assertions below.
#[test]
fn list_discloses_a_candidate_it_could_not_authenticate_rather_than_dropping_or_denying() {
    let mine = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &mine, store_a(), "https://mine.example");

    let orphan = Coin::new(
        Bytes32::new([0x55; 32]),
        mirror_coin_puzzle_hash(),
        COLLATERAL,
    );
    chain.publish_without_creating_spend(orphan, morph_store_launcher_id(store_a(), &epoch()));

    let inventory = list(&chain, mine.puzzle_hash)
        .expect("one unresolvable candidate must not deny the whole inventory");

    assert_eq!(inventory.coins().len(), 1);
    assert!(
        !inventory.is_complete(),
        "an inventory that could not see every candidate must not claim to be whole"
    );
    assert_eq!(inventory.skipped().len(), 1);
    assert_eq!(inventory.skipped()[0].coin_id(), orphan.coin_id());
    assert_eq!(
        inventory.skipped()[0].reason(),
        &SkipReason::Unauthenticated
    );
}

/// The reason a caller is given distinguishes *the source did not have it* from *nobody could read
/// it*, because only the first is worth retrying against a better source.
#[test]
fn an_undecodable_candidate_is_disclosed_as_undecodable_not_as_unauthenticated() {
    let mine = wallet(1);
    let stranger = wallet(9);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &mine, store_a(), "https://mine.example");

    let (spend, junk) = creating_spend_of_children(&stranger, DIG_ASSET_ID, 1, |ctx| {
        let improper = ctx
            .alloc(&(Bytes::new(vec![0xAA]), Bytes::new(vec![0xBB])))
            .unwrap();
        vec![(1, Memos::Some(improper))]
    });
    chain.publish(spend, junk[0], morph_store_launcher_id(store_a(), &epoch()));

    let inventory = list(&chain, mine.puzzle_hash).expect("the source answered");

    assert_eq!(inventory.skipped().len(), 1);
    assert!(matches!(
        inventory.skipped()[0].reason(),
        SkipReason::Undecodable(_)
    ));
}

/// An inventory that resolved every candidate says so, or `is_complete` would be a constant.
#[test]
fn an_inventory_that_resolved_every_candidate_reports_itself_complete() {
    let mine = wallet(1);
    let theirs = wallet(2);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &mine, store_a(), "https://mine.example");
    publish_mirror(&mut chain, &theirs, store_a(), "https://theirs.example");

    let inventory = list(&chain, mine.puzzle_hash).expect("the source answered");

    assert!(inventory.is_complete());
    assert!(inventory.skipped().is_empty());
    assert!(!inventory.is_truncated());
}

/// A source that cannot answer at all is still an `Err`, and is NOT reported as a skipped candidate.
///
/// This is the line the disclosure must not blur: "one coin on the chain is odd" and "the chain did
/// not answer" are different facts, and only the first may leave the query successful. The honest
/// mirror beside the failing read is what distinguishes the correct `Err` from a plausible-looking
/// `Ok` holding one claim.
#[test]
fn list_propagates_an_unreachable_source_rather_than_recording_it_as_a_skip() {
    let mine = wallet(1);
    let stranger = wallet(2);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &mine, store_a(), "https://mine.example");

    let (_spend, unreadable) = creating_spend(&stranger, &mirror_memos(store_a(), &["https://x"]));
    chain.publish_without_creating_spend(unreadable, morph_store_launcher_id(store_a(), &epoch()));
    chain.spend_read_fails_for = Some(unreadable.parent_coin_info);

    let error = list(&chain, mine.puzzle_hash)
        .expect_err("a source that could not answer is not a partial answer");

    assert!(matches!(error, MirrorError::ChainUnavailable(_)));
}

/// One stranger's one-mojo coin MUST NOT be able to deny every user their own inventory.
///
/// `list` scans the **globally shared** mirror puzzle hash, where almost every candidate belongs to
/// somebody else. The memos below are `(0xAA . 0xBB)` — legal CLVM, an improper list, undecodable as
/// a memo list. Nothing about this coin is weak or exotic: it is a real $DIG coin whose creating
/// spend is fully retrievable from a perfect full node, so a per-candidate `Err` propagated out of
/// the loop reaches every honest caller on the best source available.
///
/// The honest mirror beside it is what makes this test discriminating. Without it, both a correct
/// implementation and one that quietly returned an empty inventory would look alike.
#[test]
fn a_strangers_undecodable_coin_does_not_deny_an_owner_their_inventory() {
    let mine = wallet(1);
    let stranger = wallet(9);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &mine, store_a(), "https://mine.example");

    let (spend, junk) = creating_spend_of_children(&stranger, DIG_ASSET_ID, 1, |ctx| {
        let improper = ctx
            .alloc(&(Bytes::new(vec![0xAA]), Bytes::new(vec![0xBB])))
            .unwrap();
        vec![(1, Memos::Some(improper))]
    });
    chain.publish(spend, junk[0], morph_store_launcher_id(store_a(), &epoch()));

    let inventory = list(&chain, mine.puzzle_hash)
        .expect("one stranger's junk coin must not deny an unrelated owner their own inventory");

    assert_eq!(inventory.coins().len(), 1);
    assert_eq!(inventory.coins()[0].urls(), ["https://mine.example"]);
}

/// Two mirror coins created by ONE parent spend are BOTH the owner's money, so both MUST be found.
///
/// A parser that returns the parent's *first* matching output loses the second silently: it is not
/// an error, not a rejection, not a warning — the collateral simply stops being visible while
/// remaining locked on chain. The two amounts differ so that a result of one coin cannot be mistaken
/// for a result of the other.
#[test]
fn both_mirror_coins_created_by_one_parent_spend_are_found() {
    let mine = wallet(1);
    let mut chain = FakeChain::default();

    let larger = 1_000_000u64;
    let smaller = 500_000u64;
    let (spend, coins) = creating_spend_of_children(&mine, DIG_ASSET_ID, larger + smaller, |ctx| {
        let first = ctx
            .alloc(&mirror_memos(store_a(), &["https://first.example"]))
            .unwrap();
        let second = ctx
            .alloc(&mirror_memos(store_a(), &["https://second.example"]))
            .unwrap();
        vec![(larger, Memos::Some(first)), (smaller, Memos::Some(second))]
    });

    let hint = morph_store_launcher_id(store_a(), &epoch());
    chain.publish(spend.clone(), coins[0], hint);
    chain.publish(spend, coins[1], hint);

    let inventory = list(&chain, mine.puzzle_hash).expect("the source answered");
    let mut amounts: Vec<u64> = inventory
        .coins()
        .iter()
        .map(|mirror| mirror.collateral())
        .collect();
    amounts.sort_unstable();

    assert_eq!(
        amounts,
        vec![smaller, larger],
        "a second mirror coin from one parent spend must not vanish from its owner's inventory"
    );

    let found = discover(&chain, store_a(), &epoch()).expect("the source answered");
    assert_eq!(found.claims().len(), 2);
    assert_eq!(found.rejected_candidates(), 0);
}

/// The candidate bound is pinned from BOTH sides: at exactly the limit the scan completes, one
/// candidate over it the scan stops early and says so.
///
/// A bound asserted only from below can only confirm itself — every count under the limit produces
/// the same untruncated result whatever the limit actually is.
#[test]
fn the_candidate_bound_stops_a_scan_only_once_it_is_exceeded() {
    let mine = wallet(1);

    let at_limit = list(&flooded_chain(MAX_CANDIDATES), mine.puzzle_hash)
        .expect("a flood must not deny the query");
    assert!(
        !at_limit.is_truncated(),
        "a scan of exactly MAX_CANDIDATES candidates reaches the end of the list"
    );
    assert_eq!(at_limit.skipped().len(), MAX_CANDIDATES);

    let over_limit = list(&flooded_chain(MAX_CANDIDATES + 1), mine.puzzle_hash)
        .expect("a flood must not deny the query");
    assert!(
        over_limit.is_truncated(),
        "one candidate past the limit must stop the scan and be disclosed"
    );
    assert_eq!(
        over_limit.skipped().len(),
        MAX_CANDIDATES,
        "the work done is bounded by the limit, not by what the attacker supplied"
    );
}

/// `discover` walks a list anyone may add to, so it carries the same bound — and, being the verb
/// whose empty answer is read as *nobody mirrors this*, it MUST disclose when that answer is partial.
#[test]
fn a_flood_bounds_discovery_and_is_disclosed_rather_than_answered_as_nobody() {
    let over_limit = discover(&flooded_chain(MAX_CANDIDATES + 1), store_a(), &epoch())
        .expect("a flood must not deny the query");

    assert!(over_limit.is_empty());
    assert!(
        over_limit.is_truncated(),
        "an empty claim set from a truncated scan must not be readable as 'nobody mirrors this'"
    );
    assert_eq!(over_limit.rejected_candidates(), MAX_CANDIDATES);

    let at_limit = discover(&flooded_chain(MAX_CANDIDATES), store_a(), &epoch())
        .expect("a flood must not deny the query");
    assert!(!at_limit.is_truncated());
}

/// A sibling collateral coin shares the mirror puzzle hash but advertises no URLs, so it is not a
/// mirror coin and never appears in a mirror result.
#[test]
fn a_collateral_coin_advertising_no_urls_is_not_a_mirror_coin() {
    let mine = wallet(1);
    let mut chain = FakeChain::default();

    let bare = vec![Bytes::new(
        morph_store_launcher_id(store_a(), &epoch()).to_vec(),
    )];
    let (spend, coin) = creating_spend(&mine, &bare);
    chain.publish(spend, coin, morph_store_launcher_id(store_a(), &epoch()));

    let owned = list(&chain, mine.puzzle_hash).expect("the source answered");
    let found = discover(&chain, store_a(), &epoch()).expect("the source answered");

    assert!(owned.coins().is_empty());
    assert!(found.is_empty());
}

// ---------------------------------------------------------------------------------------------
// reclaim — the collateral comes back, in full
// ---------------------------------------------------------------------------------------------

#[test]
fn reclaim_is_refused_for_a_wallet_that_does_not_control_the_coin() {
    let owner = wallet(1);
    let attacker = wallet(2);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &owner, store_a(), "https://mine.example");

    let mirror = list(&chain, owner.puzzle_hash)
        .expect("the source answered")
        .coins()[0]
        .clone();
    let error =
        reclaim(&mirror, attacker.public_key, vec![], 0).expect_err("only the owner may reclaim");

    assert!(matches!(error, MirrorError::NotOwner { .. }));
}

/// The money test: the reclaim spend is executed, and its conditions must recreate the FULL
/// collateral as $DIG at the owner's address.
///
/// The expected puzzle hash is the CAT-wrapped one, not the bare p2 hash, because a $DIG coin paid
/// to a bare p2 hash would not be a $DIG coin at all. And the expected amount is the whole
/// collateral: a burn — the operation `reclaim` deliberately is not — would show up here as a
/// missing or reduced output, which is exactly what this assertion refuses.
#[test]
fn reclaim_recreates_the_entire_collateral_as_dig_at_the_owners_address() {
    let owner = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &owner, store_a(), "https://mine.example");

    let mirror = list(&chain, owner.puzzle_hash)
        .expect("the source answered")
        .coins()[0]
        .clone();
    let spends = reclaim(&mirror, owner.public_key, vec![], 0).expect("the owner may reclaim");

    let spend = spends
        .iter()
        .find(|spend| spend.coin == mirror.coin())
        .expect("the mirror coin is spent");

    let expected_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(DIG_ASSET_ID, TreeHash::from(owner.puzzle_hash)).into();
    let outputs = create_coins(spend);

    assert!(
        outputs.contains(&(expected_puzzle_hash, COLLATERAL)),
        "expected the whole collateral back as $DIG at the owner's address; got {outputs:?}"
    );
}

/// Returning the money is not enough if no wallet can find it.
///
/// A CAT coin sits at a puzzle hash that reveals nothing about its owner, so wallets locate one by
/// its hint. A reclaim that recreates the collateral with no hint produces a coin that is spendable
/// in principle and missing from the balance its owner is shown — indistinguishable, to the person,
/// from collateral that never came back.
#[test]
fn reclaimed_collateral_is_hinted_to_the_owner_so_a_wallet_can_find_it() {
    let owner = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &owner, store_a(), "https://mine.example");

    let inventory = list(&chain, owner.puzzle_hash).expect("the source answered");
    let spends =
        reclaim(&inventory.coins()[0], owner.public_key, vec![], 0).expect("the owner may reclaim");

    let spend = spends
        .iter()
        .find(|spend| spend.coin == inventory.coins()[0].coin())
        .expect("the mirror coin is spent");
    let returned_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(DIG_ASSET_ID, TreeHash::from(owner.puzzle_hash)).into();

    assert_eq!(
        create_coin_memos(spend, returned_puzzle_hash),
        vec![Bytes::new(owner.puzzle_hash.to_vec())],
        "the returned collateral must be hinted to the owner's own puzzle hash"
    );
}

/// The memos carried by the `CREATE_COIN` output of `spend` that pays `puzzle_hash`.
fn create_coin_memos(spend: &CoinSpend, puzzle_hash: Bytes32) -> Vec<Bytes> {
    let mut allocator = Allocator::new();
    let puzzle = spend.puzzle_reveal.to_clvm(&mut allocator).unwrap();
    let solution = spend.solution.to_clvm(&mut allocator).unwrap();
    let output = run_puzzle(&mut allocator, puzzle, solution).unwrap();

    Conditions::<clvmr::NodePtr>::from_clvm(&allocator, output)
        .unwrap()
        .into_iter()
        .find_map(|condition| match condition {
            Condition::CreateCoin(created) if created.puzzle_hash == puzzle_hash => {
                Some(match created.memos {
                    Memos::Some(node) => Vec::<Bytes>::from_clvm(&allocator, node).unwrap(),
                    Memos::None => Vec::new(),
                })
            }
            _ => None,
        })
        .expect("an output paying that puzzle hash")
}

/// Runs a coin spend's puzzle against its solution and collects its `CREATE_COIN` outputs.
fn create_coins(spend: &CoinSpend) -> Vec<(Bytes32, u64)> {
    let mut allocator = Allocator::new();
    let puzzle = spend.puzzle_reveal.to_clvm(&mut allocator).unwrap();
    let solution = spend.solution.to_clvm(&mut allocator).unwrap();
    let output = run_puzzle(&mut allocator, puzzle, solution).unwrap();

    Conditions::<clvmr::NodePtr>::from_clvm(&allocator, output)
        .unwrap()
        .into_iter()
        .filter_map(|condition| match condition {
            Condition::CreateCoin(create) => Some((create.puzzle_hash, create.amount)),
            _ => None,
        })
        .collect()
}

/// A parsed mirror coin knows which store it advertises only by recomputing the morph, so the check
/// answers truthfully for the store it was published for and falsely for any other.
#[test]
fn advertises_answers_only_for_the_store_the_coin_was_published_for() {
    let owner = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &owner, store_a(), "https://mine.example");

    let inventory = list(&chain, owner.puzzle_hash).expect("the source answered");
    let mirror = &inventory.coins()[0];

    assert!(mirror.advertises(store_a(), &epoch()));
    assert!(!mirror.advertises(store_b(), &epoch()));
    assert!(!mirror.advertises(store_a(), &BigInt::from(43)));
}

/// Guards against an unused-import drift in the fixture: `Puzzle` is what the crate uses to parse a
/// parent reveal, and this asserts the fixture's spends are parseable the same way.
#[test]
fn fixture_spends_are_parseable_puzzles() {
    let owner = wallet(1);
    let (spend, _coin) =
        creating_spend(&owner, &mirror_memos(store_a(), &["https://mine.example"]));

    let mut allocator = Allocator::new();
    let ptr = spend.puzzle_reveal.to_clvm(&mut allocator).unwrap();

    assert!(Puzzle::parse(&allocator, ptr).as_curried().is_some());
}

// ---------------------------------------------------------------------------------------------
// create — the loop closes: what this crate publishes is what this crate can discover
// ---------------------------------------------------------------------------------------------

/// Runs the real `create` builder and then discovers the coin it produced.
///
/// The other fixtures build their creating spends directly, which proves the *parser* works against
/// a plausible spend. This proves the parser works against **this crate's own writer** — the one
/// place a memo ordering, a namespace tag or a puzzle-hash choice could disagree with itself and
/// stay invisible in every other test, because both halves would be wrong in the same direction only
/// if they were written by the same mistake.
#[test]
fn a_mirror_this_crate_creates_is_a_mirror_this_crate_discovers() {
    let owner = wallet(1);

    let cat_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(DIG_ASSET_ID, TreeHash::from(owner.puzzle_hash)).into();
    let grandparent_parent = Bytes32::new([0x99; 32]);
    let grandparent = Coin::new(grandparent_parent, cat_puzzle_hash, COLLATERAL);
    let funding = Coin::new(grandparent.coin_id(), cat_puzzle_hash, COLLATERAL);
    let dig_coin = Cat::new(
        funding,
        Some(LineageProof {
            parent_parent_coin_info: grandparent_parent,
            parent_inner_puzzle_hash: owner.puzzle_hash,
            parent_amount: COLLATERAL,
        }),
        CatInfo::new(DIG_ASSET_ID, None, owner.puzzle_hash),
    );

    let spends = create(
        MirrorAdvertisement {
            store_launcher_id: store_a(),
            epoch: epoch(),
            urls: vec!["https://published.example".to_string()],
            collateral: COLLATERAL,
        },
        vec![dig_coin],
        owner.public_key,
        vec![],
        0,
    )
    .expect("the advertisement is well formed");

    let creating = spends
        .iter()
        .find(|spend| spend.coin == funding)
        .expect("the funding coin is spent");
    let (_, amount) = create_coins(creating)
        .into_iter()
        .find(|(puzzle_hash, _)| *puzzle_hash == mirror_coin_puzzle_hash())
        .expect("a coin is created at the mirror puzzle hash");
    let published = Coin::new(funding.coin_id(), mirror_coin_puzzle_hash(), amount);

    let mut chain = FakeChain::default();
    chain.publish(
        creating.clone(),
        published,
        morph_store_launcher_id(store_a(), &epoch()),
    );

    let found = discover(&chain, store_a(), &epoch()).expect("the source answered");

    assert_eq!(
        found.claims().len(),
        1,
        "created mirror was not discoverable"
    );
    assert_eq!(found.claims()[0].urls(), ["https://published.example"]);
    assert_eq!(found.claims()[0].collateral(), COLLATERAL);
    assert_eq!(found.claims()[0].owner_puzzle_hash(), owner.puzzle_hash);
}

/// Collateral in some other CAT is not collateral.
///
/// The economic attack this refuses is cheap and obvious: mint a worthless token, lock a large
/// amount of it, and advertise a mirror for free. The asset id is read from the coin's own curried
/// puzzle — executed, not claimed — so the substitution is visible.
#[test]
fn a_mirror_collateralised_in_another_cat_is_refused() {
    let attacker = wallet(4);
    let worthless = Bytes32::new([0xEE; 32]);
    let mut chain = FakeChain::default();

    let (spend, coin) = creating_spend_of_asset(
        &attacker,
        &mirror_memos(store_a(), &["https://free.example"]),
        worthless,
    );
    chain.publish(spend, coin, morph_store_launcher_id(store_a(), &epoch()));

    let found = discover(&chain, store_a(), &epoch()).expect("the source answered");

    assert!(found.is_empty(), "a non-$DIG mirror must not be a claim");
    assert_eq!(found.rejected_candidates(), 1);
}

/// A fee is paid from XCH, never shaved off the collateral.
///
/// The fee path is a separate branch from the zero-fee one, and it is the branch a real wallet
/// always takes — so the collateral-preservation property has to be asserted on both, or the one
/// users actually run is the untested one.
#[test]
fn reclaim_with_a_fee_still_returns_the_whole_collateral() {
    let owner = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &owner, store_a(), "https://mine.example");

    let mirror = list(&chain, owner.puzzle_hash)
        .expect("the source answered")
        .coins()[0]
        .clone();
    let fee_coin = Coin::new(Bytes32::new([0x31; 32]), owner.puzzle_hash, 10_000);

    let spends =
        reclaim(&mirror, owner.public_key, vec![fee_coin], 1_000).expect("a reclaim may pay a fee");

    let spend = spends
        .iter()
        .find(|spend| spend.coin == mirror.coin())
        .expect("the mirror coin is spent");
    let expected_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(DIG_ASSET_ID, TreeHash::from(owner.puzzle_hash)).into();

    assert!(
        create_coins(spend).contains(&(expected_puzzle_hash, COLLATERAL)),
        "the fee must come from XCH, not from the locked collateral"
    );
    assert!(
        spends.iter().any(|spend| spend.coin == fee_coin),
        "the supplied XCH fee coin is what pays the fee"
    );
}

/// The accessors report the coin the chain actually holds, not a restatement of the query's input.
#[test]
fn a_parsed_mirror_reports_its_own_coin_and_lineage() {
    let owner = wallet(1);
    let mut chain = FakeChain::default();
    let published = publish_mirror(&mut chain, &owner, store_a(), "https://mine.example");

    let mirror = list(&chain, owner.puzzle_hash)
        .expect("the source answered")
        .coins()[0]
        .clone();

    assert_eq!(mirror.coin(), published);
    assert_eq!(mirror.coin().puzzle_hash, mirror_coin_puzzle_hash());
    assert_eq!(mirror.proof().parent_inner_puzzle_hash, owner.puzzle_hash);
    assert_eq!(
        mirror.namespace_hint(),
        morph_store_launcher_id(store_a(), &epoch())
    );
}
