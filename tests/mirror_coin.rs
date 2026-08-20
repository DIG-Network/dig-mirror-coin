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
    query::MirrorChainSource, reclaim, MirrorAdvertisement, MirrorError, DIG_ASSET_ID,
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
    let mut ctx = SpendContext::new();

    let cat_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(asset_id, TreeHash::from(owner.puzzle_hash)).into();
    let grandparent_parent = Bytes32::new([0x99; 32]);
    let grandparent = Coin::new(grandparent_parent, cat_puzzle_hash, COLLATERAL);
    let parent = Coin::new(grandparent.coin_id(), cat_puzzle_hash, COLLATERAL);

    let lineage_proof = LineageProof {
        parent_parent_coin_info: grandparent_parent,
        parent_inner_puzzle_hash: owner.puzzle_hash,
        parent_amount: COLLATERAL,
    };
    let cat = Cat::new(
        parent,
        Some(lineage_proof),
        CatInfo::new(asset_id, None, owner.puzzle_hash),
    );

    let memos = Memos::Some(ctx.alloc(&memo_entries.to_vec()).unwrap());
    let conditions = Conditions::new().create_coin(
        P2ParentCoin::inner_puzzle_hash(Some(asset_id)).into(),
        COLLATERAL,
        memos,
    );
    let inner_spend = StandardLayer::new(owner.public_key)
        .spend_with_conditions(&mut ctx, conditions)
        .unwrap();
    Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner_spend)]).unwrap();

    let spend = ctx
        .take()
        .into_iter()
        .find(|spend| spend.coin == parent)
        .expect("the parent CAT spend");
    let child = Coin::new(
        parent.coin_id(),
        P2ParentCoin::puzzle_hash(Some(asset_id)).into(),
        COLLATERAL,
    );

    (spend, child)
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

    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].owner_puzzle_hash(), mine.puzzle_hash);
    assert_eq!(owned[0].urls(), ["https://mine.example"]);
    assert_eq!(owned[0].collateral(), COLLATERAL);
}

#[test]
fn list_reports_no_coins_for_an_owner_who_has_locked_nothing() {
    let mine = wallet(1);
    let theirs = wallet(2);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &theirs, store_a(), "https://theirs.example");

    let owned = list(&chain, mine.puzzle_hash).expect("the source answered");

    assert!(owned.is_empty());
}

/// `list` is an inventory of the caller's own money, so an unauthenticatable candidate is fatal
/// rather than skipped — the honest coin in this fixture is what makes the two behaviours
/// distinguishable, since a skipping implementation would return it and look correct.
#[test]
fn list_fails_closed_when_a_candidate_cannot_be_authenticated() {
    let mine = wallet(1);
    let mut chain = FakeChain::default();
    publish_mirror(&mut chain, &mine, store_a(), "https://mine.example");

    let orphan = Coin::new(
        Bytes32::new([0x55; 32]),
        mirror_coin_puzzle_hash(),
        COLLATERAL,
    );
    chain.publish_without_creating_spend(orphan, morph_store_launcher_id(store_a(), &epoch()));

    let error = list(&chain, mine.puzzle_hash)
        .expect_err("an inventory that cannot see every coin must not pretend otherwise");

    assert!(matches!(error, MirrorError::Unauthenticated { .. }));
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

    assert!(owned.is_empty());
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

    let mirror = list(&chain, owner.puzzle_hash).expect("the source answered")[0].clone();
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

    let mirror = list(&chain, owner.puzzle_hash).expect("the source answered")[0].clone();
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

    let mirror = &list(&chain, owner.puzzle_hash).expect("the source answered")[0];

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

    let mirror = list(&chain, owner.puzzle_hash).expect("the source answered")[0].clone();
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

    let mirror = list(&chain, owner.puzzle_hash).expect("the source answered")[0].clone();

    assert_eq!(mirror.coin(), published);
    assert_eq!(mirror.coin().puzzle_hash, mirror_coin_puzzle_hash());
    assert_eq!(mirror.proof().parent_inner_puzzle_hash, owner.puzzle_hash);
    assert_eq!(
        mirror.namespace_hint(),
        morph_store_launcher_id(store_a(), &epoch())
    );
}
