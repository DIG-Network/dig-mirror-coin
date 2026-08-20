//! [`MirrorCoin`] — a coin that locks $DIG to advertise a store mirror, and the rules for
//! recognising one from chain data.
//!
//! Recognition is the delicate part. A mirror coin is found through a **hint**, and a hint is an
//! unauthenticated `CREATE_COIN` memo over arbitrary bytes: anyone may place a dust coin under
//! anyone else's hint. So nothing here trusts a hint for anything except *where to look*. Every
//! property that matters — which asset is locked, how much, and who controls it — is read from the
//! coin's **creating spend**: the parent's actual puzzle reveal and solution, run to produce its
//! conditions. A coin that cannot be reconstructed that way is not accepted at all.

use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::{LineageProof, Memos};
use chia_sdk_driver::{P2ParentCoin, Puzzle};
use chia_sdk_types::{run_puzzle, Condition, Conditions};
use clvm_traits::{FromClvm, ToClvm};
use clvmr::{Allocator, NodePtr};
use num_bigint::BigInt;

use crate::asset::DIG_ASSET_ID;
use crate::error::MirrorError;
use crate::namespace::morph_store_launcher_id;

/// A coin locking $DIG as collateral behind a claim to mirror a DIG store.
///
/// ## What holding one of these proves, and what it does not
///
/// It proves that a specific amount of $DIG is locked, under a specific namespace value, by a
/// specific owner, and that all three facts come from an on-chain spend rather than from a memo
/// anyone could have written. It proves **nothing at all** about whether the advertised URLs serve
/// the store, or whether they are reachable, or whether they ever were. The collateral is a cost
/// attached to a claim; it is not evidence for the claim.
#[derive(Debug, Clone)]
pub struct MirrorCoin {
    inner: P2ParentCoin,
    namespace_hint: Bytes32,
    urls: Vec<String>,
}

impl MirrorCoin {
    /// The underlying coin — parent, puzzle hash and amount.
    pub fn coin(&self) -> Coin {
        self.inner.coin
    }

    /// The lineage proof that authenticates this coin against its parent.
    pub fn proof(&self) -> LineageProof {
        self.inner.proof
    }

    /// The amount of $DIG locked as collateral, in mojos.
    pub fn collateral(&self) -> u64 {
        self.inner.coin.amount
    }

    /// The puzzle hash of the wallet that controls this coin, and the only one that can reclaim it.
    ///
    /// This is the inner puzzle hash recorded in the lineage proof, so it comes from the parent's
    /// real puzzle reveal — not from a memo.
    pub fn owner_puzzle_hash(&self) -> Bytes32 {
        self.inner.proof.parent_inner_puzzle_hash
    }

    /// The namespace value this coin is advertised under.
    ///
    /// This is a one-way morph of a store launcher id and an epoch, so it names no store on its own.
    /// To learn whether this coin advertises a particular store, use
    /// [`advertises`](Self::advertises), which recomputes the morph and compares.
    pub fn namespace_hint(&self) -> Bytes32 {
        self.namespace_hint
    }

    /// The URLs the owner advertises for the store, in the order they were published.
    ///
    /// Unverified strings straight off the chain. Treat them as untrusted input: they have not been
    /// contacted, parsed for scheme, or bounded in number by anything but the block that carried
    /// them.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Whether this coin advertises `store_launcher_id` for `epoch`.
    ///
    /// This is the sound test, and the only one: it recomputes the namespace value from a candidate
    /// store id and compares. A caller that instead reads the store out of a memo is trusting the
    /// coin's author.
    pub fn advertises(&self, store_launcher_id: Bytes32, epoch: &BigInt) -> bool {
        self.namespace_hint == morph_store_launcher_id(store_launcher_id, epoch)
    }

    /// Reconstructs a mirror coin from the spend that CREATED it.
    ///
    /// `creating_spend` is the spend of the candidate coin's parent; `coin_id` is the candidate
    /// itself. The parent's puzzle is run against its solution and the resulting `CREATE_COIN`
    /// conditions are searched for the child — so the asset id, the amount and the owner are all
    /// derived from executed on-chain code.
    ///
    /// Returns `Ok(None)` when the spend genuinely did not create this mirror coin: the child is not
    /// a $DIG-collateral coin at all, is a different coin than the one asked about, or carries no
    /// advertised URLs. That last case is what keeps sibling collateral coins — which are hinted
    /// with a bare namespace value and no URLs — out of every mirror result. It is a necessary
    /// condition, not a sufficient one: memo shape is chosen by whoever spends the parent, so it
    /// filters honest neighbours rather than defeating an adversary.
    ///
    /// Returns `Err` only when the data could not be interpreted — which is a failure to establish
    /// an answer, never an answer of "no".
    pub fn from_creating_spend(
        creating_spend: &CoinSpend,
        coin_id: Bytes32,
    ) -> Result<Option<Self>, MirrorError> {
        let mut allocator = Allocator::new();

        let puzzle_ptr = creating_spend
            .puzzle_reveal
            .to_clvm(&mut allocator)
            .map_err(|error| {
                MirrorError::Malformed(format!("undecodable puzzle reveal: {error}"))
            })?;
        let solution_ptr = creating_spend
            .solution
            .to_clvm(&mut allocator)
            .map_err(|error| MirrorError::Malformed(format!("undecodable solution: {error}")))?;

        let parent_puzzle = Puzzle::parse(&allocator, puzzle_ptr);
        let Some((first, first_memos)) = P2ParentCoin::parse_child(
            &mut allocator,
            creating_spend.coin,
            parent_puzzle,
            solution_ptr,
        )?
        else {
            return Ok(None);
        };

        // `parse_child` answers with the parent's FIRST output at the collateral puzzle hash, which
        // is the wrong one whenever a spend created more than one. That is not hypothetical: a
        // consumer batching several advertisements into one transaction produces exactly this shape,
        // and each of those coins locks its owner's $DIG. Selecting by coin id rather than by
        // position is what keeps the later ones from vanishing while their collateral stays locked.
        let (inner, memos) = if first.coin.coin_id() == coin_id {
            (first, first_memos)
        } else {
            let Some(sibling) =
                sibling_child(&mut allocator, &first, parent_puzzle, solution_ptr, coin_id)?
            else {
                return Ok(None);
            };
            sibling
        };

        if inner.asset_id != Some(DIG_ASSET_ID) {
            return Err(MirrorError::NotDigCollateral {
                found: inner.asset_id,
            });
        }

        let Some((namespace_hint, urls)) = parse_memos(&allocator, memos)? else {
            return Ok(None);
        };

        Ok(Some(Self {
            inner,
            namespace_hint,
            urls,
        }))
    }

    /// The authenticated p2-parent view, for the spend builders.
    pub(crate) fn inner(&self) -> &P2ParentCoin {
        &self.inner
    }
}

/// Finds a LATER collateral output of the same parent spend — the one whose coin id is `coin_id`.
///
/// Reached only when the parent created more than one collateral coin and the caller asked about a
/// coin other than the first. Everything that authenticates the coin — the asset id, the lineage
/// proof, the collateral puzzle hash — is taken from `first`, the child the canonical
/// [`P2ParentCoin::parse_child`] already derived, so this function decides *which output* and
/// nothing else. Re-deriving those values here would be a second copy of upstream's CAT-argument
/// handling, free to drift from it.
///
/// Returns `Ok(None)` when no output of this spend has that coin id, which is the honest answer to
/// "did this spend create that coin": no.
fn sibling_child(
    allocator: &mut Allocator,
    first: &P2ParentCoin,
    parent_puzzle: Puzzle,
    parent_solution: NodePtr,
    coin_id: Bytes32,
) -> Result<Option<(P2ParentCoin, Memos)>, MirrorError> {
    let collateral_puzzle_hash = first.coin.puzzle_hash;
    let parent_id = first.coin.parent_coin_info;

    let output = run_puzzle(allocator, parent_puzzle.ptr(), parent_solution)
        .map_err(|error| MirrorError::Malformed(format!("parent puzzle did not run: {error}")))?;
    let conditions = Conditions::<NodePtr>::from_clvm(allocator, output)
        .map_err(|error| MirrorError::Malformed(format!("undecodable conditions: {error}")))?;

    for condition in conditions {
        let Condition::CreateCoin(created) = condition else {
            continue;
        };
        if created.puzzle_hash != collateral_puzzle_hash {
            continue;
        }

        let sibling = Coin::new(parent_id, collateral_puzzle_hash, created.amount);
        if sibling.coin_id() == coin_id {
            return Ok(Some((
                P2ParentCoin::new(sibling, first.asset_id, first.proof),
                created.memos,
            )));
        }
    }

    Ok(None)
}

/// Splits a mirror coin's memos into its namespace value and its advertised URLs.
///
/// Returns `Ok(None)` when the memos are not mirror-shaped — absent, empty, a first entry that is
/// not a 32-byte namespace value, or no URLs after it.
fn parse_memos(
    allocator: &Allocator,
    memos: Memos,
) -> Result<Option<(Bytes32, Vec<String>)>, MirrorError> {
    let Memos::Some(node) = memos else {
        return Ok(None);
    };

    let entries = Vec::<Bytes>::from_clvm(allocator, node)
        .map_err(|error| MirrorError::Malformed(format!("undecodable memos: {error}")))?;

    let Some((namespace, advertised)) = entries.split_first() else {
        return Ok(None);
    };

    let Ok(namespace_hint) = Bytes32::try_from(namespace.as_ref()) else {
        return Ok(None);
    };

    let mut urls = Vec::with_capacity(advertised.len());
    for entry in advertised {
        // A memo is arbitrary bytes; a non-UTF-8 entry is somebody else's data riding in our memo
        // list, not a URL. Dropping it is safe because URLs are advisory either way.
        if let Ok(url) = String::from_utf8(entry.to_vec()) {
            urls.push(url);
        }
    }

    if urls.is_empty() {
        return Ok(None);
    }

    Ok(Some((namespace_hint, urls)))
}
