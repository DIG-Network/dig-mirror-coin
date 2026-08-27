//! [`MirrorCoin`] — a coin that locks $DIG to advertise a store mirror, and the rules for
//! recognising one from chain data.
//!
//! Recognition is the delicate part. A mirror coin is found through a **hint**, and a hint is an
//! unauthenticated `CREATE_COIN` memo over arbitrary bytes: anyone may place a dust coin under
//! anyone else's hint. So nothing here trusts a hint for anything except *where to look*. Every
//! property that matters — which asset is locked, how much, and who controls it — is read from the
//! coin's **creating spend**: the parent's actual puzzle reveal and solution, run to produce its
//! conditions. A coin that cannot be reconstructed that way is not accepted at all.
//!
//! ## The memos are a declaration, and that is exactly why they are read
//!
//! One thing genuinely does come from the memos: **which advertisement the collateral is staked
//! on** — the store, the root and the epoch. That is not a weakening of the rule above, it is the
//! only place such a claim can live. Whoever locks the $DIG chooses what to stake it on, so the
//! declaration is theirs to make; what matters is that they can make **one**, and that a verifier
//! compares it against what it asked about instead of assuming.
//!
//! The alternative — inferring the advertisement by recomputing the hint — cannot work, and the
//! reason is written out on [`mirror_hint`]: the epoch is an unbounded free term, so its author can
//! solve for a value that lands a coin bonding their own store on anyone else's hint. Under that
//! construction one stake would back unlimited claims. The declaration is what pins it to one.

use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::{LineageProof, Memos};
use chia_sdk_driver::{P2ParentCoin, Puzzle};
use chia_sdk_types::{run_puzzle, Condition, Conditions};
use clvm_traits::{FromClvm, ToClvm};
use clvmr::{Allocator, NodePtr};
use num_bigint::BigInt;

use crate::asset::DIG_ASSET_ID;
use crate::error::MirrorError;
use crate::namespace::mirror_hint;

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
    declared: Advertised,
    urls: Vec<String>,
}

/// The advertisement a mirror coin declares in its memos: which store, at which root, for which
/// epoch.
///
/// Held as one value rather than three loose fields because the three are only ever meaningful
/// together — a coin bonds a *tuple*, and comparing two of the three is the shape of the bug this
/// crate exists to make impossible.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Advertised {
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: BigInt,
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
    /// This is a one-way morph of all four advertised terms, so it names no store on its own. To
    /// learn whether this coin advertises a particular store and root, use
    /// [`advertises`](Self::advertises).
    pub fn namespace_hint(&self) -> Bytes32 {
        self.namespace_hint
    }

    /// The store this coin **declares** it mirrors.
    ///
    /// Read from the coin's memos, which is where the declaration belongs — see the module docs.
    /// A caller checking a coin it was handed by a stranger wants [`advertises`](Self::advertises),
    /// which compares this against what the caller actually asked about. This accessor is for the
    /// caller that already trusts the coin is theirs and simply wants to know what it bonds, which
    /// is the ordinary case after [`list`](crate::list).
    pub fn store_launcher_id(&self) -> Bytes32 {
        self.declared.store_launcher_id
    }

    /// The store root this coin declares it mirrors.
    ///
    /// A mirror bonds one root, not a store as a whole: this is the value that lets an owner match
    /// a coin against the `.dig` files actually on disk, and reclaim the ones that no longer are.
    pub fn root_hash(&self) -> Bytes32 {
        self.declared.root_hash
    }

    /// The epoch this coin declares it advertises for.
    pub fn epoch(&self) -> &BigInt {
        &self.declared.epoch
    }

    /// Whether this coin advertises `store_launcher_id` at `root_hash` for `epoch`.
    ///
    /// This is the sound test, and the only one. It makes **two** comparisons, and neither is
    /// redundant:
    ///
    /// 1. the coin's declared tuple equals the tuple asked about — which is what binds this
    ///    collateral to this advertisement and nothing else; and
    /// 2. the coin's hint equals the hint that tuple morphs to, using the owner taken from the
    ///    coin's own **lineage proof** rather than from any memo — which is what says the coin was
    ///    really published in that tuple's bucket instead of squatting in another.
    ///
    /// Check 1 without check 2 accepts a coin that declares one thing and is indexed as another.
    /// Check 2 without check 1 accepts a coin bonding an entirely different store, because the
    /// epoch term is free and its author can solve for a hint collision — see [`mirror_hint`].
    ///
    /// The owner is not a parameter because it does not need to be: it is recoverable from the coin
    /// ([`owner_puzzle_hash`](Self::owner_puzzle_hash)), so a verifier holding nothing but a coin id
    /// and a tuple can close the loop without trusting whoever handed the coin over.
    pub fn advertises(
        &self,
        store_launcher_id: Bytes32,
        root_hash: Bytes32,
        epoch: &BigInt,
    ) -> bool {
        let asked = Advertised {
            store_launcher_id,
            root_hash,
            epoch: epoch.clone(),
        };

        self.declared == asked
            && self.namespace_hint
                == mirror_hint(
                    store_launcher_id,
                    root_hash,
                    self.owner_puzzle_hash(),
                    epoch,
                )
    }

    /// The URLs the owner advertises for the store, in the order they were published.
    ///
    /// Unverified strings straight off the chain. Treat them as untrusted input: they have not been
    /// contacted, parsed for scheme, or bounded in number by anything but the block that carried
    /// them.
    pub fn urls(&self) -> &[String] {
        &self.urls
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
        match Self::classify(creating_spend, coin_id)? {
            Candidate::Mirror(mirror) => Ok(Some(*mirror)),
            Candidate::NotAMirror => Ok(None),
            Candidate::UndecodableMemos { detail, .. } => Err(MirrorError::Malformed(detail)),
        }
    }

    /// As [`from_creating_spend`](Self::from_creating_spend), but keeping what the execution had
    /// already established when it ran out of things it could establish.
    ///
    /// The distinction exists for one reason. A coin's OWNER comes from the lineage proof and is
    /// settled well before its memos are read; its memos are arbitrary bytes chosen by whoever spent
    /// the parent. So when the memos will not decode, the question *is this coin mine* still has an
    /// answer, and for every caller but one that answer is **no**. Collapsing the two into a single
    /// `Err` throws that answer away and turns one stranger's dust into everybody's unresolved gap.
    pub(crate) fn classify(
        creating_spend: &CoinSpend,
        coin_id: Bytes32,
    ) -> Result<Candidate, MirrorError> {
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
            return Ok(Candidate::NotAMirror);
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
                return Ok(Candidate::NotAMirror);
            };
            sibling
        };

        if inner.asset_id != Some(DIG_ASSET_ID) {
            return Err(MirrorError::NotDigCollateral {
                found: inner.asset_id,
            });
        }

        // The owner is settled from here on, whatever the memos turn out to hold.
        let owner_puzzle_hash = inner.proof.parent_inner_puzzle_hash;

        let decoded = match parse_memos(&allocator, memos) {
            Ok(decoded) => decoded,
            Err(detail) => {
                return Ok(Candidate::UndecodableMemos {
                    owner_puzzle_hash,
                    detail,
                })
            }
        };

        let Some((namespace_hint, declared, urls)) = decoded else {
            return Ok(Candidate::NotAMirror);
        };

        Ok(Candidate::Mirror(Box::new(Self {
            inner,
            namespace_hint,
            declared,
            urls,
        })))
    }

    /// The authenticated p2-parent view, for the spend builders.
    pub(crate) fn inner(&self) -> &P2ParentCoin {
        &self.inner
    }
}

/// What a candidate coin turned out to be, once its creating spend was executed.
///
/// The three cases are not three flavours of failure. They differ in **what was established**, and a
/// caller can only act correctly if that difference survives the return: two of them are settled
/// answers and one is a genuine gap in knowledge.
pub(crate) enum Candidate {
    /// A mirror coin, fully re-derived from executed on-chain code.
    ///
    /// Boxed because it is far larger than the other two variants, and both queries build one of
    /// these per candidate across a list bounded only by [`MAX_CANDIDATES`](crate::MAX_CANDIDATES) —
    /// so the unboxed enum would size every rejected candidate at the cost of an accepted one.
    Mirror(Box<MirrorCoin>),

    /// Settled as not a mirror coin: the spend created no such output, the output is a different
    /// coin, or the memos decoded cleanly and carried no advertised URLs.
    ///
    /// *Decoded and found no URLs* belongs here and nowhere else. It is a fact about the coin, read
    /// successfully — the ordinary shape of a sibling collateral coin — and it must never be
    /// confused with memos that could not be read at all.
    NotAMirror,

    /// The coin was authenticated as far as its OWNER, and then its memos would not decode.
    ///
    /// The owner is carried because it is genuinely known: it comes from the lineage proof, which is
    /// established before a single memo byte is examined. Whether this is a gap in the caller's own
    /// inventory or a stranger's malformed coin is therefore answerable, and the answer differs per
    /// caller — which is exactly why this variant refuses to decide it here.
    UndecodableMemos {
        /// The wallet that controls the coin, from its lineage proof.
        owner_puzzle_hash: Bytes32,
        /// Why the memos could not be decoded.
        detail: String,
    },
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

/// Splits a mirror coin's memos into its namespace value, its declared advertisement, and its URLs.
///
/// # The layout
///
/// ```text
/// [ hint(32) , store(32) , root(32) , epoch(signed BE) , url , url , … ]
/// ```
///
/// A fixed four-entry prefix followed by a homogeneous tail of URLs, and every prefix entry is
/// shape-checked: the three 32-byte terms must be exactly 32 bytes or the memos are not
/// mirror-shaped. That structure is deliberate. The ancestor layout was
/// `[hint, peerIp, publicSyntheticKey]`, where slot 1 was a public key that any reader following the
/// obvious rule surfaced as a bogus URL; the defence against repeating that is not care, it is a
/// prefix whose arity is fixed and whose entries cannot be mistaken for the tail.
///
/// `Ok(None)` means the memos were READ and are not mirror-shaped — absent, empty, too short, a
/// prefix entry of the wrong width, or no URLs after it. `Err(detail)` means they could not be read
/// at all. The signature keeps those apart deliberately: the first is an answer about the coin, the
/// second is the absence of one, and every caller above needs to treat them differently.
fn parse_memos(
    allocator: &Allocator,
    memos: Memos,
) -> Result<Option<(Bytes32, Advertised, Vec<String>)>, String> {
    let Memos::Some(node) = memos else {
        return Ok(None);
    };

    let entries = Vec::<Bytes>::from_clvm(allocator, node)
        .map_err(|error| format!("undecodable memos: {error}"))?;

    let Some(([namespace, store, root, epoch], advertised)) = entries.split_first_chunk::<4>()
    else {
        return Ok(None);
    };

    let (Ok(namespace_hint), Ok(store_launcher_id), Ok(root_hash)) = (
        Bytes32::try_from(namespace.as_ref()),
        Bytes32::try_from(store.as_ref()),
        Bytes32::try_from(root.as_ref()),
    ) else {
        return Ok(None);
    };

    let declared = Advertised {
        store_launcher_id,
        root_hash,
        // An empty atom is CLVM's zero, and `from_signed_bytes_be` already reads it as such.
        epoch: BigInt::from_signed_bytes_be(epoch.as_ref()),
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

    Ok(Some((namespace_hint, declared, urls)))
}
