//! # dig-mirror-coin — mirror coins, and the $DIG they lock
//!
//! A **mirror coin** advertises that a peer serves a DIG store, and it does so by **locking $DIG as
//! collateral**. The stake is the point: anyone can *claim* to mirror a store, but only a holder
//! willing to lock $DIG can make that claim cost something.
//!
//! ## Four verbs
//!
//! | verb | what it does |
//! |---|---|
//! | [`create`] | locks $DIG and publishes a mirror for one root of a store |
//! | [`list`] | answers *which mirror coins are mine* |
//! | [`discover`] | answers *does this peer bond this store at this root* |
//! | [`reclaim`] | releases the collateral back to its owner |
//!
//! ## A mirror bonds a ROOT, not a store
//!
//! A store changes, and a publisher funding mirrors must be able to pay for the current root and
//! decline the ones before it. So a mirror coin is per `(store, root, owner, epoch)`: one coin per
//! root a peer actually holds, and a node's coin exists exactly while the `.dig` for that store at
//! that root is on its disk. Withdrawing a root is [`reclaim`] on its coin, and it takes the money
//! back with it.
//!
//! Because the owner is one of the four terms, [`discover`] checks a **named** peer's bond rather
//! than enumerating a store's mirrors. Peers come from the DHT; what this crate answers is whether
//! the collateral behind a peer's claim is real and is staked on the root being asked for.
//!
//! [`list`] and [`discover`] are separate on purpose. They are keyed differently, trusted
//! differently, and an empty answer means something different in each — see [`query`].
//!
//! ## Reclaim returns the money
//!
//! [`reclaim`] recreates the full locked amount at the owner's puzzle hash. There is no path in this
//! crate that reduces $DIG supply, and none may be added to `reclaim`: burning supply through a CAT
//! TAIL is a different operation with the opposite outcome, and would get its own name.
//!
//! ## The collateral is a CAT, not XCH
//!
//! $DIG is a CAT, so a mirror coin does not sit at its owner's puzzle hash. It sits at the OUTER
//! hash currying the asset id around the collateral puzzle, produced by the canonical CAT
//! construction and never assembled by hand. Ownership lives in the coin's lineage proof, so every
//! mirror coin in existence shares one puzzle hash — which is why finding a particular store's
//! mirrors needs a hint, and why a hint is never believed on its own.
//!
//! ## A hint is not evidence
//!
//! A hint is an unauthenticated `CREATE_COIN` memo over arbitrary bytes; anyone may hint any coin to
//! any value for the price of a dust coin. This crate uses hints only to decide *where to look*.
//! Which asset is locked, how much, and who controls it are always re-derived from the coin's
//! creating spend — the parent's real puzzle reveal and solution, executed.
//!
//! ## A mirror coin is not availability
//!
//! It proves $DIG is locked. It does not prove the owner serves the store, that the advertised URLs
//! resolve, or that anything is fetchable. [`discover`] returns a [`MirrorSet`] of *claims* for
//! exactly this reason. Availability is established by fetching, and only by fetching.
//!
//! ## Scope
//!
//! Mirror coins only. The ancestor type in `DataLayer-Driver` served two namespaces at once —
//! store-collateral and mirror-collateral — and splitting the mirror half out is the point of this
//! crate. The store-collateral namespace is deliberately absent, and this crate carries no
//! `datalayer-driver` dependency: it owns its code.
//!
//! ## Chain access
//!
//! This crate is a primitive and pulls no network stack down into itself. Reads arrive through the
//! ecosystem's canonical [`ChainSource`](dig_chainsource_interface::ChainSource) trait, extended
//! with the single hint lookup that trait does not expose ([`MirrorChainSource`]). Nothing here
//! opens a socket, holds a key, signs, or broadcasts: the spend builders return unsigned coin spends
//! for the caller's own signer to complete.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod asset;
pub mod census;
mod coin;
mod create;
mod error;
mod namespace;
pub mod query;
mod reclaim;

pub use asset::{mirror_coin_puzzle_hash, DIG_ASSET_ID};
pub use census::{census, census_height, CensusHeight, CensusOutcome, Exclusions, MirrorCensus};
pub use coin::MirrorCoin;
pub use create::{create, MirrorAdvertisement};
pub use error::MirrorError;
pub use namespace::{mirror_hint, MIRROR_NAMESPACE};
pub use query::{
    discover, list, MirrorChainSource, MirrorInventory, MirrorSet, SkipReason, SkippedCandidate,
    MAX_CANDIDATES,
};
pub use reclaim::reclaim;

/// The crate version, sourced from `Cargo.toml` at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
