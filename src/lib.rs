//! # dig-mirror-coin — mirror coins, and the $DIG they lock
//!
//! A **mirror coin** advertises that a peer serves a DIG store, and it does so by
//! **locking $DIG as collateral**. The stake is the point: anyone can *claim* to mirror a
//! store, but only a holder willing to lock $DIG can make that claim cost something.
//!
//! ## What this crate is for, and what it deliberately is not
//!
//! This crate owns **mirror** coins only. Its ancestor in `DataLayer-Driver` — `DigCollateralCoin`
//! — serves two namespaces at once, morphing a store launcher id into *either* a store-collateral
//! or a mirror-collateral namespace. Splitting the mirror half out is the point of this crate: the
//! two have different lifetimes, different spenders and different reasons to exist, and sharing one
//! type made every caller reason about both.
//!
//! ## Naming
//!
//! `DataLayer-Driver` calls the XCH-collateralised variant a **server coin**; the on-chain puzzle it
//! curries has always been called the **mirror puzzle** (`MIRROR_PUZZLE`, `MirrorArgs`,
//! `MirrorSolution`). This crate uses **mirror coin** throughout, which is the name the chain
//! already uses.
//!
//! ## The collateral is a CAT, not XCH
//!
//! $DIG is a CAT, so a mirror coin does **not** sit at its owner's puzzle hash — it sits at the
//! OUTER hash that curries the asset id (TAIL) around the owner's inner p2 hash, and is merely
//! *hinted* to the p2 hash so a wallet can find it. A hint is an unauthenticated `CREATE_COIN` memo
//! over an arbitrary 32 bytes, so **a hint is not proof of an asset** and must never be read as one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Placeholder while the migration from `DataLayer-Driver`'s `DigCollateralCoin` lands.
///
/// Tracked on the superproject epic; this constant exists so the crate compiles and publishes its
/// scaffolding before the implementation arrives, and it will be removed by that migration.
pub const MIGRATION_PENDING: bool = true;
