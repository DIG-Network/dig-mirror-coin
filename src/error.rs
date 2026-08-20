//! [`MirrorError`] — why a mirror-coin operation could not be completed.
//!
//! The split that matters most here is between **"the chain says no"** and **"the chain did not
//! say"**. The query verbs ([`list`](crate::list), [`discover`](crate::discover)) never report an
//! absence as an error: an owner with no mirror coins, or a store nobody mirrors, is a successful
//! read that happens to be empty. An error from those verbs always means the answer could not be
//! established, and a caller MUST fail closed on it rather than reading it as "nobody mirrors this".

use chia_protocol::Bytes32;
use chia_sdk_driver::DriverError;
use thiserror::Error;

/// The reason a mirror-coin operation failed.
///
/// `#[non_exhaustive]`: new failure modes may arrive in a minor release, so consumers MUST include
/// a wildcard match arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MirrorError {
    /// A chain source could not reliably answer a read.
    ///
    /// **This is never an absence.** It means the question went unanswered — a transport failure, a
    /// timeout, an unsupported query, a malformed response. A caller MUST NOT degrade this into an
    /// empty result; see [`crate::MirrorSet`] for the distinction the query verbs preserve.
    #[error("chain source could not answer: {0}")]
    ChainUnavailable(String),

    /// A coin was read successfully but is not a $DIG-collateralised mirror coin.
    ///
    /// Carries the asset id actually curried into the coin's puzzle, if it had one at all. `None`
    /// means the coin was plain XCH rather than a CAT.
    #[error("coin is collateralised in {found:?}, not $DIG")]
    NotDigCollateral {
        /// The CAT asset id the coin's puzzle actually curries, or `None` for a bare XCH coin.
        found: Option<Bytes32>,
    },

    /// The spend was refused because the coin is controlled by a different wallet.
    ///
    /// Ownership is proven from the coin's lineage proof — the inner puzzle hash of its parent —
    /// never from a hint, which anyone may place.
    #[error("mirror coin {coin_id} is controlled by another wallet")]
    NotOwner {
        /// The coin whose ownership check failed.
        coin_id: Bytes32,
    },

    /// A coin presented for reclaim has already been spent, so its collateral is no longer locked.
    #[error("mirror coin {coin_id} has already been spent")]
    AlreadySpent {
        /// The coin that was already spent.
        coin_id: Bytes32,
    },

    /// The creating spend of a candidate coin could not be found, so the coin could not be
    /// authenticated as a mirror coin.
    ///
    /// A hint index can point at any coin at all; without its creating spend there is no evidence
    /// of what the coin is, and this crate refuses to guess.
    #[error("no creating spend found for coin {coin_id}; cannot authenticate it")]
    Unauthenticated {
        /// The coin that could not be authenticated.
        coin_id: Bytes32,
    },

    /// On-chain data was read but could not be interpreted (an undecodable memo, a puzzle that did
    /// not run). The read is untrustworthy, so the operation fails closed.
    #[error("malformed chain data: {0}")]
    Malformed(String),

    /// A puzzle construction or spend-building step failed inside the Chia driver layer.
    ///
    /// Boxed because `DriverError` is large and would otherwise bloat every `Result` in the crate.
    #[error("chia driver error: {0}")]
    Driver(#[from] Box<DriverError>),
}

impl From<DriverError> for MirrorError {
    fn from(error: DriverError) -> Self {
        Self::Driver(Box::new(error))
    }
}
