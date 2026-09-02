//! The declaration that binds a mirror coin to the DIG peer it collateralises.
//!
//! # Why a memo term is an authority, when a memo is normally not
//!
//! Everywhere else in this crate a memo is treated as the one part of a mirror coin its publisher
//! writes freely, and is trusted for nothing: [`MirrorCoin::advertises`](crate::MirrorCoin::advertises)
//! deliberately re-derives the owner from the coin's own lineage proof rather than reading it from a
//! memo. That caution is about the wrong question. A memo cannot tell you who owns a coin, because
//! anyone can write any bytes into their own coin's memos.
//!
//! It can tell you what the **owner said**. Memos are written by the spend that creates the coin,
//! and only the owner's key can produce that spend, so a term the coin carries is a statement by the
//! coin's owner attested by executed on-chain code. That is exactly the missing property: a mirror
//! coin proves collateral is locked, and until now nothing connected that collateral to the peer
//! offering to serve the content.
//!
//! So the coin names the peer it stands behind. No new authority, no new key, and no change to any
//! wire format — the term rides in memo space the format already reserves for the owner's free use.
//!
//! # What this does NOT establish
//!
//! The declaration binds **coin to peer id**. It does not bind a peer id to a network address, and
//! nothing here should be read as if it did. A record naming an honest holder's peer id, that
//! holder's real coin id, and an attacker's addresses satisfies this check completely. Closing that
//! is the consumer's problem and needs a different mechanism; see `SPEC.md`.
//!
//! # At most one peer, and that is an economic rule
//!
//! A coin declares **one** peer or none. The collateral is what makes a claim cost something, so a
//! coin standing behind fifty peers would make each of those claims cost a fiftieth as much while
//! every one of them still read as fully bonded — the guarantee would quietly dilute in proportion
//! to a number the claimant chooses. An owner who wants two peers bonded creates two coins and
//! locks the collateral twice, which is the price the design intends.
//!
//! Both ends hold this. [`MirrorAdvertisement::declared_peer`](crate::MirrorAdvertisement) is an
//! `Option`, which cannot represent two, and [`create`](crate::create) refuses an advertised URL
//! carrying the declaration prefix — the two write into the same memo tail, so the typed field is a
//! guarantee only because the untyped path beside it is closed. A coin that nonetheless carries two
//! or more declaration terms — which only its own owner could have written — declares **nobody**: an
//! ambiguous coin withholds credit rather than granting it to a guess.
//!
//! **The count is over the terms this crate can READ**, which are the UTF-8-decodable ones: a memo
//! entry that is not valid UTF-8 is dropped before it reaches here. An owner can therefore publish a
//! tail whose raw bytes hold two prefixed entries where only one decodes, and this crate credits
//! that one. The divergence is bounded and self-inflicted — only the coin's own owner can write such
//! a tail, and the strictest reading credits nobody rather than someone else — but it is stated in
//! `SPEC.md` §5.1 rather than left for two implementations to discover separately.

use crate::MirrorError;

/// The prefix that marks an advertised memo term as a peer declaration.
///
/// Matched exactly. `dig-peer-two:` and `xdig-peer:` are ordinary advertised strings and are not
/// declarations, because a prefix test loose enough to accept them is loose enough for a
/// neighbouring format to collide with this one later.
pub const PEER_DECLARATION_PREFIX: &str = "dig-peer:";

/// The DIG peer id a mirror coin's owner declared it collateralises.
///
/// Held as the 32 raw bytes rather than as the text that carried them, so that every comparison is
/// a comparison of hashes. Two spellings of one peer id — upper and lower case hex — denote the same
/// `SHA-256(TLS SPKI DER)` and must not produce different answers; comparing the strings would
/// silently withhold credit from an owner who wrote the same id in the other case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerDeclaration([u8; 32]);

impl PeerDeclaration {
    /// Reads a peer id written as 64 hex characters, in either case.
    ///
    /// `Err` for anything that is not exactly 32 bytes of hex. A peer id is the output of a
    /// SHA-256, so a value of any other length is not a peer id that was mistyped — it is a
    /// different kind of thing.
    pub fn from_hex(peer_id: &str) -> Result<Self, MirrorError> {
        // Indexed as BYTES, never as `&str` slices. `peer_id` reaches this function from a provider
        // record a stranger wrote, and `&peer_id[i..i + 2]` panics when `i` lands inside a
        // multi-byte character -- which a 64-BYTE string of two-byte characters produces while
        // passing a `len() == 64` check. A panic in a verifier reached from peer-supplied input is a
        // denial of service, so the length test alone is not enough and the parse works on bytes.
        let raw = peer_id.as_bytes();
        if raw.len() != 64 {
            return Err(MirrorError::Malformed(format!(
                "a DIG peer id is 64 hex characters; got {}",
                raw.len()
            )));
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let (high, low) = (hex_digit(raw[index * 2]), hex_digit(raw[index * 2 + 1]));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(MirrorError::Malformed(
                    "a DIG peer id is 64 hex characters".to_string(),
                ));
            };
            *byte = (high << 4) | low;
        }
        Ok(PeerDeclaration(bytes))
    }

    /// The declared peer id as canonical lowercase hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The raw 32 bytes of the declared peer id.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether this declaration names `peer_id`, compared as bytes.
    ///
    /// A `peer_id` that is not itself well-formed matches nothing. There is no peer whose id fails
    /// to parse, so the honest answer for such an input is "not this one" rather than an error the
    /// caller would have to decide how to rank.
    pub fn names(&self, peer_id: &str) -> bool {
        matches!(PeerDeclaration::from_hex(peer_id), Ok(other) if other == *self)
    }

    /// The memo term that carries this declaration, as [`create`](crate::create) writes it.
    pub fn to_term(&self) -> String {
        format!("{PEER_DECLARATION_PREFIX}{}", self.to_hex())
    }
}

/// The single peer an advertised memo tail declares, if it declares exactly one.
///
/// `None` covers three genuinely different situations that a consumer must treat identically,
/// because all three mean the coin has not named this claimant: no declaration term at all (every
/// coin created before this format existed), a declaration that will not parse, and **two or more**
/// declarations (see the module docs — ambiguity withholds credit rather than picking one).
///
/// The scan is linear in the number of advertised terms. That list was parsed out of a block, so its
/// length is already bounded by what an owner was willing to pay to publish, and the walk is
/// arithmetic on memory the caller is holding either way — it costs nothing next to the chain reads
/// a consumer performs before reaching this point. No entry is skipped or truncated: a bound applied
/// here would silently withhold credit from a legitimate declaration that happened to sit past it.
pub fn declared_peer(advertised_terms: &[String]) -> Option<PeerDeclaration> {
    let mut declared = None;
    for term in advertised_terms {
        // Counted by PREFIX rather than by successful parse. A coin carrying two declaration terms
        // is ambiguous whether or not both of them read, and resolving that ambiguity by discarding
        // the half that failed to parse would let the answer depend on which malformed spelling its
        // owner happened to use.
        let Some(payload) = term.strip_prefix(PEER_DECLARATION_PREFIX) else {
            continue;
        };
        if declared.is_some() {
            return None;
        }
        declared = Some(PeerDeclaration::from_hex(payload).ok());
    }
    declared.flatten()
}

/// The value of one hexadecimal digit, or `None` for any other byte.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
