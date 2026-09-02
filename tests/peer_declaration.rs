//! The binding between a mirror coin's owner and the DIG peer it collateralises (dig-node#473).
//!
//! Every coin here is created by a genuine CAT spend whose puzzle is executed to produce its
//! conditions -- the same execution `MirrorCoin::from_creating_spend` performs -- so a declaration
//! is read back out of real memo bytes rather than out of a struct a test assembled.
//!
//! # Why a stranger appears in nearly every fixture
//!
//! The property under test is not "a coin can carry a peer id". It is that a coin names **one**
//! peer and refuses every other, which is the whole point: coin ids are public, so a stranger can
//! republish an honest holder's coin id as its own. A fixture whose only claimant is the coin's own
//! declared peer passes identically whether the binding works or is missing entirely, so each test
//! below asks about a peer the coin did **not** name and asserts the answer is no.

use dig_mirror_coin::{
    create, declared_peer, MirrorAdvertisement, MirrorCoin, MirrorError, PeerDeclaration,
    PEER_DECLARATION_PREFIX,
};

mod support;

use support::*;

/// The peer an honest holder runs.
const PEER_H: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
/// A stranger's peer, which no coin in this file ever declares.
const PEER_STRANGER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn term(peer_id: &str) -> String {
    format!("{PEER_DECLARATION_PREFIX}{peer_id}")
}

/// Builds a real mirror coin whose advertised tail is exactly `tail`.
fn coin_advertising(tail: &[&str]) -> MirrorCoin {
    let owner = wallet(1);
    let memos = mirror_memos(&owner, store_a(), root_1(), tail);
    let (spend, coin) = creating_spend(&owner, &memos);
    MirrorCoin::from_creating_spend(&spend, coin.coin_id())
        .expect("the spend is readable")
        .expect("the spend created this mirror coin")
}

/// THE test. A coin declares the peer its owner named, and refuses a stranger asking about the same
/// coin -- which is exactly what a stranger republishing this public coin id would be doing.
#[test]
fn a_coin_names_the_peer_its_owner_declared_and_refuses_every_other() {
    let mirror = coin_advertising(&["https://h.example", &term(PEER_H)]);

    assert!(
        mirror.declares_peer(PEER_H),
        "the coin's owner declared this peer, so the coin must name it"
    );
    assert!(
        !mirror.declares_peer(PEER_STRANGER),
        "a stranger republishing this coin id is named by nothing the owner wrote"
    );
}

/// The control that says the test above measures the declaration and not the fixture: the same
/// coin, the same claimant, no declaration term -- and the answer flips.
#[test]
fn a_coin_carrying_no_declaration_names_nobody() {
    let mirror = coin_advertising(&["https://h.example"]);

    assert_eq!(mirror.declared_peer(), None);
    assert!(!mirror.declares_peer(PEER_H));
    assert!(!mirror.declares_peer(PEER_STRANGER));
}

/// Ambiguity withholds credit. One coin's collateral standing behind two peers would halve what
/// each claim costs while both still read as fully bonded, so a coin whose owner wrote two
/// declarations names neither of them.
#[test]
fn two_declarations_name_nobody_rather_than_bonding_both_at_half_price() {
    let mirror = coin_advertising(&["https://h.example", &term(PEER_H), &term(PEER_STRANGER)]);

    assert_eq!(mirror.declared_peer(), None);
    assert!(
        !mirror.declares_peer(PEER_H),
        "the first of two declarations must not win by position"
    );
    assert!(!mirror.declares_peer(PEER_STRANGER));
}

/// Two spellings of one peer id denote the same SHA-256. Comparing the text rather than the bytes
/// would withhold credit from an owner who wrote the id in the other case -- a silent authorization
/// difference produced by nothing but capitalisation.
#[test]
fn a_declaration_is_read_regardless_of_the_hex_case_it_was_written_in() {
    let mirror = coin_advertising(&["https://h.example", &term(&PEER_H.to_uppercase())]);

    assert!(mirror.declares_peer(PEER_H));
    assert!(mirror.declares_peer(&PEER_H.to_uppercase()));
    assert!(!mirror.declares_peer(PEER_STRANGER));
}

/// The prefix is matched exactly. A test loose enough to accept these is loose enough for a
/// neighbouring memo format to collide with this one later.
#[test]
fn a_prefix_lookalike_is_an_ordinary_advertised_string() {
    for lookalike in [
        format!("x{PEER_DECLARATION_PREFIX}{PEER_H}"),
        format!("dig-peer-two:{PEER_H}"),
        format!("dig-peers:{PEER_H}"),
        format!("DIG-PEER:{PEER_H}"),
    ] {
        let mirror = coin_advertising(&["https://h.example", &lookalike]);
        assert_eq!(
            mirror.declared_peer(),
            None,
            "{lookalike} must not read as a declaration"
        );
    }
}

/// A term carrying the right prefix and the wrong payload declares nothing. It cannot be a mistyped
/// peer id, because a peer id is the output of a SHA-256 and has exactly one length.
#[test]
fn a_malformed_payload_declares_nobody() {
    let too_long = format!("{PEER_H}a");
    let payloads = [
        "",
        "abc",
        // 64 characters, but `zz` is not hex.
        "zz11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899",
        &PEER_H[..63],
        &too_long[..],
    ];
    for payload in payloads {
        let mirror = coin_advertising(&["https://h.example", &term(payload)]);
        assert_eq!(
            mirror.declared_peer(),
            None,
            "payload of length {} must not declare a peer",
            payload.len()
        );
    }
}

/// A claimant whose own id is not a well-formed peer id matches nothing. There is no peer whose id
/// fails to parse, so the honest answer is "not this one" rather than an error to rank.
#[test]
fn a_claimant_that_is_not_a_peer_id_matches_no_declaration() {
    let mirror = coin_advertising(&["https://h.example", &term(PEER_H)]);

    for claimant in ["", "not-hex", &PEER_H[..10]] {
        assert!(!mirror.declares_peer(claimant), "claimant {claimant:?}");
    }
}

/// A declaration rides behind the advertised URLs, so adding one does not displace the first real
/// URL for any consumer that reads `urls()` positionally.
#[test]
fn a_declaration_does_not_displace_the_advertised_urls() {
    let mirror = coin_advertising(&[
        "https://first.example",
        "https://second.example",
        &term(PEER_H),
    ]);

    assert_eq!(mirror.urls()[0], "https://first.example");
    assert_eq!(mirror.urls()[1], "https://second.example");
    assert!(mirror.declares_peer(PEER_H));
}

/// The two questions are independent, and a consumer needs both. A coin that genuinely bonds this
/// content still names only its own peer -- which is precisely why bonding alone must not promote a
/// claimant.
#[test]
fn bonding_the_content_and_naming_the_claimant_are_separate_answers() {
    let mirror = coin_advertising(&["https://h.example", &term(PEER_H)]);

    assert!(
        mirror.advertises(store_a(), root_1(), &epoch()),
        "the coin really does bond this content"
    );
    assert!(
        mirror.declares_peer(PEER_H),
        "and it names its own peer -- asserted so this test varies with the parser"
    );
    assert!(
        !mirror.declares_peer(PEER_STRANGER),
        "and it still names only the peer its owner declared"
    );
}

/// A peer id round-trips to canonical lowercase hex whatever case it arrived in.
#[test]
fn a_peer_id_normalises_to_lowercase_hex() {
    let lower = PeerDeclaration::from_hex(PEER_H).expect("well formed");
    let upper = PeerDeclaration::from_hex(&PEER_H.to_uppercase()).expect("well formed");

    assert_eq!(lower, upper);
    assert_eq!(lower.to_hex(), PEER_H);
    assert_eq!(upper.to_hex(), PEER_H);
    assert_eq!(lower.to_term(), term(PEER_H));
}

/// Reading a peer id that is not one is an error rather than a silently truncated value.
#[test]
fn a_peer_id_of_the_wrong_shape_is_refused() {
    let too_long = format!("{PEER_H}a");
    for bad in ["", "abc", &PEER_H[..63], &too_long[..]] {
        assert!(PeerDeclaration::from_hex(bad).is_err(), "{bad:?}");
    }
}

/// The term the writer emits is the term the reader reads. This is the format agreement itself,
/// asserted without a chain in the way, so a divergence names the format rather than the fixture.
#[test]
fn the_written_term_is_the_term_that_is_read() {
    let declaration = PeerDeclaration::from_hex(PEER_H).expect("well formed");

    assert_eq!(
        declared_peer(&[declaration.to_term()]),
        Some(declaration),
        "the reader must read back exactly what the writer emits"
    );
}

/// `create` refuses a declaration smuggled in as an advertised URL.
///
/// The typed `declared_peer` field is what makes "one coin declares at most one peer" a property of
/// the type rather than a comment. Both it and `urls` are written verbatim into the same memo tail,
/// so without this refusal a caller could write a declaration -- or a second one -- without ever
/// touching the field, and the guarantee would be worth nothing. Refused rather than filtered: a
/// caller that passed one meant something by it.
///
/// The advertisement is otherwise well formed and the funding list is empty, so the guard is the
/// only thing that can produce this error; the honest control below proves the same call shape
/// reaches past it.
#[test]
fn create_refuses_a_declaration_smuggled_in_as_an_advertised_url() {
    let owner = wallet(4);

    let smuggled = create(
        MirrorAdvertisement {
            declared_peer: None,
            store_launcher_id: store_a(),
            root_hash: root_1(),
            epoch: epoch(),
            urls: vec!["https://h.example".to_string(), term(PEER_H)],
            collateral: 1_000,
        },
        Vec::new(),
        owner.public_key,
        Vec::new(),
        0,
    );

    match smuggled {
        Err(MirrorError::Malformed(message)) => assert!(
            message.contains("declared_peer"),
            "the refusal must name the field to use instead; got {message:?}"
        ),
        other => panic!("a smuggled declaration must be refused, got {other:?}"),
    }

    // Control: the identical call without the smuggled term gets PAST this guard. It still fails --
    // there are no coins to fund it -- but it fails for a different reason, which is what says the
    // assertion above measured the guard rather than the empty funding list.
    let honest = create(
        MirrorAdvertisement {
            declared_peer: Some(PeerDeclaration::from_hex(PEER_H).expect("well formed")),
            store_launcher_id: store_a(),
            root_hash: root_1(),
            epoch: epoch(),
            urls: vec!["https://h.example".to_string()],
            collateral: 1_000,
        },
        Vec::new(),
        owner.public_key,
        Vec::new(),
        0,
    );

    assert!(
        !matches!(&honest, Err(MirrorError::Malformed(message)) if message.contains("declared_peer")),
        "the honest advertisement must not trip the smuggling guard"
    );
}

/// A claimant id that is 64 BYTES but not 64 characters must be refused, not panicked on.
///
/// `peer_id` reaches the parser from a provider record a stranger wrote. Indexing it as `&str`
/// slices panics when a two-byte index lands inside a multi-byte character -- and a string of 32
/// two-byte characters passes a `len() == 64` test while doing exactly that. A panic in a verifier
/// reached from peer-supplied input is a denial of service, so this asserts the refusal rather than
/// trusting the length check to imply it.
#[test]
fn a_sixty_four_byte_claimant_that_is_not_sixty_four_characters_is_refused_not_panicked_on() {
    let multibyte: String = "\u{00e9}".repeat(32);
    assert_eq!(
        multibyte.len(),
        64,
        "the fixture must be 64 BYTES for this to be the trap"
    );
    assert_ne!(
        multibyte.chars().count(),
        64,
        "and must not be 64 characters"
    );

    assert!(PeerDeclaration::from_hex(&multibyte).is_err());

    let mirror = coin_advertising(&["https://h.example", &term(PEER_H)]);
    assert!(!mirror.declares_peer(&multibyte));

    // And the same shape arriving as the coin's own declaration term.
    let odd = coin_advertising(&["https://h.example", &term(&multibyte)]);
    assert_eq!(odd.declared_peer(), None);
}
