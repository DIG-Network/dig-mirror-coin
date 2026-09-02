# dig-mirror-coin — normative specification

## 1. Scope

A **mirror coin** is a coin that locks **$DIG** as collateral to advertise that its owner serves a
given DIG store. This crate defines the mirror coin and the four operations on it: **create**,
**list**, **discover**, **reclaim**.

This crate MUST NOT define store-collateral coins. Its ancestor type serves both namespaces; the
split is deliberate, because the two have different lifetimes and different spenders.

This crate MUST own its implementation. It MUST NOT depend on `datalayer-driver` and MUST NOT be a
re-export layer over another crate.

## 2. Naming

The on-chain puzzle is the **mirror puzzle**. This crate names its wrapper **mirror coin**. The name
*server coin* is `DataLayer-Driver`'s and MUST NOT appear in this crate's public API.

The operation that returns locked collateral to its owner is named **reclaim**. It MUST NOT be named
*melt*: in CAT terms a melt burns supply through the TAIL, which is the opposite outcome.

## 3. Invariants

1. **The collateral is a CAT.** A mirror coin sits at the OUTER puzzle hash currying the $DIG asset
   id around the collateral puzzle. An implementation MUST derive it through the canonical CAT
   construction (`CatArgs::curry_tree_hash`), MUST NOT derive it by hand, and MUST NOT infer the
   asset from a hint.

   As of the chia-wallet-sdk 0.36 line that value is
   `f2ed90e749738d6167bc51470572af94695f98dc51d6ee09673aafdd54601e9d`. It is stated here because it
   is **derived, not chosen**: it depends on upstream puzzle bytes, and it changed once already when
   `chia-sdk-types` replaced `DEFAULT_CAT_MAKER_PUZZLE` between 0.30 and 0.36 (it was
   `e991be5f…` on the 0.30 line). An implementation MUST re-derive it rather than copy it, and MUST
   treat a change in this value as a wire-breaking event.
2. **A hint is not an asset, and not an owner.** Hints are unauthenticated `CREATE_COIN` memos over
   arbitrary 32-byte values. Anyone may place a coin under anyone's hint for the price of a dust
   coin, so a hint MUST NOT be treated as evidence of ownership, of asset identity, or of which
   store a coin advertises. A hint MAY be used only to decide where to look.
3. **Advertising is a claim; the collateral is the cost.** Nothing about a mirror coin proves the
   owner actually serves the store. It proves only that $DIG is locked. A consumer MUST NOT read a
   mirror coin as evidence of availability.
4. **Reclaim is explicit.** Collateral returns to its owner only through a deliberate spend.
5. **No path in this crate reduces $DIG supply.** `reclaim` MUST recreate the full locked amount.
   Any supply-reducing operation MUST have its own name and MUST NOT be reachable from `reclaim`.
6. **This crate performs no I/O and holds no keys.** Chain reads arrive through a caller-supplied
   [`ChainSource`]; spend builders return unsigned coin spends. The crate MUST NOT open a socket,
   sign, or broadcast.

## 4. The namespace

A mirror advertisement is the tuple `(store_launcher_id, root_hash, owner_puzzle_hash, epoch)`. It
MUST be morphed into the mirror namespace before use as a hint:

```
morph(store, root, owner, epoch) =
    tree_hash( (int(store) + int(root) + int(owner) + epoch, "DIG_STORE_MIRROR_COLLATERAL") )
```

where `int(...)` reads a 32-byte value as a big-endian signed integer. `DIG_STORE_MIRROR_COLLATERAL`
is a wire constant.

A mirror coin bonds **one root of one store**, not a store as a whole. A publisher MUST be able to
fund the current root and decline earlier ones, and a node's mirror coin for a store and root SHOULD
exist exactly while the `.dig` file for that store at that root is held.

The morph is one-way and MUST NOT be inverted. A consumer that needs to know what a coin advertises
MUST bring candidate terms and compare, per §4.1.

### 4.1 The namespace value is an index and MUST NOT be treated as a binding

The morph is a sum, so distinct tuples produce an identical value: `(store, root, owner, epoch)` and
`(store + 1, root - 1, owner, epoch)` collide by construction. A namespace value therefore identifies
no advertisement on its own, which is a further reason §3.2 binds.

For the three 32-byte terms the collision is unreachable in practice — a launcher id, a merkle root
and a puzzle hash are each the output of a hash, so steering their sum onto a chosen target is a
2^256 search. **The epoch is not.** It is an unbounded integer chosen freely by whoever builds the
coin, so its author can solve for a value that places a coin bonding their own store and root exactly
on another advertisement's hint:

```
e' = store + root + owner + epoch - store' - root' - owner'
```

Accepting a coin on a recomputed hint alone would therefore let **one stake back unlimited claims**.

An implementation MUST NOT decide what a coin advertises from the namespace value alone. A mirror
coin MUST declare its own `(store, root, epoch)` in its memos (§5), and a consumer checking a coin
against an advertisement MUST perform BOTH of:

1. compare the coin's **declared** tuple, term by term, against the tuple asked about; and
2. recompute the namespace value from the tuple asked about and the owner taken from the coin's
   **lineage proof**, and compare it against the coin's namespace value.

Neither check substitutes for the other. Check 1 alone accepts a coin that declares one advertisement
and is indexed as another; check 2 alone accepts a coin bonding an entirely different store, by the
epoch solution above.

The owner MUST be taken from the lineage proof and MUST NOT be taken from a caller-supplied argument
or a memo. It is the one term of the four recoverable from the coin itself, which is what lets a
consumer holding only a coin close the loop without trusting whoever supplied it.

## 5. Authentication

A candidate coin MUST be re-derived from the spend that CREATED it — the parent's puzzle reveal run
against its solution — before any property of it is believed.

The reveal MUST first be bound to the coin it claims to belong to: its tree hash MUST equal that
coin's puzzle hash, and an implementation MUST reject the spend otherwise, per §7 — a reveal a source
supplied and nothing checked is not chain evidence. Every property below is read out of the reveal,
including the owner, so an unbound reveal lets whoever supplies the spend choose all of them. The
coin-id match that selects among a parent's several outputs does NOT establish this: a child's coin id
is a hash of the parent's id, the mirror puzzle hash and the amount, and the parent's inner puzzle
appears in none of them, so a substituted reveal leaves the coin id identical while re-attributing the
coin.

From that execution an implementation MUST take:

- the **asset id**, from the parent's curried CAT puzzle. It MUST equal the $DIG asset id.
- the **amount**, from the matching `CREATE_COIN` condition.
- the **owner**, from the lineage proof's parent inner puzzle hash.
- the **namespace value, the declared advertisement, and the URLs**, from the `CREATE_COIN` memos,
  in this layout:

  ```
  [ hint(32) , store(32) , root(32) , epoch(signed big-endian) , url , url , … ]
  ```

  The prefix has fixed arity. Entries 0, 1 and 2 MUST each be exactly 32 bytes; entry 3 is the epoch
  as a minimal signed big-endian integer, where an empty atom denotes zero. Every remaining entry is
  a URL. An implementation MUST reject as not-mirror-shaped any memo list shorter than five entries
  or whose fixed-width entries are the wrong width — a heterogeneous prefix read positionally without
  shape checks is how the ancestor layout `[hint, peerIp, publicSyntheticKey]` surfaced a public key
  as a URL.

  The declared advertisement is the ONE property taken from the memos, and §4.1 states why: whoever
  locks the collateral chooses what to stake it on, so the declaration is theirs to make and a
  consumer's obligation is to compare it against what it asked about rather than to assume it.

A coin whose creating spend cannot be read MUST NOT be accepted.

One spend MAY create several collateral coins, and each of them locks its owner's $DIG. An
implementation MUST select the parent output whose derived coin id equals the candidate's, and MUST
NOT select the first output at the collateral puzzle hash: doing so loses every coin after the first
while its collateral remains locked on chain, with no error and no error to report.

A coin whose memos DECODE and carry no URLs is NOT a mirror coin and MUST be excluded. This excludes
sibling collateral coins sharing the same puzzle hash. It is a necessary condition only: memo shape is
chosen by whoever spends the parent, so it MUST NOT be relied on against an adversary.

**Memos that decode and say nothing, and memos that cannot be decoded, are different facts and MUST
NOT share a representation.** The first is an answer about the coin — read successfully, and the
ordinary shape of a sibling collateral coin. The second is the absence of an answer. They are a word
apart in English and opposite in consequence, and an implementation returning the same value for both
makes the difference unrecoverable for every layer above it. That is the shape of defect this
specification has already produced once (§7), so it is stated here at the level where it arises.

An implementation MUST also carry forward what was established BEFORE the memos were read. The
**owner** comes from the lineage proof and is settled at that point; the memos are arbitrary bytes
chosen by whoever spent the parent. A coin with undecodable memos therefore still has a known owner,
and §6.2 requires that owner to remain available rather than be discarded with the memo failure.

### 5.1 The peer declaration

A mirror coin MAY declare the **DIG peer** its collateral stands behind. The declaration is an
advertised memo term of the exact form `dig-peer:<64 lowercase hex characters>`, naming a
`peer_id` as defined by the DIG peer network (`SHA-256` of the TLS SubjectPublicKeyInfo DER).

Every other statement in §5 says a memo MUST NOT be believed. This one is different, and the
difference is precise: a memo cannot establish **who owns** a coin, because anyone may write any
bytes into their own coin's memos — but it does establish **what the owner said**, because the memos
are written by the spend that creates the coin and only the owner's key can produce that spend. The
declaration is therefore an owner attestation carried by executed on-chain code, and it is the only
memo-derived value in this specification that an implementation MAY rely on against an adversary.

A conforming implementation:

1. MUST match the prefix `dig-peer:` exactly. `DIG-PEER:`, `dig-peers:` and `xdig-peer:` are
   ordinary advertised strings.
2. MUST compare peer ids as the 32 BYTES they denote, never as text. One peer id has two hex
   spellings, and treating them as different peers withholds credit on capitalisation alone.
3. MUST treat a coin carrying **two or more** terms with the declaration prefix as declaring
   **nobody**, whether or not each parses. This is an economic rule, not a parsing convenience: the
   collateral is what makes a claim cost something, so one coin standing behind several peers would
   make each claim cost a fraction as much while every one still read as fully bonded. An owner who
   wants two peers bonded MUST create two coins and lock the collateral twice.
4. MUST treat a term whose payload is not exactly 64 hex characters as declaring nobody, and MUST
   NOT fail on it. A peer id is a `SHA-256` output and has exactly one length.
5. MUST NOT panic on any claimant string. A claimant id arrives from a provider record written by a
   stranger, so it may be any bytes at all — including a 64-BYTE string that is not 64 characters.
6. MUST place the declaration AFTER the advertised URLs in the memo tail, so adding one does not
   displace the first URL for a consumer reading the list positionally.
7. MUST NOT treat the absence of a declaration as evidence of anything. Every coin created before
   this format existed carries none.

**What the declaration establishes, and what it does not.** It binds a **coin to a peer id**. It
does not bind a peer id to a network address, and an implementation MUST NOT read it as if it did: a
provider record carrying an honest holder's peer id, that holder's real coin id, and an attacker's
addresses satisfies this check completely. Closing that requires the consumer's transport to pin the
dialled peer id against the presented certificate, which is a property of the transport and not of
this crate. A consumer whose transport does not pin MUST NOT use a declaration to rank a holder.

## 6. The verbs

### 6.1 create

Locks collateral and publishes a mirror for one root of one store. The advertisement MUST name a
store, a root and an epoch, and the coin it produces MUST both be hinted to their morph (§4) and
declare them in its memos (§5) — a coin whose hint and declaration disagree bonds nothing (§4.1).

The advertisement MUST carry at least one URL, and the
collateral MUST be non-zero — a claim staked on nothing is free, and §3.3 makes the cost the entire
point of the coin. An implementation MUST NOT impose a higher floor: how much collateral is *enough*
is an economic question for the network, and a number fixed here would become a wire constant.

The returned coin spends are unsigned.

### 6.2 list — keyed by owner

Answers *which mirror coins are mine*. An implementation MUST scan the shared mirror puzzle hash and
keep coins whose authenticated lineage proof names the caller's puzzle hash.

An empty result MUST mean the owner has locked no collateral, and MUST NOT be presented that way when
the scan stopped early (§6.5).

A candidate that cannot be authenticated MUST NOT abort the read (§6.5), and MUST NOT be dropped in
silence either. It MUST be reported to the caller, identified by coin id and with the reason it could
not be resolved, and the result MUST expose whether any such candidate was met — so a caller that
would rather refuse than under-report its own money can fail closed on that signal. A silently short
inventory understates the owner's money; a deniable one hands every user's inventory, and with it the
route to `reclaim`, to whoever places one dust coin.

A candidate settled as *not the caller's* — somebody else's mirror coin, a coin advertising no URLs,
collateral that is not $DIG — is not unresolved and MUST NOT be reported as such.

**A coin with undecodable memos whose OWNER is not the caller is settled too, and MUST NOT be reported
as unresolved.** The owner is known regardless of the memos (§5), so the question *is this coin mine*
has an answer, and for every caller but one that answer is no. An implementation that reports it to
all of them makes the completeness signal jammable: one mojo at the shared puzzle hash would hold it
false for every caller forever, and a consumer following the fail-closed advice above would then be
denied exactly as thoroughly as an aborting `list` denied everybody. That is this section's own defect
displaced one level up, and it MUST NOT be reintroduced there.

The caller's OWN unreadable coin MUST still be reported. Only the wallet controlling a coin can have
written its memos, so that gap is real, is theirs, and is what the signal exists to convey.

### 6.3 discover — keyed by the whole advertisement

Answers *does this owner bond this store, at this root, for this epoch*. An implementation MUST look
up the advertisement's namespace value in a hint index, then re-derive each candidate per §5 and keep
only those that satisfy BOTH checks of §4.1.

The owner is a required input. Because it is one of the four morphed terms there is no store-wide
bucket to enumerate, so this verb checks a **named** peer's bond and MUST NOT be described as a
census of a store's mirrors. Peer discovery is the DHT's job; what this verb establishes is that the
collateral behind a named peer's claim is real and is staked on the root asked for.

Naming an owner MUST NOT make another owner's coin answer. The owner used in check 2 of §4.1 comes
from the coin's lineage proof, so a caller that names the wrong owner receives an empty result rather
than somebody else's coin.

An empty result MUST mean the source was consulted and found no such bond, and MUST NOT be presented
that way when the scan stopped early (§6.5).

A candidate that fails authentication MUST be dropped and counted, not fatal — the hint index is
writable by anyone, and one dust coin MUST NOT be able to suppress every honest mirror. A source that
could not ANSWER is different and MUST produce an error.

`discover` MUST NOT present its result as availability (§3.3).

### 6.4 reclaim

Releases collateral to its owner. An implementation MUST refuse the spend when the supplied key does
not match the coin's authenticated owner. It MUST recreate the entire locked amount as $DIG at the
owner's address, and MUST draw any fee from separately supplied XCH coins rather than from the
collateral.

The recreated coin MUST be hinted to the owner's puzzle hash. A CAT coin's puzzle hash reveals
nothing about its owner, so wallets locate one by hint: unhinted collateral is absent from the balance
its owner is shown, which is indistinguishable to that person from collateral that never returned.

### 6.5 Both queries are bounded, and a bound is never a refusal

Both queries walk lists that anyone may extend for the price of a dust coin, so each MUST bound the
number of candidates it examines in one call.

Reaching the bound MUST stop the scan and MUST be reported to the caller. It MUST NOT produce an
error: refusing at a limit would hand an attacker a cheaper form of the denial the bound exists to
prevent. It MUST NOT be silent either, because a truncated scan cannot support the claims an
untruncated one supports — §6.2's *this is your whole inventory* and §6.3's *nobody advertises this
store* both require a scan that reached the end.

## 7. Fail-closed reads

Every read distinguishes two outcomes a consumer MUST treat differently:

- an **empty result** — the source reliably answered and the thing genuinely does not exist. Safe to
  act on.
- an **error** — the source could not reliably answer. The answer is unknown; the consumer MUST fail
  closed and MUST NOT treat it as an absence.

An implementation MUST NOT degrade an error into an empty result at any layer, including per
candidate inside a loop.

The two outcomes are properties of the SOURCE, not of any one coin on it. A source that could not
answer MUST produce an error in every verb. A single coin that could not be interpreted MUST NOT,
because a coin is written by whoever paid for it: treating one coin's contents as a verdict on the
source lets anybody deny a query to everybody. Such a candidate is reported per §6.2 or §6.3 instead
— which is neither an error nor a silence, and is what keeps *the answer is unknown* and *this
particular coin is unreadable* from collapsing into each other.

Per **NC-12**, an answer from a single unauthenticated source is not corroborated. A consumer that
requires corroboration MUST obtain it by querying several sources, which this crate enables by taking
the source as a parameter.

## 8. The census

The per-epoch collateral requirement is a recurrence: what a mirror MUST lock in epoch `n` is derived
from what the network actually locked in epoch `n-1`. `dig-mirror-collateral` defines the arithmetic
and reads no chain. This section defines the chain read that produces its inputs.

### 8.1 The census height

The census of epoch `n` is taken at a single **block height** `H(n)`, never at a wall-clock instant:
every node MUST arrive at the same requirement without coordinating, and only a height is consensus
data.

`H(n)` is the height of the **first transaction block whose timestamp is at or after the epoch
start**. Chia block timestamps are in seconds.

**Non-transaction blocks carry no timestamp and MUST be skipped entirely.** They are not candidates
for `H(n)` and they do not advance the comparison. An implementation MUST NOT select a height that
carries no timestamp, and MUST NOT interpolate one. A one-block disagreement here is a fork.

A source that answers no timestamp for any height near the search is **not** a chain without blocks.
An implementation MUST report such a read as unanswerable (§7) and MUST NOT resolve it by guessing.

An epoch start the chain has not yet reached is an **absence**, not an error: an implementation MUST
report it as an empty answer.

The epoch calendar — the mapping from an epoch number to its start time — is **not defined by this
crate**. An implementation MUST take the epoch start as an input.

### 8.2 Qualifying coins

A coin at `H(n)` qualifies for the census of epoch `n` when all of the following hold.

- **C0** — the record is at the mirror puzzle hash (§3.1). A source MAY return records it was not
  asked for, and an implementation MUST NOT read any other rule off such a record.
- **C0b** — the record is **not a block-reward (coinbase) coin**. Such a coin has no creating spend
  on any source, so it can never satisfy C1 and MUST NOT be allowed to make the census unanswerable
  (§8.7). An implementation MUST decide this from the coin record alone, before any chain read. A
  source's coinbase flag, where it populates one, is authoritative; because a source need not
  populate one, an implementation MUST additionally recognise the synthesised parent's shape, and
  MUST NOT rest C0b on the flag alone. §9 requires such a coin to be excluded rather than failed
  closed on, and a flag-only implementation cannot meet that requirement against a source that
  reports every reward coin as `coinbase: false` while knowing no better — which is every source
  deriving its records from a wallet-protocol coin state, since that message carries no such flag.
  Consensus builds the synthesised parent as sixteen bytes of the genesis challenge followed by the block height as a sixteen-byte
  big-endian integer, so the bytes at offsets 16..28 are zero for every reachable height, which a
  coin id (a SHA-256 output) matches only with negligible probability. The detector is safe in the
  one direction that matters: it can only ever discard a coin, and the coins it discards could not
  have qualified.
- **C1** — its collateral is **$DIG**, established from the lineage proof in its creating spend.
  C0 does not imply C1 and MUST NOT be treated as implying it: the mirror puzzle hash is a CAT outer
  hash, but it is still 32 bytes, and an ordinary XCH `CREATE_COIN` paying to it produces a record
  there whose amount is denominated in mojos.
- **C2** — it was created at a height less than or equal to `H(n)`.
- **C3** — it was not spent at any height less than or equal to `H(n)`. A coin spent *after* `H(n)`
  was locked at the height being counted and MUST still qualify. It follows that the population read
  MUST include spent coins.
- **C4** — its declared epoch equals `n-1` **exactly**. A coin declaring an earlier epoch MUST be
  excluded, and so MUST a coin declaring a later one: pre-posting for a future epoch and padding with
  a stale coin are both excluded by the same rule.
- **C5** — its collateral is greater than or equal to the requirement of epoch `n-1`. The
  requirement is denominated in DIG CAT base units, so this comparison is meaningful only once C1
  has established the asset, and an implementation MUST NOT decide C5 before C1. An implementation
  MAY compare the record's raw amount earlier as a filter — a qualifying coin's collateral equals
  its record amount, so such a filter cannot discard a coin that would have qualified — but MUST NOT
  treat passing it as evidence of collateral, and MUST NOT rest a bound on it.
- **C6** — its memos parse as a well-formed advertisement (§5).
- **C7** — the counted unit is the triple `(owner, store, root)`. An implementation MUST NOT count
  coins.
- **C8** — the owner is **proven**, never assumed. The owner MUST be taken from the coin's lineage
  proof, and the coin's declared advertisement MUST reproduce the hint the coin was published under
  when that owner is substituted into the morph (§4.1). A coin failing this MUST be excluded rather
  than attributed on a guess.
- **C9** — where several qualifying coins share one triple, exactly one is selected: the **largest
  amount**, ties broken by the **lowest coin id compared big-endian bytewise**. Both axes MUST be
  deterministic, or two nodes compute a different locked total from the same chain.

A coin that cannot be placed in time — one whose confirmation height the source does not know — MUST
be excluded rather than assumed to fall on either side of `H(n)`.

### 8.3 An under-collateralised coin is invisible

A coin failing **C5** MUST contribute to **nothing**: not the store count, not the owner count, and
not the locked total.

This is the primary anti-spam property of the design and it MUST NOT be relaxed. The controller reads
a network failing to meet its requirement as a signal to lower it, so a coin that counted as a
participant without paying for one would let an attacker drive the requirement down for the price of
dust. Under-collateralised is not partially collateralised.

### 8.4 The recurrence is well founded, not circular

A coin qualifies for epoch `n` against the requirement of epoch `n-1`, which was derived from the
census of `n-2`, terminating at the epoch-1 bootstrap constant. This is induction on the epoch number.

An implementation MUST require the record for epoch `n-1` in order to census epoch `n`. It MUST NOT
qualify coins against the requirement of the epoch being censused, and MUST NOT substitute a cheaper
threshold to remove the apparent circularity — doing so reopens §8.3.

### 8.5 The three outputs

- `stores(n)` — the count of distinct qualifying triples. It is an advertisement count: one owner
  publishing two roots of one store contributes two, each paid for in full.
- `owners(n)` — the count of distinct owner puzzle hashes across the qualifying triples. It is **not
  a node count and not an operator count**, and a surface displaying it MUST NOT describe it as
  either.
- `locked(n)` — the sum of the amounts of the coins selected by C9, in **DIG CAT base units**
  (`1 DIG = 1_000`). These are never mojos: a mojo is XCH's base unit at `10^-12` XCH, nine orders
  of magnitude away, and an implementation MUST NOT describe a mirror coin's amount as one.

### 8.6 Finality

A census taken at the tip is reorg-sensitive. An implementation MUST NOT publish, gossip, or act on a
census whose height is within `CENSUS_FINALITY_DEPTH_BLOCKS` of its source's peak; it MUST report the
epoch as pending instead. A source that exposes no peak cannot establish finality, and an
implementation MUST refuse to census against one.

### 8.7 A census is complete or it is absent

Unlike `list` (§6.2), a census MUST NOT tolerate an unanswerable read. A census computed over part of
the population is not a smaller census; it is a different number from the one every other node
computes, produced silently. An implementation MUST return an error and no census.

A coin that was read successfully and failed a rule is the opposite case: that is an answer, and an
implementation MUST count it as an exclusion and continue.

A creating spend the source did not produce is NOT such an answer. It is an unanswerable read per §7,
and a census MUST fail closed on it rather than counting the coin as unreadable and completing —
otherwise a pruned source silently reports a smaller network, which is the direction that lowers the
requirement for everyone, with no attacker involved. This is where a census MUST diverge from `list`
(§6.2), whose tolerance is correct for a different question.

**Exactly one shape is exempt, and it is exempt because no source could ever answer for it.** The
rule above rests on the possibility of a better source: a spend absent from one source may be present
in another, so failing closed preserves the chance of a complete answer. A **block-reward** coin
breaks that premise. Consensus synthesises its `parent_coin_info` rather than deriving it from a
spent coin, so it is not the coin id of any coin and no creating spend for it exists on a perfect,
complete, unpruned node. An implementation MUST exclude such a coin under **C0b** (§8.2) instead of
failing closed on it.

An implementation that does not MUST be understood to be permanently deniable at negligible cost. A
farmer's or pool's reward target is free-form configuration validated against nothing, so directing
it at the mirror puzzle hash costs one block; the resulting coin is never spent, so C3 never begins
excluding it, and every census at every subsequent height on every node returns an error for good.
The requirement then freezes, which is the direction that cannot be recovered from — per §8.4 the
requirement that would price an attacker out can only rise via a census.

A spend **of a different coin** is such an unanswerable read, and is the case an implementation is
most likely to miss. An implementation MUST verify that the returned spend's coin id equals the
candidate's `parent_coin_info` before interpreting it. Without that check, the spend classifies
cleanly, no output carries the candidate's coin id, and the candidate is recorded as "not a mirror
coin" — a fact about the source reported as a fact about the chain. A source could then delete any
chosen mirror from a census while the census still completed.

### 8.8 The census bound is a REFUSAL, and here that is the opposite of §6.5

A census MUST examine the ENTIRE candidate population. It MUST NOT compute a census over a prefix of
it, and MUST NOT return a census that did.

This inverts §6.5 deliberately, and the reason is the population rather than the bound. A query walks
one owner's or one advertisement's hint bucket, where a truncated answer is still an honest partial
answer to the caller's own question. A census walks the single global mirror puzzle hash — a set
anyone may add to for the price of a dust coin, and one that never shrinks because spent coins are
included per C3. A prefix of that set is a censorship primitive: enough dust erases an honest network
from every node permanently, and two nodes whose sources enumerate differently take different
prefixes and compute different requirements from the same chain.

An implementation MAY bound the work it does. Where a bound is exceeded it MUST report that it could
not compute the census, and MUST NOT return a census — a node that says it cannot compute the network
is recoverable, and a node that quietly computes a smaller one is not.

A refusal over an attacker-writable set is itself a denial, so **what** is bounded decides whether the
bound is safe. A bound MUST NOT be denominated in a quantity an attacker obtains for free. In
particular it MUST NOT be denominated in candidate coins: coins at the mirror puzzle hash cost the
price of a `CREATE_COIN`, thousands may be minted by one transaction, and a census that refuses on
their count can be denied permanently — the requirement that would price the flood out can only rise
via a census.

A bound SHOULD instead be denominated in **distinct creating spends**, which is both the work the
expensive pass performs — one execution answers for every output that spend produced — and a quantity
an attacker must get on chain per unit of work forced. An implementation that bounds this way MUST
execute each creating spend at most once per census, or the bound does not bound the work.

Rules decidable from the coin record alone — C0, C0b, C2 and C3 — SHOULD be applied to the whole
population before any rule requiring a further chain read.

## 9. Conformance

An implementation conforms when:

1. its mirror coins are verifiably $DIG by the outer-hash test in §3.1;
2. its `reclaim` spend returns the full collateral to the creator;
3. its `discover` rejects a coin hinted under a store it does not advertise;
3a. its `discover` rejects a real, fully-collateralised mirror coin that bonds a DIFFERENT root of the
    same store, while still returning that coin for the root it does bond (§4.1 check 1);
3b. its `discover` rejects a coin that declares the advertisement asked about but was published under
    a different namespace value (§4.1 check 2);
3c. a tuple that collides with the coin's own advertisement under the morph is refused (§4.1);
3d. naming an owner does not make a coin controlled by anyone else answer for them (§6.3);
4. its `discover` rejects collateral held in any CAT other than $DIG;
5. its `list` returns the caller's coins, and reports the unresolved candidate, when one candidate
   among them cannot be authenticated — neither erroring nor omitting it in silence (§6.2);
6. every mirror coin created by one parent spend is found, not only the first (§5);
7. its `create` refuses a zero collateral (§6.1);
8. its `reclaim` hints the recreated coin to the owner (§6.4);
9. a scan that reached its candidate bound is distinguishable by the caller from one that did not
   (§6.5);
10. its `list` reports one undecodable coin as unresolved to the wallet that owns it and as settled to
    every other caller (§6.2), so no stranger can hold the completeness signal false;
11. memos that decoded and carried no URLs are distinguishable, inside the implementation, from memos
    that could not be decoded at all (§5);
12. an empty result and an unreachable source are distinguishable by the caller in every verb;
13. its census excludes a coin below the epoch requirement from ALL THREE outputs while still
    counting an honest coin beside it (§8.3);
14. its census counts one triple once however many coins back it, and selects the largest (§8.2 C9);
15. its census excludes a coin declaring any epoch other than `n-1`, earlier or later (§8.2 C4);
16. its census excludes a coin whose declaration does not reproduce its hint under the owner from its
    lineage proof (§8.2 C8);
17. its census reports an epoch within the finality depth of the tip as pending rather than final
    (§8.6), and errors rather than shrinking when a read cannot be answered (§8.7);
18. its census returns the SAME result for a population whichever order a source enumerates it in,
    including when an honest coin sits past the point a bound would have stopped at (§8.8);
19. its census refuses to answer, rather than answering over a prefix, when its bound is exceeded —
    and does not refuse a population exactly at that bound (§8.8);
20. a flood of coins minted by ONE creating spend does not consume its census bound, however large,
    and an honest network beside such a flood is still counted (§8.8);
21. its census fails closed when a candidate's creating spend cannot be produced, while `list`
    continues to report the same coin as unresolved (§8.7, §6.2);
22. a puzzle reveal substituted onto a real coin cannot re-attribute that coin's owner, store or
    root, and the same coin with its genuine spend is still attributed (§5, §7);
23. its census excludes a record the source returned that is not at the mirror puzzle hash, without
    fetching a creating spend for it, and still counts an honest coin beside it (§8.2 C0);
  - excludes a block-reward coin paid to the mirror puzzle hash — including one a source reports
    without a coinbase flag — and completes the census rather than failing closed on it (§8.2 C0b,
    §8.7);
24. its census ends, rather than excluding the coin and completing, when a source answers a
    candidate's creating-spend read with a different coin's genuine spend (§8.7).
25. a coin declares the peer its owner named and refuses every other claimant asking about that same
    coin, and the same coin without a declaration term names nobody (§5.1);
26. a coin carrying two declaration terms declares NEITHER of them, rather than the first by
    position (§5.1 rule 3);
27. a declaration is read identically whichever hex case its owner wrote it in (§5.1 rule 2), and a
    claimant id of 64 bytes that is not 64 characters is refused rather than panicked on (§5.1
    rule 5);
28. its `create` writes a declaration that its own reader reads back off a real coin, so the format
    the writer emits and the format the reader parses cannot diverge unnoticed (§5.1, §6.1).
