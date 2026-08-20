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

A store launcher id MUST be morphed into the mirror namespace before use as a hint:

```
morph(store_launcher_id, epoch) = tree_hash( (int(store_launcher_id) + epoch, "DIG_STORE_MIRROR_COLLATERAL") )
```

where `int(...)` reads the launcher id as a big-endian signed integer. `DIG_STORE_MIRROR_COLLATERAL`
is a wire constant.

The morph is one-way and MUST NOT be inverted. A consumer that needs to know which store a coin
advertises MUST recompute the morph from a candidate store id and compare.

The offset is arithmetic, so a store one unit ahead at epoch *n* and a store one unit behind at
epoch *n+1* produce the SAME namespace value. A namespace value therefore identifies no store on its
own, which is a further reason §3.2 binds.

## 5. Authentication

A candidate coin MUST be re-derived from the spend that CREATED it — the parent's puzzle reveal run
against its solution — before any property of it is believed. From that execution an implementation
MUST take:

- the **asset id**, from the parent's curried CAT puzzle. It MUST equal the $DIG asset id.
- the **amount**, from the matching `CREATE_COIN` condition.
- the **owner**, from the lineage proof's parent inner puzzle hash.
- the **namespace value and URLs**, from the `CREATE_COIN` memos: the first entry is a 32-byte
  namespace value, the remaining entries are URLs.

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

## 6. The verbs

### 6.1 create

Locks collateral and publishes a mirror. The advertisement MUST carry at least one URL, and the
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

### 6.3 discover — keyed by store

Answers *who mirrors this store*. An implementation MUST look up the store's namespace value in a
hint index, then re-derive each candidate per §5 and keep only those whose recomputed namespace value
matches the store and epoch asked about.

An empty result MUST mean the source was consulted and found nobody advertising that store, and MUST
NOT be presented that way when the scan stopped early (§6.5).

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

## 8. Conformance

An implementation conforms when:

1. its mirror coins are verifiably $DIG by the outer-hash test in §3.1;
2. its `reclaim` spend returns the full collateral to the creator;
3. its `discover` rejects a coin hinted under a store it does not advertise;
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
12. an empty result and an unreachable source are distinguishable by the caller in every verb.
