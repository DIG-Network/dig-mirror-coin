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

A coin whose memos carry no URLs is NOT a mirror coin and MUST be excluded. This excludes sibling
collateral coins sharing the same puzzle hash. It is a necessary condition only: memo shape is chosen
by whoever spends the parent, so it MUST NOT be relied on against an adversary.

## 6. The verbs

### 6.1 create

Locks collateral and publishes a mirror. The advertisement MUST carry at least one URL. The returned
coin spends are unsigned.

### 6.2 list — keyed by owner

Answers *which mirror coins are mine*. An implementation MUST scan the shared mirror puzzle hash and
keep coins whose authenticated lineage proof names the caller's puzzle hash.

An empty result MUST mean the owner has locked no collateral.

`list` MUST fail closed: a candidate that cannot be authenticated MUST abort the read with an error
rather than being skipped, because a silently short inventory understates the owner's own money.

### 6.3 discover — keyed by store

Answers *who mirrors this store*. An implementation MUST look up the store's namespace value in a
hint index, then re-derive each candidate per §5 and keep only those whose recomputed namespace value
matches the store and epoch asked about.

An empty result MUST mean the source was consulted and found nobody advertising that store.

A candidate that fails authentication MUST be dropped and counted, not fatal — the hint index is
writable by anyone, and one dust coin MUST NOT be able to suppress every honest mirror. A source that
could not ANSWER is different and MUST produce an error.

`discover` MUST NOT present its result as availability (§3.3).

### 6.4 reclaim

Releases collateral to its owner. An implementation MUST refuse the spend when the supplied key does
not match the coin's authenticated owner. It MUST recreate the entire locked amount as $DIG at the
owner's address, and MUST draw any fee from separately supplied XCH coins rather than from the
collateral.

## 7. Fail-closed reads

Every read distinguishes two outcomes a consumer MUST treat differently:

- an **empty result** — the source reliably answered and the thing genuinely does not exist. Safe to
  act on.
- an **error** — the source could not reliably answer. The answer is unknown; the consumer MUST fail
  closed and MUST NOT treat it as an absence.

An implementation MUST NOT degrade an error into an empty result at any layer, including per
candidate inside a loop.

Per **NC-12**, an answer from a single unauthenticated source is not corroborated. A consumer that
requires corroboration MUST obtain it by querying several sources, which this crate enables by taking
the source as a parameter.

## 8. Conformance

An implementation conforms when:

1. its mirror coins are verifiably $DIG by the outer-hash test in §3.1;
2. its `reclaim` spend returns the full collateral to the creator;
3. its `discover` rejects a coin hinted under a store it does not advertise;
4. its `discover` rejects collateral held in any CAT other than $DIG;
5. its `list` errors rather than under-reporting when a candidate cannot be authenticated;
6. an empty result and an unreachable source are distinguishable by the caller in every verb.
