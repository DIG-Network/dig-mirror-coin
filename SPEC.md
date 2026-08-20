# dig-mirror-coin — normative specification

**Status: SCAFFOLD.** The behavioural clauses arrive with the migration from `DataLayer-Driver`'s
`DigCollateralCoin`. What is normative today is the scope, the naming, and the invariants any
implementation MUST hold.

## 1. Scope

A **mirror coin** is a coin that locks **$DIG** as collateral to advertise that its owner serves a
given DIG store. This crate defines the mirror coin, its creation, and its reclaim spend.

This crate MUST NOT define store-collateral coins. Its ancestor type serves both namespaces; the
split is deliberate, because the two have different lifetimes and different spenders.

## 2. Naming

The on-chain puzzle is the **mirror puzzle**. This crate names its wrapper **mirror coin**. The name
*server coin* is `DataLayer-Driver`'s and MUST NOT appear in this crate's public API.

## 3. Invariants

1. **The collateral is a CAT.** A mirror coin sits at the OUTER puzzle hash currying the $DIG asset
   id around the owner's inner p2 hash. An implementation MUST NOT derive it by hand and MUST NOT
   infer the asset from a hint.
2. **A hint is not an asset.** Hints are unauthenticated `CREATE_COIN` memos over arbitrary 32-byte
   values. Anyone may place a coin under anyone's hint for the price of a dust coin, so a hint MUST
   NOT be treated as evidence of ownership or of asset identity.
3. **Advertising is a claim; the collateral is the cost.** Nothing about a mirror coin proves the
   owner actually serves the store. It proves only that $DIG is locked. A consumer MUST NOT read a
   mirror coin as evidence of availability.
4. **Reclaim is explicit.** Collateral returns to its owner only through a deliberate spend.

## 4. Conformance

An implementation conforms when it creates a mirror coin whose asset is verifiably $DIG by the
outer-hash test in §3.1, and whose reclaim spend returns the collateral to the creator.
