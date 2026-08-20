# dig-mirror-coin

Mirror coins for the DIG Network: **lock $DIG as collateral to advertise that you serve a DIG store.**

Anyone can claim to mirror a store. A mirror coin makes the claim cost something — the collateral is
the signal, and reclaiming it is a deliberate spend.

## Four verbs

| verb | what it answers |
|---|---|
| `create` | lock $DIG and publish a mirror for a store |
| `list` | which mirror coins are mine? |
| `discover` | who mirrors this store? |
| `reclaim` | release the collateral back to its owner |

`list` and `discover` are separate on purpose. They are keyed differently, they are trusted
differently, and an empty answer means something different in each: `list` empty means *you have
locked nothing*, `discover` empty means *nobody advertises this store*. Neither ever reports an
unreachable chain source as an empty result — that is an error, and callers must fail closed on it.

## Encapsulated, not thin

This crate owns its implementation. No `datalayer-driver` dependency, no re-export layer. It was
migrated from `DataLayer-Driver`'s `DigCollateralCoin`, which serves both the store-collateral and
mirror-collateral namespaces from one type; this crate takes the mirror half only.

## Chain access

It is a primitive, so it pulls no network stack down into itself. Reads arrive through the
ecosystem's canonical `ChainSource` trait, extended with the single hint lookup that trait does not
expose. Nothing here opens a socket, holds a key, signs, or broadcasts: the spend builders return
unsigned coin spends for the caller's own signer to complete.

## The collateral is a CAT

$DIG is a CAT, so a mirror coin sits at the **outer** puzzle hash that curries the asset id around
the collateral puzzle. Ownership lives in the coin's lineage proof, which means every mirror coin in
existence shares one puzzle hash — so finding a particular store's mirrors needs a hint, and a hint
is an unauthenticated memo anyone can write. This crate uses hints only to decide where to look;
which asset is locked, how much, who owns it and which store it advertises are always re-derived from
the coin's creating spend.

## Reclaim returns the money

`reclaim` recreates the full locked amount as $DIG at the owner's address, and pays any fee from
separately supplied XCH. There is no path in this crate that reduces $DIG supply — burning through a
CAT TAIL is a different operation with the opposite outcome, and would get its own name.

## A mirror coin is not availability

It proves $DIG is locked. It does not prove the owner serves the store, or that the advertised URLs
resolve. `discover` returns *claims* for exactly that reason. Availability is established by
fetching.

See [`SPEC.md`](./SPEC.md) for the normative contract.

## License

MIT OR Apache-2.0.
