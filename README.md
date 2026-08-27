# dig-mirror-coin

Mirror coins for the DIG Network: **lock $DIG as collateral to advertise that you serve a DIG store.**

Anyone can claim to mirror a store. A mirror coin makes the claim cost something — the collateral is
the signal, and reclaiming it is a deliberate spend.

## Four verbs

| verb | what it answers |
|---|---|
| `create` | lock $DIG and publish a mirror for one root of a store |
| `list` | which mirror coins are mine? |
| `discover` | does this peer bond this store, at this root? |
| `reclaim` | release the collateral back to its owner |

`list` and `discover` are separate on purpose. They are keyed differently, they are trusted
differently, and an empty answer means something different in each: `list` empty means *you have
locked nothing*, `discover` empty means *this peer is not bonded here*. Neither ever reports an
unreachable chain source as an empty result — that is an error, and callers must fail closed on it.

## A mirror bonds a ROOT, not a store

A store changes, and a publisher funding mirrors has to be able to pay for the current root and
decline the ones before it. So a mirror coin is per `(store, root, owner, epoch)`: one coin per root
a peer actually holds, existing exactly while that `.dig` is on disk, and withdrawn — with the money
— by `reclaim`.

Because the owner is one of the four terms, `discover` checks a **named** peer's bond rather than
enumerating a store's mirrors. Peers come from the DHT; what this crate answers is whether the
collateral behind a peer's claim is real and is staked on the root you asked for.

The hint those four terms morph to is an *index*, never a binding: it is a sum, so tuples collide,
and the epoch term is freely chosen — its author can solve for a value landing their coin on anyone
else's hint. A mirror coin therefore **declares** what it bonds in its memos, and a check compares
that declaration as well as recomputing the hint. See §4.1 of the spec.

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
existence shares one puzzle hash — so finding a particular bond needs a hint, and a hint is an
unauthenticated memo anyone can write. This crate uses hints only to decide where to look; which
asset is locked, how much and who owns it are always re-derived from the coin's creating spend, and
what it advertises is taken from its own declaration and compared, never inferred from the hint.

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
