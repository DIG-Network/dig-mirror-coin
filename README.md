# dig-mirror-coin

Mirror coins for the DIG Network: **lock $DIG as collateral to advertise that you serve a DIG store.**

Anyone can claim to mirror a store. A mirror coin makes the claim cost something — the collateral is
the signal, and reclaiming it is a deliberate spend.

## Status

Scaffolding. The implementation is being migrated from `DataLayer-Driver`'s `DigCollateralCoin`,
which serves both store-collateral and mirror-collateral namespaces from one type. This crate takes
the mirror half, natively, with no `datalayer-driver` dependency.

## Naming

`DataLayer-Driver` calls the XCH-collateralised variant a *server coin*. The on-chain puzzle has
always been the **mirror puzzle**. This crate uses **mirror coin** throughout — the name the chain
already uses.

## The collateral is a CAT

$DIG is a CAT, so a mirror coin sits at the **outer** puzzle hash that curries the asset id around
the owner's inner p2 hash, and is only *hinted* to that p2 hash. A hint is an unauthenticated memo:
it helps a wallet find the coin and proves nothing about which asset it holds.

## License

MIT OR Apache-2.0.
