# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.8.0] - 2026-09-02

### Features
- `census_height_seeded` — a census-height search bounded by a caller-supplied lower bound, so a
  caller walking every epoch since genesis no longer re-searches the whole chain once per epoch.
  The seed is verified against the source and discarded when it does not hold, so it can change
  only how much work the search does and never which height it returns. `census_height` is
  unchanged.

## [0.7.0] - 2026-08-28

### Features
- Mirror-coin census at the epoch census height (#8)

## [0.5.0] - 2026-08-27

### Features
- **BREAKING** Mirror coins are per (store, root, owner, epoch) (#5)

## [0.4.0] - 2026-08-27

### Features
- **BREAKING** **deps:** Move to the chia 0.36 ceiling; the mirror puzzle hash changes to f2ed90e7 (#4)

## [0.3.1] - 2026-08-20

### Features
- Encapsulated mirror coin crate — create, list, discover, reclaim (#1)

### Bug Fixes
- **ci:** Name this crate, not the one the workflows were copied from (#2)

## [0.1.0] - 2026-08-20

### Chores
- Scaffold dig-mirror-coin


