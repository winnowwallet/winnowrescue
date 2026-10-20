# Winnow Rescue: build plan

One Rust workspace, pull requests of one commit each, named `area: subject`. Every parser gets a
fuzz target; every expected value comes from a file under `vectors/` with its upstream source and
revision recorded in a `SOURCE.md` beside it; nothing is regenerated with the code under test.

## Workspace

| Path | Holds |
| --- | --- |
| `crates/rescue-core` | the pure core: derivation plans, coin proofs, the sweep and its checks; no sockets, files, clock, randomness or logging; `HistorySource`, `Headers` and `Broadcaster` are traits the host implements or takes from the next crate |
| `crates/rescue-electrum` | the default I/O: an Electrum client over TLS and an Esplora adapter |
| `crates/rescue-cli` | `rescue`: the five steps on the command line, with an offline signing mode |
| `crates/rescue-gui` | `rescue-gui`: the same five steps in one window (egui) |
| `fuzz/` | one cargo-fuzz target per parser, its own workspace root; kept findings replay on stable from `fuzz/regressions/` |
| `vectors/` | reference data, one directory per upstream source |

The toolchain is pinned in `rust-toolchain.toml`. Workspace lints forbid `unsafe_code` and deny
`clippy::all`; the core also denies `unwrap_used`, `expect_used`, `panic`,
`arithmetic_side_effects`, `print_stdout`, `print_stderr` and `dbg_macro`. `deny.toml` holds the
licence allow-list, bans OpenSSL and native TLS, and refuses unknown sources. CI runs fmt, clippy
with warnings as errors, the tests, the fuzzing-feature replay, cargo-deny, a check that the core
carries no logging facade, and a fixed-seed fuzz smoke on a date-pinned nightly, on Linux, macOS
and Windows. There are no retries anywhere.

## One rust-bitcoin line

`bitcoin` 0.32 supplies BIP32, addresses, the sighash cache (legacy, BIP143, BIP341 key spend),
the taproot tweak, witness builders, header proof-of-work and retarget checks, and merkle trees.
`secp256k1`, `bitcoin_hashes` and `hex-conservative` are reached only through `bitcoin::`
re-exports; their newer standalone lines belong to the next rust-bitcoin line and are never direct
dependencies. The line is upgraded together with `miniscript`, not before.

## The core's modules

| Module | Holds |
| --- | --- |
| `secret` | `SecretInput`, `Seed`, `RootKey`, `KeyHandle`, `Session`: zeroized, erased on drop, `Debug` prints `<redacted>`, compile-time checked to be neither `Clone` nor `Serialize` |
| `words` | BIP39 with the wrong word named by position only; Electrum 2.x seeds (standard and segwit; two-factor refused) |
| `keys` | WIF, mini private keys, 32-byte hex, `dumpwallet` text, extended private keys including the SLIP-0132 forms |
| `paths` | script kinds, purposes 44/49/84/86, the quirk table, a typed-path parser |
| `plan` | the tiered branches with their first addresses and a public fingerprint |
| `destination` | P2TR only, network-checked |
| `headers` | the header chain from genesis: proof of work, retargets, checkpoints |
| `proof` | a coin proved by its transaction bytes, merkle branch and header |
| `discover` | the sans-IO engine: tiers, gaps, budgets, resumable public progress |
| `source` | the three traits and their errors |
| `review`, `sweep`, `sign` | the fee rules, the all-in one-out transaction, per-kind signing with every signature re-verified |
| `flow`, `strings` | the five-step state machine and the string table every shell renders |
| `fuzz_api` | the entry points the fuzz targets and the regression replay share |

The host API is one state machine in every language: import a secret and get a plan; discover
against a source under the host's consent screen, with progress; review coins against a
destination and a rate and get the exact fee or a named refusal; sign; broadcast. Public types
carry no secret field; the only secret-bearing entry is the import.

## Pull requests, in order

| # | Commit | Status |
| --- | --- | --- |
| 1 | `repo: workspace, toolchain pin, deny and CI matrix` | merged |
| 2 | `core: secrets, derivation plan and input checks` | merged |
| 3 | `core: header chain and coin proofs` | merged |
| 4 | `core: discovery tiers, budgets and resumable progress` | open |
| 5 | `electrum: Electrum and Esplora adapters` | |
| 6 | `core: review, sweep and signing`, with the regtest journey: the first sweep accepted by Bitcoin Core | |
| 7 | `cli: the five steps and the offline signing mode`: the first mainnet sweep possible | |
| 8 | `core: the Flow state machine and string table` | |
| 9 | `gui: the desktop egui binary` | |
| 10 | `release: checksummed binaries for three desktops` | |

After the desktop milestone: the generated Swift and Kotlin bindings and the wasm package for
host wallets; descriptors, foreign vaults and the PSBT hand-off; the exchange check; an
emergency wallet in the standalone app, if wanted.

## Verification

Every pull request runs the CI set above. The sweep is held by property tests: the fee never
exceeds a tenth of the total or is refused; inputs minus output equals the fee exactly; the
actual rate is at or above the request and below it plus one sat/vB; every signature verifies; the
bytes round-trip; vsize stays under the standard cap; one output; version 2; RBF sequences;
locktime at the tip; no duplicate inputs; uncompressed keys only in P2PKH; uneconomic coins
excluded and counted. The regtest journey runs Bitcoin Core and electrs in containers, funds legacy,
nested, native and Electrum-path wallets from fixed seeds, sweeps them through the library and
then the command-line tool, and has Core accept and confirm the transaction; the negatives (a
typo destination, a test-network key, the fee cap) are refused by name.
