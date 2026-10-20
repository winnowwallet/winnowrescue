# Bitcoin Core v29.4 chain parameters

- File: `chainparams.cpp`
- Upstream: https://github.com/bitcoin/bitcoin, `src/kernel/chainparams.cpp`
- Revision: tag `v29.4` (annotated tag object `4e70eab99b60f7718b78e2158de9fb82726f3cec`, commit `3fc0865963a38b871e9f7d94e6151c4953563516`)
- Copied: 2026-10-20 with `curl https://raw.githubusercontent.com/bitcoin/bitcoin/v29.4/src/kernel/chainparams.cpp`; compared byte for byte with a second fetch the same day. SHA-256 `11b795133d69076560c144a6d642fb8ff02d5b6d811a8e6c0ceaccb55fefaf37`
- Used by: `crates/rescue-core/src/tests/headers.rs` (the mainnet `checkpointData` table is parsed out of the file and compared with `MAINNET_CHECKPOINTS` in `headers.rs`; the genesis hash that `CMainParams`, `SigNetParams` and `CRegTestParams` assert is compared with the genesis header of each network)

## Why v29.4 and not v31.0

The build plan names `v31.0` (the tag object `84b62e1e8dbc9bbb393d0cb50c863b161b378f35` the other directory here uses). Its
`src/kernel/chainparams.cpp` has no `checkpointData` at all: Core dropped its checkpoints before v30.0. The
files at `v30.0`, `v31.0` and `master` contain no occurrence of the word "checkpoint" (checked 2026-10-20),
and the last release line that has the table is v29. `v29.0` to `v29.4` carry the same mainnet table
(compared 2026-10-20); `v29.4` is the newest of them, so it is the revision kept. The thirteen mainnet
entries are old, settled history (heights 11111 to 295000) and cannot change.
