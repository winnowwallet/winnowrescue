# Electrum seed vectors

- Files: `mnemonic.py` (`electrum/mnemonic.py`, the normalisation and version check being ported), `test_mnemonic.py` and `test_wallet_vertical.py` (`tests/`)
- Upstream: https://github.com/spesmilo/electrum
- Revision: commit `c073a33dc2af833d174f41d4ff9f60352a459594`
- Copied: 2026-10-18; compared byte for byte with `https://raw.githubusercontent.com/spesmilo/electrum/c073a33dc2af833d174f41d4ff9f60352a459594/<path>` on 2026-10-19
- Used by: `crates/rescue-core/src/tests/electrum.rs` reads the `SEED_TEST_CASES` and the `Test_seeds.mnemonics` set from `test_mnemonic.py`, and from `test_wallet_vertical.py` the `UNICODE_HORROR_HEX` passphrase and the first addresses of the standard and segwit seeds and the BIP39 wallet cases (read by `derivation.rs`)
