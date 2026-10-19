# Bitcoin Core v31.0 key and address vectors

- Files: `key_io_valid.json`, `key_io_invalid.json`
- Upstream: https://github.com/bitcoin/bitcoin, `src/test/data/`
- Revision: tag `v31.0` (annotated tag object `84b62e1e8dbc9bbb393d0cb50c863b161b378f35`, commit `6574cb40869b96b9ffc79c19dc8f4e467d60f321`)
- Copied: 2026-10-18; compared byte for byte with `https://raw.githubusercontent.com/bitcoin/bitcoin/v31.0/src/test/data/<file>` on 2026-10-19
- Used by: `crates/rescue-core/src/tests/core_key_io.rs` (private-key rows through the WIF parser, address rows through the destination parser, every invalid string through every parser)
