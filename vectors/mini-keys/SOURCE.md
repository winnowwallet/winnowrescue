# Casascius mini private key examples

- File: `mini-keys.json`
- Upstream: https://en.bitcoin.it/wiki/Mini_private_key_format (revision `oldid=70839`, last edited 2025-11-11)
- Copied: 2026-10-18. The page names the 30-character example `S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy`. The 22-character key `SzavMBLoXU6kDrqtUVmffv` is not on that page; it was supplied with the task for the 22-character form and is held to the same independent recomputation.
- The expected secret, uncompressed WIF and uncompressed P2PKH address are not copied from the page: `recompute.py` derives them with `hashlib` and plain Python integers for secp256k1, and shares no code with `rescue-core`. `python3 -I recompute.py --check` asserts that `mini-keys.json` agrees (run 2026-10-19).
- Used by: `crates/rescue-core/src/tests/mini.rs`
