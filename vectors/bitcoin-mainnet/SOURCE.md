# Mainnet block headers, block hashes and two coins with their merkle proofs

Recorded on 2026-10-20 (mainnet tip then: height 972317). Everything here is public chain data.
Every file is kept as the servers answered; nothing was regenerated with the code under test.

## Headers

`headers-*.hex`: one raw 80-byte header per line, lowercase hex, as `blockchain.block.headers` returns them.

| File | Heights | Lines | SHA-256 |
| --- | --- | --- | --- |
| `headers-0-4032.hex` | 0 to 4032: genesis, and the retargets at 2016 and 4032 (difficulty 1, so the new target is clamped at the limit) | 4033 | `4d5c3eeceef69d48856859bdf2e9f4ff6ceaaa276022e360daa9b173813fa3db` |
| `headers-11100-11112.hex` | the eleven headers before the checkpoint at 11111, the checkpoint, and one more | 13 | `0f9efdab9283212526c37e369d2afb0e7bc79c57e07c821f14032a93a86b3a47` |
| `headers-858816-860831.hex` | the retarget period before the next range (858816 is 426 x 2016): the seed a chain starting at 860832 needs for its first retarget | 2016 | `39c09554683fb9d7446ef981828132bb5b1d1aaa3a6af2af22d87bf2e10cd954` |
| `headers-860832-864864.hex` | 860832 (427 x 2016) to 864864 (429 x 2016): three retargets at real difficulty, at 860832, 862848 and 864864 | 4033 | `39b12c46dcdddfe795bf98c8157251309c5e464050b083bfd0e4895831bfd854` |

- Source: the Electrum server `electrum.blockstream.info:50002` (electrs-esplora 0.4.1, protocol 1.4), `blockchain.block.headers(start, count)` with at most 2016 headers per call.
- How: `python3 -I fetch_headers.py electrum.blockstream.info 50002` in this directory. The script checks that every header links to its predecessor with plain `hashlib`. The TLS certificate is not verified, because nothing here is trusted on the connection's word: the chain is checked again by proof of work in the tests, and by the next item.
- Cross-check: the block hash and the raw header at heights 0, 1, 2015, 2016, 4032, 858816, 858817, 860831, 860832, 860833, 862847, 862848 and 864864 were compared with `https://blockstream.info/api/block-height/<h>` and `/block/<hash>/header` and with `https://mempool.space/api/...` (two operators) on 2026-10-20: all equal. The checkpoint window `headers-11100-11112.hex` was added after that check and is covered by the hash of block 11111 in `block-hashes.txt`, which is also the hash Bitcoin Core's checkpoint table names.

## Block hashes

`block-hashes.txt`: a height and the hash of the block there, written as explorers write it.
Source: `https://blockstream.info/api/block-height/<height>`; script `fetch_hashes.py`. SHA-256 `b9851fdc4320b75bf9cd389f50fc3a8cfad1568f1fabc81248b239936eb7185e`.
The tests compare these with the hash of the recorded header at the same height.

## Coins and merkle proofs

- `proof-block862000-pos1500.json`: transaction `40b74a1c...83fd`, position 1500 of 2207 in block 862000 (inside `headers-860832-864864.hex`), a segwit transaction (one input with a witness; output 0 is an OP_RETURN of 0 sat, output 1 a P2WPKH of 546 sat). SHA-256 `d90b199dbb57d97ba1fa6028bae177e1947f4085d921eebb1de29309aa67aac9`.
- `proof-block1-coinbase.json`: the coinbase of block 1 (inside `headers-0-4032.hex`), the only transaction of its block, so its merkle branch is empty. One output of 50 BTC paying a pay-to-public-key script. SHA-256 `1640e4b6a11ebd59a37adb0dfd34454512ad0158103c391c562b738379a79346`.

Each JSON file keeps, as the servers answered: `raw` (`https://blockstream.info/api/tx/<txid>/raw`, binary, kept as hex), `esplora_tx` (`/tx/<txid>`, the source of the expected scripts and amounts), `esplora_merkle_proof` (`/tx/<txid>/merkle-proof`), `electrum_get_merkle` (`blockchain.transaction.get_merkle` on `electrum.blockstream.info:50002`), and `header` (`/block/<hash>/header`).
How: `python3 -I fetch_proofs.py electrum.blockstream.info 50002`. The transaction in block 862000 was picked by position (1500 = 0b10111011100: both kinds of step in the path) after looking at three candidates of the block.
The Esplora and Electrum proofs are the same list of hashes in the same written order (reversed bytes, as a txid is written); a test asserts it.

Used by: `crates/rescue-core/src/tests/headers.rs`, `proof.rs`, `source.rs` (through `tests/chains.rs`).
