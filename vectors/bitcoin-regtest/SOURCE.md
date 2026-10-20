# A regtest chain mined with Bitcoin Core

- Files: `headers-0-2020.hex` (2021 lines: genesis and 2020 mined blocks, one raw 80-byte header per line, lowercase hex), `chainwork.txt` (height, block hash and Core's `chainwork` at ten heights)
- Source: Bitcoin Core `v31.1.0` (`bitcoind` from Homebrew), run on 2026-10-20 on an empty data directory, RPC port 18543, peer port 18544, no peers, no wallet. Never Core's default 18443.
- How: `sh mine.sh <empty datadir> .` in this directory. The commands are in the script, in this order:
  1. `bitcoind -regtest -daemon -datadir=<datadir> -rpcport=18543 -port=18544 -listen=0 -connect=0 -dnsseed=0 -discover=0 -server=1 -rpcuser=winnowrescue -rpcpassword=vectors-only -nowallet=1 -printtoconsole=0`
  2. `bitcoin-cli ... generatetoaddress 2020 bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080` (the BIP173 example program as a regtest address)
  3. for each height `bitcoin-cli ... getblockhash <h>` then `bitcoin-cli ... getblockheader <hash> false` (the raw header) and, at ten heights, `getblockheader <hash> true` (its `chainwork`)
  4. `bitcoin-cli ... stop`
- SHA-256: `headers-0-2020.hex` `fadbc63bf33afe4abde919fe73a2c4ba096822ba9082f3c2c45cd3a354da809b`; `chainwork.txt` `b9cfbc662be6dcd587e3d7ef13d25ab258616bb2853e75e4090755e3e2e89d04`
- Why 2020 blocks and not 30: regtest never retargets, and the rule can only be seen at height 2016, where mainnet and signet rules would change the target. Core mined the blocks within seconds of each other, so almost every block carries the earliest time its median rule allows (the median of the eleven before it, plus one second): the boundary the chain's time rule has to accept.
- Used by: `crates/rescue-core/src/tests/headers.rs`, `proof.rs`
