#!/bin/sh
# Mines the recorded regtest chain on a private Bitcoin Core node and writes
# every header, genesis included, as raw hex one per line, and Core's own
# running total of work (`chainwork`) at a few heights.
#
#   sh mine.sh <empty datadir> <output directory>
#
# The node listens for RPC on 18543 only (never on Core's default 18443) and
# makes no peer connections. 2020 blocks is enough to pass height 2016, where
# mainnet rules retarget and regtest rules must not.
set -eu
datadir=$1
out=$2
cli="bitcoin-cli -regtest -datadir=$datadir -rpcport=18543 -rpcuser=winnowrescue -rpcpassword=vectors-only"
bitcoind -regtest -daemon -datadir="$datadir" -rpcport=18543 -port=18544 -listen=0 -connect=0 \
    -dnsseed=0 -discover=0 -server=1 -rpcuser=winnowrescue -rpcpassword=vectors-only \
    -nowallet=1 -printtoconsole=0 >&2
until $cli getblockchaininfo >/dev/null 2>&1; do sleep 1; done
# The BIP173 example program as a regtest address: no wallet is needed.
$cli generatetoaddress 2020 bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 >&2
tip=$($cli getblockcount)
: > "$out/headers-0-2020.hex"
: > "$out/chainwork.txt"
height=0
while [ "$height" -le "$tip" ]; do
    hash=$($cli getblockhash "$height")
    $cli getblockheader "$hash" false >> "$out/headers-0-2020.hex"
    case $height in
        0|1|10|11|12|30|2015|2016|2017|2020)
            echo "$height $hash $($cli getblockheader "$hash" true | grep '"chainwork"' | cut -d'"' -f4)" \
                >> "$out/chainwork.txt" ;;
    esac
    height=$((height + 1))
done
$cli stop >&2
