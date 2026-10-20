"""Records two mainnet coins with their merkle proofs.

Run as `python3 -I fetch_proofs.py <electrum host> <port>` in this directory.
For each transaction it keeps, as the servers answered: the raw bytes
(`/tx/:txid/raw`, binary, kept as hex), the transaction's own JSON (`/tx/:txid`, the source of the
expected scripts and amounts), the Esplora merkle proof
(`/tx/:txid/merkle-proof`), the Electrum one (`blockchain.transaction.get_merkle`)
and the 80-byte header of its block (`/block/:hash/header`). Nothing here uses
the code under test.
"""
import json
import socket
import ssl
import sys
import urllib.request

ESPLORA = "https://blockstream.info/api"

# name: (block height, position in the block)
COINS = {
    "proof-block1-coinbase.json": (1, 0),
    "proof-block862000-pos1500.json": (862000, 1500),
}


def get_bytes(path):
    request = urllib.request.Request(ESPLORA + path, headers={"User-Agent": "winnowrescue-vectors"})
    return urllib.request.urlopen(request, timeout=30).read()


def get(path):
    return get_bytes(path).decode().strip()


def electrum(host, port, method, params):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    stream = context.wrap_socket(socket.create_connection((host, port), timeout=30)).makefile("rwb")
    for ident, (name, args) in enumerate([("server.version", ["winnowrescue", "1.4"]), (method, params)]):
        stream.write((json.dumps({"id": ident, "method": name, "params": args}) + "\n").encode())
        stream.flush()
        reply = json.loads(stream.readline())
    return reply["result"]


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    for name, (height, position) in COINS.items():
        block = get(f"/block-height/{height}")
        txid = json.loads(get(f"/block/{block}/txids"))[position]
        record = {
            "fetched": "2026-10-20",
            "txid": txid,
            "block_height": height,
            "block_hash": block,
            "header": get(f"/block/{block}/header"),
            "raw": get_bytes(f"/tx/{txid}/raw").hex(),  # the endpoint answers binary
            "esplora_tx": json.loads(get(f"/tx/{txid}")),
            "esplora_merkle_proof": json.loads(get(f"/tx/{txid}/merkle-proof")),
            "electrum_get_merkle": electrum(host, port, "blockchain.transaction.get_merkle", [txid, height]),
        }
        with open(name, "w") as out:
            json.dump(record, out, indent=1)
            out.write("\n")
        print(name, txid, "position", record["esplora_merkle_proof"]["pos"],
              "branch", len(record["esplora_merkle_proof"]["merkle"]))


main()
