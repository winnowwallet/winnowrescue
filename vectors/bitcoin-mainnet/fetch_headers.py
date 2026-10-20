"""Fetches the four recorded mainnet header ranges from a public Electrum server.

Run as `python3 -I fetch_headers.py <host> <port>` in this directory. It asks
`blockchain.block.headers`, the call whose answer the header chain absorbs
unchanged, checks that every header links to the one before it by hashing with
plain hashlib, and writes one 80-byte header per line as lowercase hex.
Nothing here uses the code under test.
"""
import hashlib
import json
import socket
import ssl
import sys

RANGES = {
    # name: (first height, last height)
    "headers-0-4032.hex": (0, 4032),
    # The eleven headers before the first checkpoint, the checkpoint, and one more.
    "headers-11100-11112.hex": (11100, 11112),
    "headers-858816-860831.hex": (858816, 860831),
    "headers-860832-864864.hex": (860832, 864864),
}


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def connect(host, port):
    # Public data checked below by hash links and, later, by proof of work, so
    # a server's self-signed certificate is not a concern here.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    stream = context.wrap_socket(socket.create_connection((host, port), timeout=30))
    return stream.makefile("rwb")


def call(stream, ident, method, params):
    request = {"id": ident, "method": method, "params": params}
    stream.write((json.dumps(request) + "\n").encode())
    stream.flush()
    reply = json.loads(stream.readline())
    if "result" not in reply:
        sys.exit(f"{method} failed: {reply}")
    return reply["result"]


def fetch(stream, first, last):
    headers = []
    height = first
    while height <= last:
        count = min(2016, last - height + 1)
        result = call(stream, height, "blockchain.block.headers", [height, count])
        raw = bytes.fromhex(result["hex"])
        if result["count"] != count or len(raw) != 80 * count:
            sys.exit(f"short answer at {height}: {result['count']} headers")
        headers += [raw[i : i + 80] for i in range(0, len(raw), 80)]
        height += count
    return headers


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    stream = connect(host, port)
    call(stream, 0, "server.version", ["winnowrescue-fetch", "1.4"])
    for name, (first, last) in RANGES.items():
        headers = fetch(stream, first, last)
        for a, b in zip(headers, headers[1:]):
            if b[4:36] != sha256d(a):
                sys.exit(f"{name}: a header does not link to its predecessor")
        with open(name, "w") as out:
            out.write("".join(h.hex() + "\n" for h in headers))
        print(name, len(headers), "headers; first block hash", sha256d(headers[0])[::-1].hex())


main()
