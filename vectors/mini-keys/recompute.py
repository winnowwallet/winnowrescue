"""Recomputes the expected values in mini-keys.json from the two mini keys.

Standard library only: hashlib for SHA-256 and RIPEMD-160, and plain Python
integers for secp256k1. It shares no code with rescue-core, which is the point.

    python3 -I recompute.py            # prints the values it computes
    python3 -I recompute.py --check    # also asserts mini-keys.json agrees
"""
import hashlib
import json
import os
import sys

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (m * m - a[0] - b[0]) % P
    return (x, (m * (a[0] - x) - a[1]) % P)


def mul(k, point=G):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def compute(text):
    assert len(text) in (22, 30) and text[0] == "S" and all(c in B58 for c in text)
    # The check byte: SHA-256 of the text plus "?" must start with a zero byte.
    assert hashlib.sha256((text + "?").encode()).digest()[0] == 0
    secret = hashlib.sha256(text.encode()).digest()
    k = int.from_bytes(secret, "big")
    assert 0 < k < N
    x, y = mul(k)
    uncompressed = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return {
        "text": text,
        "secret_hex": secret.hex(),
        "wif_uncompressed": b58check(b"\x80" + secret),
        "p2pkh_uncompressed": b58check(b"\x00" + hash160(uncompressed)),
    }


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "mini-keys.json")) as f:
        recorded = json.load(f)
    for row in recorded["keys"]:
        got = compute(row["text"])
        print(json.dumps(got, indent=2))
        if "--check" in sys.argv:
            assert got == row, "mini-keys.json disagrees with the recomputation"
    if "--check" in sys.argv:
        print("mini-keys.json agrees")
