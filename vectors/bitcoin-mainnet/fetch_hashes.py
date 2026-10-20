"""Records the block hash at the heights the tests check, from an Esplora server.

Run as `python3 -I fetch_hashes.py` in this directory. Each line of
`block-hashes.txt` is a height and the hash of the block there, written the
way explorers write it. The answers come from `/block-height/:height`, and the
tests compare them with the hashes of the recorded headers, so a header file
and a second source have to agree. Nothing here uses the code under test.
"""
import urllib.request

ESPLORA = "https://blockstream.info/api"
HEIGHTS = [0, 1, 2015, 2016, 4032, 11111, 858816, 860831, 860832, 862000, 862848, 864864]


def get(path):
    request = urllib.request.Request(ESPLORA + path, headers={"User-Agent": "winnowrescue-vectors"})
    return urllib.request.urlopen(request, timeout=30).read().decode().strip()


with open("block-hashes.txt", "w") as out:
    for height in HEIGHTS:
        out.write(f"{height} {get(f'/block-height/{height}')}\n")
