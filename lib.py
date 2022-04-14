import hashlib


def hash(e, B, q, uni_hash):
    return [((a * sha256(e) + b) % q) % B for a, b in uni_hash]


def sha256(e):
    return int(hashlib.sha256(e.encode('utf-8')).hexdigest(), 16)


def strc(c, s):
    colors = {'r': 31, 'b': 34, 'g': 32, 'y': 33, 'm': 35, 'c': 36}
    return f"\u001b[{colors[c]}m{s}\u001b[0m"


def printv(verbose, s):
    if verbose:
        print(strc('b', s))
