#!/usr/bin/env python3

import collections
import hashlib
from chacha20poly1305 import ChaCha

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p G n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Base point.
    G=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


class ScalarOverflowError(ValueError):
    pass

class CommitmentVerifyError(RuntimeError):
    pass

def x(P):
    return P[0]

def y(P):
    return P[1]

def point_add(P1, P2):
    if (P1 is None):
        return P2
    if (P2 is None):
        return P1
    if (P1[0] == P2[0] and P1[1] != P2[1]):
        return None
    if (P1 == P2):
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], curve.p - 2, curve.p)) % curve.p
    else:
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], curve.p - 2, curve.p)) % curve.p
    x3 = (lam * lam - P1[0] - P2[0]) % curve.p
    return (x3, (lam * (P1[0] - x3) - P1[1]) % curve.p)


def point_mul(P, n):
    R = None
    for i in range(256):
        if ((n >> i) & 1):
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(x):
    return x.to_bytes(32, byteorder="big")

def bytes_from_point(P):
    return bytes_from_int(x(P))

def compress_pubkey_xy(b):
    P = point_from_bytes_xy(b)
    return ((2).to_bytes(1, 'little') if has_even_y(P) else (3).to_bytes(1, 'little')) + bytes_from_point(P)

def bytes_from_point_xy(P):
    return bytes_from_int(x(P)) + bytes_from_int(y(P))

def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(x ^ y for (x, y) in zip(b0, b1))

def point_from_compressed_bytes(b):
    parity = int_from_bytes(b[:1])
    x = int_from_bytes(b[1:])
    if x >= curve.p:
        return None
    y_sq = (pow(x, 3, curve.p) + 7) % curve.p
    y = pow(y_sq, (curve.p + 1) // 4, curve.p)
    if pow(y, 2, curve.p) != y_sq:
        return None
    if (y & 1) == 0 and parity == 3:
        y = curve.p-y
    return (x, y)

def point_from_bytes(b):
    x = int_from_bytes(b)
    if x >= curve.p:
        return None
    y_sq = (pow(x, 3, curve.p) + 7) % curve.p
    y = pow(y_sq, (curve.p + 1) // 4, curve.p)
    if pow(y, 2, curve.p) != y_sq:
        return None
    return (x, y if y & 1 == 0 else curve.p-y)

def point_from_bytes_xy(b):
    x = int_from_bytes(b[:32])
    y = int_from_bytes(b[32:])
    if x >= curve.p or y >= curve.p:
        return None
    if pow(y, 2, curve.p) != (pow(x, 3, curve.p) + 7) % curve.p:
        return None
    return (x, y)


def int_from_bytes(b):
    return int.from_bytes(b, byteorder="big")

def hash_sha256(b):
    return hashlib.sha256(b).digest()

def tagged_hash(tag, msg):
    tag_hash = hash_sha256(tag.encode())
    return hash_sha256(tag_hash + tag_hash + msg)

def is_infinity(P):
    return P is None

def has_even_y(P) -> bool:
    assert not is_infinity(P)
    return y(P) % 2 == 0

def is_secret_overflow(x):
    return not (1 <= x <= curve.n - 1)

def chacha20_prng(key, counter):
    nonce = bytes(12)
    chacha20 = ChaCha(key, nonce)
    key_stream = chacha20.key_stream(counter)
    r1 = int_from_bytes(key_stream[:32])
    r2 = int_from_bytes(key_stream[32:])
    if is_secret_overflow(r1):
        raise ScalarOverflowError('r1 outside of the group order.')
    if is_secret_overflow(r2):
        raise ScalarOverflowError('r2 outside of the group order.')
    return [r1, r2]

def pubkey_gen(seckey):
    x = int_from_bytes(seckey)
    if is_secret_overflow(x):
        raise ScalarOverflowError('Secret key outside of the group order.')
    P = point_mul(curve.G, x)
    return bytes_from_point(P)

def pubkey_gen_xy(seckey):
    x = int_from_bytes(seckey)
    if is_secret_overflow(x):
        raise ScalarOverflowError('Secret key outside of the group order.')
    P = point_mul(curve.G, x)
    return bytes_from_point_xy(P)



