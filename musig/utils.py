#!/usr/bin/env python3

import collections
import hashlib
import os
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
    def __init__(self, message='Value outside of the group order.'):
        super().__init__()
        self.message = message
 
    def __str__(self):
        return self.message
    
    

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
    return bytes_from_int(P[0])

def point_from_bytes(b):
    x = int_from_bytes(b)
    y_sq = (pow(x, 3, curve.p) + 7) % curve.p
    y0 = pow(y_sq, (curve.p + 1) // 4, curve.p)
    if pow(y0, 2, curve.p) != y_sq:
        return None
    return (x, y0)

def int_from_bytes(b):
    return int.from_bytes(b, byteorder="big")


def tagged_hash(tag, msg):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def hash_sha256(b):
    return hashlib.sha256(b).digest()

def is_infinity(P):
    return P is None

def is_square(x):
    return pow(x, (curve.p - 1) // 2, curve.p) == 1

def has_square_y(P):
    return not is_infinity(P) and is_square(y(P))

def x(P):
    return P[0]

def y(P):
    return P[1]

def scalar_overflow(x):
    return not (1 <= x <= curve.n - 1)

def chacha20_prng(key, counter):
    nonce = bytes(12)
    chacha20 = ChaCha(key, nonce)
    key_stream = chacha20.key_stream(counter)
    r1 = int_from_bytes(key_stream[:32])
    r2 = int_from_bytes(key_stream[32:])
    if scalar_overflow(r1):
        raise ScalarOverflowError('r1 outside of the group order.')
    if scalar_overflow(r2):
        raise ScalarOverflowError('r2 outside of the group order.')
    return [r1, r2]

def pubkey_gen(seckey):
    x = int_from_bytes(seckey)
    if scalar_overflow(x):
        raise ScalarOverflowError('Secret key outside of the group order.')
    P = point_mul(curve.G, x)
    return bytes_from_point(P)

def create_key_pair():
    seckey0 = int_from_bytes(os.urandom(32)) % curve.n
    if scalar_overflow(seckey0):
        raise ScalarOverflowError('Secret key outside of the group order.')
    pubkey = point_mul(curve.G, seckey0)
    #seckey = curve.n - seckey0 if not  has_square_y(pubkey) else seckey0
    seckey = seckey0
    return bytes_from_int(seckey), bytes_from_point(pubkey)



