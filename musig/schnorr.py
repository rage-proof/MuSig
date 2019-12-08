#!/usr/bin/env python3

from .utils import *

def schnorr_sign(msg, seckey0):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    seckey0 = int_from_bytes(seckey0)
    if not (1 <= seckey0 <= curve.n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(curve.G, seckey0)
    seckey = seckey0 if has_square_y(P) else curve.n - seckey0
    k0 = int_from_bytes(tagged_hash("BIPSchnorrDerive", bytes_from_int(seckey) + msg)) % curve.n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(curve.G, k0)
    k = curve.n - k0 if not has_square_y(R) else k0
    e = int_from_bytes(tagged_hash("BIPSchnorr", bytes_from_point(R) + bytes_from_point(P) + msg)) % curve.n
    return bytes_from_int(R[0]) + bytes_from_int((k + e * seckey) % curve.n)

def schnorr_verify(msg, pubkey, sig, tag = "BIPSchnorr"):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = point_from_bytes(pubkey)
    if (P is None):
        return False
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (r >= curve.p or s >= curve.n):
        return False
    e = int_from_bytes(tagged_hash(tag, sig[0:32] + pubkey + msg)) % curve.n
    R = point_add(point_mul(curve.G, s), point_mul(P, curve.n - e))
    print(r)#
    print(R)#
    if R is None or not has_square_y(R) or x(R) != r:
        return False
    return True

def schnorr_batch_verify(msgs, pubkeys, sigs):
    u = len(msgs)
    if (u != len(pubkeys) or u != len(sigs)):
        raise ValueError('The count of Values must be equally.')
    s_sum = 0
    RP = None
    for i in range(len(msgs)):
        pubkey = pubkeys[i]
        msg = msgs[i]
        sig = sigs[i]
        
        if len(msg) != 32:
            raise ValueError('The message must be a 32-byte array.')
        if len(pubkey) != 32:
            raise ValueError('The public key must be a 32-byte array.')
        if len(sig) != 64:
            raise ValueError('The signature must be a 64-byte array.')
        
        P = point_from_bytes(pubkey)
        if (P is None):
            return False
        r = int_from_bytes(sig[0:32])
        s = int_from_bytes(sig[32:64])
        if (r >= curve.p or s >= curve.n):
            return False
        e = int_from_bytes(tagged_hash("BIPSchnorr", sig[0:32] + pubkey + msg)) % curve.n
        
        R = point_from_bytes(sig[0:32])
        if (R is None):
            return False
        
        s_sum = (s_sum + s) % curve.n
        eP = point_mul(P, e)
        RP = point_add(point_add(R, eP),RP)
    return point_mul(curve.G,s_sum) == RP

