#!/usr/bin/env python3

from .utils import *

def schnorr_sign(msg, seckey0, aux_rand):
    """Sign a message with a scret key."""
    
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes.')
    seckey0 = int_from_bytes(seckey0)
    if is_secret_overflow(seckey0):
        raise ScalarOverflowError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(curve.G, seckey0)
    seckey = seckey0 if has_even_y(P) else curve.n - seckey0
    t = xor_bytes(bytes_from_int(seckey), tagged_hash("BIP0340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % curve.n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(curve.G, k0)
    k = k0 if has_even_y(R) else curve.n - k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % curve.n
    return bytes_from_point(R) + bytes_from_int((k + e * seckey) % curve.n)


def schnorr_verify(msg, pubkey, sig):
    """Verify that a message was indeed signed with a specific secret key."""
    
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
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % curve.n
    R = point_add(point_mul(curve.G, s), point_mul(P, curve.n - e))
    if R is None or not has_even_y(R) or x(R) != r:
        return False
    return True


def schnorr_batch_verify(msgs, pubkeys, sigs):
    """Verify a array of messages with an array of public keys."""
    
    sig_num = len(msgs)
    if (sig_num != len(pubkeys) or sig_num != len(sigs)):
        raise RuntimeError('The count of Values must be equally.')
    s_sum = 0
    RP = None
    seed = hash_sha256(b''.join(sigs) + b''.join(msgs) + b''.join(pubkeys))
    rand_coefficient = [1]
    
    for i in range(len(msgs)):
        pubkey = pubkeys[i]
        msg = msgs[i]
        sig = sigs[i]
        if (i % 2 == 1):
            rand_coefficient = chacha20_prng(seed, i // 2)

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
        e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % curve.n
        
        R = point_from_bytes(sig[0:32])
        if (R is None):
            return False
        s_sum = (s_sum + (rand_coefficient[i % 2] * s)) % curve.n
        eP = point_mul(P, (rand_coefficient[i % 2] * e) % curve.n)
        aR = point_mul(R, rand_coefficient[i % 2])
        RP = point_add(point_add(aR, eP),RP)
    return point_mul(curve.G,s_sum) == RP

