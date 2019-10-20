import collections
import hashlib

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

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def point_add(P1, P2):
    if (P1 is None):
        return P2
    if (P2 is None):
        return P1
    if (P1[0] == P2[0] and P1[1] != P2[1]):
        return None
    if (P1 == P2):
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p)) % p
    else:
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p)) % p
    x3 = (lam * lam - P1[0] - P2[0]) % p
    return (x3, (lam * (P1[0] - x3) - P1[1]) % p)

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
    y_sq = (pow(x, 3, p) + 7) % p
    y0 = pow(y_sq, (p + 1) // 4, p)
    if pow(y0, 2, p) != y_sq:
        return None
    return (x, y0)

def int_from_bytes(b):
    return int.from_bytes(b, byteorder="big") 

def tagged_hash(tag, msg):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def hash_sha256(b):
    return hashlib.sha256(b).digest()

def jacobi(x):
    return pow(x, (p - 1) // 2, p)

def create_key_pair():
    seckey0 = int_from_bytes(os.urandom(32)) % n
    if seckey0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    pubkey = point_mul(G, seckey0)
    seckey = n - seckey0 if (jacobi(pubkey[1]) != 1) else seckey0
    return seckey, bytes_from_point(pubkey)

def schnorr_sign(msg, seckey):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if not (1 <= seckey <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    k0 = int_from_bytes(tagged_hash("BIPSchnorrDerive", bytes_from_int(seckey) + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0)
    k = n - k0 if (jacobi(R[1]) != 1) else k0
    e = int_from_bytes(tagged_hash("BIPSchnorr", bytes_from_int(R[0]) + bytes_from_point(point_mul(G, seckey)) + msg)) % n
    return bytes_from_int(R[0]) + bytes_from_int((k + e * seckey) % n)

def schnorr_verify(msg, pubkey, sig):
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
    if (r >= p or s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIPSchnorr", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if R is None or jacobi(R[1]) != 1 or R[0] != r:
        return False
    return True

import os

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
        if (r >= p or s >= n):
            return False
        e = int_from_bytes(tagged_hash("BIPSchnorr", sig[0:32] + pubkey + msg)) % n
        
        R = point_from_bytes(sig[0:32])
        if (R is None):
            return False
        
        s_sum = (s_sum + s) % n
        eP = point_mul(P, e)
        RP = point_add(point_add(R, eP),RP)
    return point_mul(G,s_sum) == RP

    
def main2():
    
    msg = tagged_hash("BIPSchnorr", b'Test')
    msg2 = tagged_hash("BIPSchnorr", b'Tesdsggdfgihdfuhugfdhut')
    msg3 = tagged_hash("BIPSchnorr", b'Tesbvbt')
    msg4 = tagged_hash("BIPSchnorr", b'Tesdsggdfgihdfuhugfdhut')

    x,P = create_key_pair()
    x2,P2 = create_key_pair()
    x3,P3 = create_key_pair()
    x4,P4 = create_key_pair()

    sig = schnorr_sign(msg,x)
    sig2 = schnorr_sign(msg2,x2)
    sig3 = schnorr_sign(msg3,x3)
    sig4 = schnorr_sign(msg4,x4)
    
    print(x,P)


    print(schnorr_verify(msg, P, sig))
    print(schnorr_verify(msg2, P2, sig2))
    
    
    sigs = [sig,sig2,sig3,sig4]
    msgs = [msg,msg2,msg3,msg4]
    pubkeys = [P,P2,P3,P4]
    print(schnorr_batch_verify(msgs,pubkeys,sigs))
    
    
def main():
    
    x = int_from_bytes(os.urandom(32))
    P = point_mul(G, x)
    print('P: ',P)
    
    assert P[0] <= p,"Zahl passt nicht"
    
    y_sq = (pow(P[0], 3, p) + 7) % p
    y0 = pow(y_sq, (p + 1) // 4, p)
    if pow(y0, 2, p) != y_sq:
        raise ValueError('y stimmt nicht.')
    
    
    print('P2:',(P[0],y0))
    print(p-P[1])
    
    print('Test2: ' , pow(P[1], 2, p))
    print('Test1: ' , pow(y0, 2, p) )
    
    
    

if __name__ == '__main__':
    main2()
