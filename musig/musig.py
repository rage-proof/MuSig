#!/usr/bin/env python3

from .utils import *

MUSIG_TAG = 'MuSig coefficient'
PRE_SESSION_MAGIC = 0xf4adbbdf7c7dd304


class CombinedPubkey:
    """
    This class represents a combined public key for all participating signers.

    In order to create a combined public key all separate public keys needs provided in advance.
    Compute X = (r[0]*X[0]) + (r[1]*X[1]) + ... + (r[n]*X[n])
    !!!The order/index of the public keys needs to be the same as in the MuSig session.!!!
    """

    @staticmethod
    def musig_coefficient(ell, idx):
        """Compute r = SHA256(ell, idx). The four bytes of idx are serialized least significant byte first. """
        
        return int_from_bytes(tagged_hash(MUSIG_TAG, ell + idx.to_bytes(4, byteorder="little"))) % curve.n

    @staticmethod
    def musig_compute_ell(pubkeys: list) -> bytes:
        """Computes ell = SHA256(pk[0], ..., pk[np-1])"""
        
        #pubkeys.sort(key = int_from_bytes) #rethink
        p = b''
        for pubkey in pubkeys:
            if len(pubkey) != 32:
                raise ValueError('The pubkeys must be a 32-byte array.')
            p += pubkey
        return hash_sha256(p)

    @staticmethod
    def create_pre_session(pre_session_magic, pk_hash, is_negated, tweak_is_set=False):
        """Creates a dictionary with fixed state values."""
        
        pre_session = dict()
        pre_session['pre_session_magic'] = pre_session_magic
        pre_session['pk_hash'] = pk_hash
        pre_session['is_negated'] = is_negated
        pre_session['tweak_is_set'] = tweak_is_set
        return pre_session

    def __init__(self, pubkeys, pk_hash = None, pre_session = None):
        P = None
        ell = pk_hash or CombinedPubkey.musig_compute_ell(pubkeys)
        for i in range(len(pubkeys)):
            P_i = point_from_bytes(pubkeys[i])
            if (P_i is None):
                raise ValueError('Received a invalid public key. index: {}'.format(i))
            coefficient = CombinedPubkey.musig_coefficient(ell,i)
            summand = point_mul(P_i,coefficient)
            P = point_add(P,summand)
        is_negated = not has_square_y(P)
        self.__combined_pk = bytes_from_point(P)
        self.__pre_session = CombinedPubkey.create_pre_session(PRE_SESSION_MAGIC, ell, is_negated)

    def get_key(self):
        """Return the combined public key."""
        
        return self.__combined_pk

    def get_pre_session(self):
        """Return the pre-session dictionary."""
        
        return self.__pre_session

    def __str__(self):
        return 'combined public key: {} \nis quadratic?: {}'.format(int_from_bytes(self.__combined_pk),
                                                                    not self.__pre_session['is_negated'])


class MuSigSession:
    """
    A Class that represents one multi signature session with n participants.
    

    Methods
    -------
    
    """
    
    @staticmethod
    def signers_init(n_signers):
        """Initialize the parties in the MuSig session and set their index number."""

        signers = []
        for i in range(n_signers):
            signers.append({'index':i,'present':0})
        return signers

    def __init__(self, session_id32, n_signers, my_index, seckey, combined_pk, pre_session, msg32):
        """
        Parameters
        ----------
        session_id32 : 32 byte array
        #todo
            
        """

        if n_signers == 0:
            raise ValueError('Amount of signers is 0.')
        if my_index >= n_signers:
            raise ValueError('my_index is bigger that the number of all participants.')
        if n_signers > 2**32:
            raise ValueError('Amount of signers is too large.')
        if pre_session['pre_session_magic'] != PRE_SESSION_MAGIC:
            raise ValueError('Session magic has a wrong value.')
        if len(msg32) != 32:
            raise ValueError('The message must be a 32-byte array.')
        if len(seckey) != 32:
            raise ValueError('The secret key must be a 32-byte array.')
        if len(session_id32) != 32:
            raise ValueError('The session id must be a 32-byte array.')
        if len(combined_pk) != 32:
            raise ValueError('The combined public key must be a 32-byte array.')

        self.__msg_is_set = 1
        self.__msg = msg32
        self.__combined_pk = combined_pk
        self.__pre_session = pre_session
        self.__nonce_is_set = 0
        self.__has_secret_data = 1
        self.__n_signers = n_signers
        self.__signers = MuSigSession.signers_init(self.__n_signers)
        self.__nonce_commitments_hash_is_set = 0
        self.__nonce_commitments_hash = None

        # 1 compute secret key
        secret = int_from_bytes(seckey)
        if is_secret_overflow(secret):
            raise ScalarOverflowError('The secret key is outside of the group order.') 
        coefficient = CombinedPubkey.musig_coefficient(self.__pre_session['pk_hash'], my_index)
        X = point_mul(curve.G, secret)
        secret = curve.n - secret if (not has_square_y(X)) ^ self.__pre_session['is_negated'] else secret
        self.__seckey = (coefficient * secret) % curve.n

        # 2 compute secret nonce
        # DONT use a deterministic nonce! 
        self.__secnonce = int_from_bytes(hash_sha256(session_id32 + msg32 + combined_pk + seckey))
        if is_secret_overflow(self.__secnonce):
            raise ScalarOverflowError('The nonce is outside of the group order.')         

        # 3 Compute public nonce and commitment
        R = point_mul(curve.G, self.__secnonce)
        self.__secnonce = curve.n - self.__secnonce if not has_square_y(R) else self.__secnonce
        self.__nonce = bytes_from_point(R)
        self.__nonce_commitment = hash_sha256(self.__nonce)

    def get_nonce_commitment(self):
        """Return the nonce commitment for this signer."""
        
        return self.__nonce_commitment

    def get_public_nonce(self, commitments):
        """Receive an array of nonce commitments(H(x(R))) from the other signers and return the public nonce(x(R))."""

        if (len(commitments) != self.__n_signers or self.__has_secret_data == 0):
            raise ValueError('The number of commitments is incomplete.')
        for i in range(self.__n_signers):
             if len(commitments[i]) != 32:
                raise ValueError('The commitment of the nonce must be a 32-byte array.')

        nonce_commitments = b''
        for i in range(len(commitments)):
            self.__signers[i]['nonce_commitment'] = commitments[i]
            nonce_commitments = nonce_commitments + commitments[i]
        nonce_commitments_hash = hash_sha256(nonce_commitments)

        if (nonce_commitments_hash != self.__nonce_commitments_hash and self.__nonce_commitments_hash_is_set == 1):
            raise RuntimeError('get_public_nonce has called before with a different set of commitments.')

        self.__nonce_commitments_hash = nonce_commitments_hash
        self.__nonce_commitments_hash_is_set = 1
        return self.__nonce
    
    def set_nonce(self, nonces):
        """Receive an array of public nonces and verify that they match the nonce commitments."""

        if len(nonces) != self.__n_signers:
            raise ValueError('The number of nonces is incomplete.')
        if (self.__nonce_commitments_hash_is_set == 0):
            raise RuntimeError('The nonce commitments must be known before adding the public nonces.')

        for i in range(len(nonces)):
            if len(nonces[i]) != 32:
                raise ValueError('The nonce (R) must be a 32-byte array. index: {}'.format(i))
            if point_from_bytes(nonces[i]) is None:
                raise ValueError('The nonce (R) is invalid curve Point. index: {}'.format(i))
            if self.__signers[i]['nonce_commitment'] != hash_sha256(nonces[i]):
                raise RuntimeError('The nonce of one or more signers doesn\'t match the commitment. index: {} '.format(i))
            self.__signers[i]['nonce'] = nonces[i]
            self.__signers[i]['present'] = 1
        return True

    def combine_nonces(self, adaptor = None):
        """Compute R = R[0] + R[1] + ..., + R[n]"""

        R0 = None
        for i in range(self.__n_signers):
            if self.__signers[i]['present'] != 1:
                raise RuntimeError('The nonce of one or more signers is not correctly set yet. index: {} '.format(i))
            R0 = point_add(R0, point_from_bytes(self.__signers[i]['nonce']))
        #check for nonce_commitments_hash #https://github.com/jonasnick/secp256k1-zkp/blob/schnorrsig-updates/src/modules/musig/main_impl.h
        #add adaptor point
        if adaptor is not None:
            if len(adaptor) != 64:
                raise ValueError('The adaptor point must be a valid 64-byte array.')
            public_adaptor = point_from_bytes_xy(adaptor)
            if public_adaptor is None:
                raise ValueError('Adaptor is invalid Curve Point')
            R0 = point_add(R0, public_adaptor)
        self.__nonce_is_negated = not has_square_y(R0)
        self.__combined_nonce = bytes_from_point(R0)
        self.__nonce_is_set = 1
        return True

    def partial_sign(self, tag = 'BIPSchnorr'):
        """Compute s = k + e*x with the own secret key and secret nonce."""
        
        if self.__nonce_is_set == 0:
            raise RuntimeError('The combined nonce is missing.')
        if self.__has_secret_data == 0:
            raise RuntimeError('Not a session initiallized as signer.')
        if self.__msg_is_set == 0:
            raise RuntimeError('The message is missing.')

        e = int_from_bytes(tagged_hash(tag, self.__combined_nonce + self.__combined_pk + self.__msg)) % curve.n
        k = curve.n - self.__secnonce if self.__nonce_is_negated else self.__secnonce
        s = (k + (e * self.__seckey)) % curve.n
        return bytes_from_int(s)

    def partial_sig_verify(self, sig, pubkey, i, tag = 'BIPSchnorr'):
        """Validate a signature with a public key."""
        
        if self.__nonce_is_set == 0:
            raise RuntimeError('The combined nonce is missing.')
        if (self.__signers[i]['present'] != 1):
            raise RuntimeError('Nonce is missing from session participant.')
        if len(sig) != 32:
            raise ValueError('The signature must be a 32-byte array.')
        if len(pubkey) != 32:
            raise ValueError('The public key must be a 32-byte array.')

        s = int_from_bytes(sig)
        if is_scalar_overflow(s):
            raise ScalarOverflowError('The signature is outside of the group order.') 

        coefficient = CombinedPubkey.musig_coefficient(self.__pre_session['pk_hash'], self.__signers[i]['index'])
        e = int_from_bytes(tagged_hash(tag, self.__combined_nonce + self.__combined_pk + self.__msg)) % curve.n
        e = curve.n - ((e * coefficient) % curve.n) if self.__pre_session['is_negated'] else (e * coefficient) % curve.n
        Ri = point_from_bytes(self.__signers[i]['nonce'])
        Si = point_mul(curve.G, s)
        Pi = point_from_bytes(pubkey)
        RP = point_add(Si, point_mul(Pi, curve.n - e))
        # This is needed for the combined nonce only. It's the opposite action to signing.
        RP = (x(RP), curve.p - y(RP)) if not self.__nonce_is_negated else RP
        SUM = point_add(RP, Ri)
        if not is_infinity(SUM):
            return False
        return True

    def partial_sig_combine(self, sigs):
        """
        Compute the sum of all signature from an array of partial signatures.

        s_sum = s[0] + s[1] + ...  + s[n]
        """
        
        if self.__nonce_is_set == 0:
            raise RuntimeError('The combined nonce is missing.')
        if len(sigs) != self.__n_signers:
            raise ValueError('The number of signatures is not equal the signing parties.')
        s_sum = 0
        for i in range(len(sigs)):
            if len(sigs[i]) != 32:
                raise ValueError('The signature must be a 32-byte array. index: {}'.format(i))
            s = int_from_bytes(sigs[i])
            if is_scalar_overflow(s):
                raise ScalarOverflowError('The signature is outside of the group order. index: {}'.format(i))
            s_sum = (s_sum + s) % curve.n
        self.__combined_sig = bytes_from_int(s_sum)
        return self.__combined_nonce + self.__combined_sig

    def partial_sig_adapt(self, sig, secret_adaptor):
        """Compute sig_a' = sig_a + t"""

        if self.__nonce_is_set == 0:
            raise RuntimeError('The combined nonce is missing.')
        if len(sig) != 32:
            raise ValueError('The signature must be a 32-byte array.')
        if len(secret_adaptor) != 32:
            raise ValueError('The adaptor secret must be a 32-byte array.')
                             
        s = int_from_bytes(sig)
        if is_scalar_overflow(s):
            raise ScalarOverflowError('The signature is outside of the group order.')
        t = int_from_bytes(secret_adaptor)
        if is_secret_overflow(t):
            raise ScalarOverflowError('The adaptor key is outside of the group order.')
        
        if self.__nonce_is_negated:
            t = curve.n - t
        return bytes_from_int((s + t) % curve.n)

    def extract_secret_adaptor(self, partial_sigs, final_sig):
        """Compute s_sum - s[0] - s[1] - ... - s[n] = t"""

        if len(partial_sigs) != self.__n_signers:
            raise ValueError('The number of signatures is not equal the signing parties.')
        if len(final_sig) != 64 :
            raise ValueError('The final signature must be a 64-byte array.')
        t = int_from_bytes(final_sig[32:])
        if is_scalar_overflow(t):
            raise ScalarOverflowError('The signature is outside of the group order.')
        t = curve.n - t
        
        for i in range(self.__n_signers):
            if len(partial_sigs[i]) != 32:
                raise ValueError('The signature must be a 32-byte array. index: {}'.format(i))
            s = int_from_bytes(partial_sigs[i])
            if is_scalar_overflow(s):
                raise ScalarOverflowError('The signature is outside of the group order. index: {}'.format(i))
            t = (t + s) % curve.n
            
        if not self.__nonce_is_negated:
            t = curve.n - t
        return bytes_from_int(t)
