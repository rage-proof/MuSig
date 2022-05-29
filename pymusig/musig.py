#!/usr/bin/env python3
from pymusig.utils import point_from_bytes

from .utils import *

class CombinedPubkey:
    """
    This class represents a combined public key for all participating signers.

    In order to create a combined public key all separate public keys needs provided in advance.
    Compute X = (r[0]*X[0]) + (r[1]*X[1]) + ... + (r[n]*X[n])
    !!!The order/index of the public keys needs to be the same as in the MuSig session.!!!
    """
    PRE_SESSION_MAGIC = 0xf4adbbdf7c7dd304

    @staticmethod
    def hash_keys(pubkeys: list) -> bytes:
        """Computes ell = SHA256(pk[0], ..., pk[np-1])"""

        p = b''
        for pubkey in pubkeys:
            if len(pubkey) != 32:
                raise ValueError('The pubkeys must be a 32-byte array.')
            p += pubkey
        return tagged_hash('KeyAgg list', p)

    @staticmethod
    def determine_second_pk(pubkeys):
        first = pubkeys[0]
        for pubkey in pubkeys:
            if pubkey != first:
                return pubkey
        return None

    @staticmethod
    def key_agg_coefficient(ell, pk):
        """Compute r = SHA256(ell + pk). """
        
        return int_from_bytes(tagged_hash('KeyAgg coefficient', ell + pk)) % curve.n

    @staticmethod
    def create_pre_session(pre_session_magic, pk_hash, second_pk):
        """Creates a dictionary with fixed state values."""
        
        pre_session = dict()
        pre_session['pre_session_magic'] = pre_session_magic
        pre_session['pk_hash'] = pk_hash
        pre_session['second_pk'] = second_pk
        pre_session['pk_parity'] = 0
        pre_session['is_tweaked'] = False
        pre_session['tweak'] = 0
        return pre_session

    def __init__(self, pubkeys, pk_hash = None):
        P = None
        ell = pk_hash or CombinedPubkey.hash_keys(pubkeys)
        second_pk = CombinedPubkey.determine_second_pk(pubkeys)
        for i in range(len(pubkeys)):
            P_i = point_from_bytes(pubkeys[i])
            if (P_i is None):
                raise ValueError('Received an invalid public key. index: {}'.format(i))
            coefficient = 1 if second_pk == pubkeys[i] else CombinedPubkey.key_agg_coefficient(ell, pubkeys[i])
            summand = point_mul(P_i, coefficient)
            P = point_add(P, summand)
        self.__combined_pk = bytes_from_point_xy(P)
        #pk_parity = not has_even_y(P)
        self.__pre_session = CombinedPubkey.create_pre_session(self.PRE_SESSION_MAGIC, ell, second_pk)

    def get_pubkey(self):
        """Return the combined public key."""
        
        return self.__combined_pk

    def get_xpubkey(self):
        """Return the x value of combined public key."""

        return self.__combined_pk[:32]

    def get_pre_session(self):
        """Return the pre-session dictionary."""
        
        return self.__pre_session

    def pubkey_tweak_add(self, tweak):
        """Adding a tweak to the resulting public key."""

        if len(tweak) != 32:
            raise ValueError('The teak must be a 32-byte array.')
        int_tweak = int_from_bytes(tweak)
        pubkey = point_from_bytes_xy(self.__combined_pk)
        if not has_even_y(pubkey):
            pubkey = (x(pubkey), curve.p-y(pubkey))
            self.__pre_session['pk_parity']  ^= 1
            self.__pre_session['tweak'] = curve.n - self.__pre_session['tweak']
        self.__pre_session['tweak'] = (self.__pre_session['tweak'] + int_tweak) % curve.n
        tweak_point = point_mul(curve.G, int_tweak)
        pubkey = point_add(pubkey, tweak_point)
        if is_infinity(pubkey):
            raise ValueError('The resulting pubkey is invalid.')
        self.__pre_session['is_tweaked'] = True
        self.__combined_pk = bytes_from_point_xy(pubkey)

    def __str__(self):
        return 'combined public key: {}'.format(self.__combined_pk.hex())


class MuSigSession:
    """
    A Class that represents one multi signature session with n other participants.
    """
    
    @staticmethod
    def signers_init(n_signers):
        """Initialize the parties in the MuSig session and set their index number."""

        signers = []
        for i in range(n_signers):
            signers.append({'index': i,
                            'present': 0,
                            'pubnonces': [None, None]})
        return signers

    def __init__(self, session_id32, n_signers, seckey, combined_pk, pre_session, msg32 = None):
        if n_signers == 0:
            raise ValueError('Amount of signers is 0.')
        if n_signers > 2**32:
            raise ValueError('Amount of signers is too large.')
        if len(seckey) != 32:
            raise ValueError('The secret key must be a 32-byte array.')
        if len(session_id32) != 32:
            raise ValueError('The session id must be a 32-byte array.')
        if len(combined_pk) != 64:
            raise ValueError('The combined public key must be a 64-byte array.')

        if msg32 is not None:
            self.set_msg(msg32)
        else:
            self.msg_is_set = 0
            self.msg = None
        self.combined_pk64 = combined_pk
        self.combined_pk = combined_pk[:32]
        self.pre_session = pre_session
        self.secnonces = [None, None]
        self.pubnonces = [None, None]
        self.nonce_is_set = 0
        self.agg_nonces = [None, None]
        self.agg_nonces_set = 0
        self.nonce_coefficient = None
        self.fin_nonce = None
        self.fin_nonce_parity = None
        self.has_secret_data = 1
        self.n_signers = n_signers
        self.signers = MuSigSession.signers_init(self.n_signers)
        self.session_id = session_id32
        self.secret = seckey
        self.s_part = 0

        # compute secret key (x * a_i)
        secret = int_from_bytes(seckey)
        if is_secret_overflow(secret):
            raise ScalarOverflowError('The secret key is outside of the group order.')
        X = point_mul(curve.G, secret)
        if (not has_even_y(X) != (not has_even_y(point_from_bytes_xy(combined_pk)))) != self.pre_session['pk_parity']:
            secret = curve.n - secret
        coefficient = 1 if self.pre_session['second_pk'] == bytes_from_point(X) else \
            CombinedPubkey.key_agg_coefficient( self.pre_session['pk_hash'], bytes_from_point(X))
        self.seckey = bytes_from_int((coefficient * secret) % curve.n)

    def create_nonces(self, use_msg = True, use_seckey = True, use_pk = True, extra_input32 = None):
        """Create the two nonces R_i,1 and R_i,2."""

        msg = self.msg if use_msg is True else None
        key = self.secret if use_seckey is True else None
        pk = self.combined_pk if use_pk is True else None
        self.secnonces = MuSigSession.nonce_function(self.session_id, msg, key, pk, extra_input32)
        self.pubnonces = []
        for i in range(2):
            if is_secret_overflow(self.secnonces[i]):
                raise ScalarOverflowError('The nonce is outside of the group order.')
            # 2 Compute public nonces
            R = point_mul(curve.G, self.secnonces[i])
            self.pubnonces.append(bytes_from_point_xy(R))
        self.nonce_is_set = 1

    @staticmethod
    def nonce_function(id, msg, key, pk, extra_input):
        """Compute the pseudo random nonces."""

        if id is None:
            raise ValueError('The session id must not be None.')
        secnonces = []
        # compute secret nonces
        # DONT use a deterministic nonce!
        if key is not None:
            rand = bytearray(tagged_hash('MuSig/aux', id))
            for i in range(32):
                rand[i] = rand[i] ^ key[i]
        else:
            rand = id

        input = rand
        input += (32).to_bytes(1, 'big') + pk if pk is not None else (0).to_bytes(1, 'big')
        input += (32).to_bytes(1, 'big') + msg if msg is not None else (0).to_bytes(1, 'big')
        input += (0).to_bytes(3, 'big')
        input += (32).to_bytes(1, 'big') + extra_input if extra_input is not None else (0).to_bytes(1, 'big')
        for i in range(2):
            tmp = input + i.to_bytes(1, 'big')
            secnonces.append(int_from_bytes(tagged_hash('MuSig/nonce', tmp)))
        return secnonces

    def get_pubnonces(self):
        """Export the public nonces that needs to be transmitted to all signing parties."""

        if self.nonce_is_set == 0:
            raise RuntimeError('The local nonces needs to be set before exporting.')
        return self.pubnonces

    def set_msg(self, msg32):
        """Set the message value for the challenge, if it wasn't set initially."""

        if len(msg32) != 32:
            raise ValueError('The message must be a 32-byte array.')
        self.msg_is_set = 1
        self.msg = msg32
        return True

    def __agg_pubnonces(self, pubnonces):
        """  """

        if len(pubnonces) != self.n_signers:
            raise ValueError('The number of pubnonce pairs not equal number of signers.')
        if self.nonce_is_set == 0:
            raise RuntimeError('The local nonces needs to be set before calculating the aggregated ones.')

        agg_nonces = [None, None]
        for i in range(self.n_signers):
            for j in range(2):
                Rj = point_from_bytes_xy(pubnonces[i][j])
                agg_nonces[j] = point_add(agg_nonces[j], Rj)
        self.agg_nonces[0] = bytes_from_point_xy(agg_nonces[0])
        self.agg_nonces[1] = bytes_from_point_xy(agg_nonces[1])
        self.agg_nonces_set = 1
        return True

    def set_nonces(self, pubnonces):
        """Receive an array of public nonces and verify that they match the nonce commitments."""

        if len(pubnonces) != self.n_signers:
            raise ValueError('The number of pubnonce pairs not equal number of signers.')

        for i in range(len(pubnonces)):
            if len(pubnonces[i][0]) != 64:
                raise ValueError('The nonce R0 must be a 64-byte array. index: {}'.format(i))
            if len(pubnonces[i][1]) != 64:
                raise ValueError('The nonce R1 must be a 64-byte array. index: {}'.format(i))
            if point_from_bytes_xy(pubnonces[i][0]) is None:
                raise ValueError('The nonce R0 is Point at infinity. index: {}'.format(i))
            if point_from_bytes_xy(pubnonces[i][1]) is None:
                raise ValueError('The nonce R1 is Point at infinity. index: {}'.format(i))

            self.signers[i]['pubnonces'] = pubnonces[i]
            self.signers[i]['present'] = 1
        if not self.__agg_pubnonces(pubnonces):
            return False
        return True

    def combine_nonces(self, adaptor = None):
        """ Compute R = AggNonce[0] + AggNonce[1] * NonceCoefficient """

        if self.msg_is_set == 0:
            raise RuntimeError('The message must be set.')
        if self.agg_nonces_set == 0:
            raise RuntimeError('The public nonces needs be known.')

        R0 = point_from_bytes_xy(self.agg_nonces[0])
        R1 = point_from_bytes_xy(self.agg_nonces[1])

        if adaptor is not None:
            if len(adaptor) != 64:
                raise ValueError('The adaptor point must be a valid 64-byte array.')
            public_adaptor = point_from_bytes_xy(adaptor)
            if public_adaptor is None:
                raise ValueError('Adaptor is invalid Curve Point.')
            R0 = point_add(R0, public_adaptor)

        # calculate nonce coefficient b
        nonce_hash = tagged_hash("MuSig/noncecoef" ,compress_pubkey_xy(bytes_from_point_xy(R0)) +
                                 compress_pubkey_xy(bytes_from_point_xy(R1)) + self.combined_pk + self.msg)
        b = int_from_bytes(nonce_hash)
        if is_secret_overflow(b):
            raise ScalarOverflowError('The nonce coefficient is outside of the group order.')
        R1 = point_mul(R1, b)
        final_nonce = point_add(R0, R1)
        self.nonce_coefficient = b
        self.fin_nonce = bytes_from_point(final_nonce)
        self.fin_nonce_parity = not has_even_y(final_nonce)
        self.challenge = int_from_bytes(tagged_hash("BIP0340/challenge", self.fin_nonce + self.combined_pk + self.msg)) % curve.n
        self.s_part = 0
        if self.pre_session['tweak'] != 0:
            e = (self.pre_session['tweak'] * self.challenge) % curve.n
            if not has_even_y(point_from_bytes_xy(self.combined_pk64)):
                e = curve.n - e
            self.s_part = (self.s_part + e) % curve.n
        return True

    def partial_sign(self):
        """Compute s = (k[0] + k[1] * b) + e * x with the own secret key and secret nonces."""

        if self.nonce_is_set == 0:
            raise RuntimeError('The local nonces needs to be set before calculating the aggregated ones.')
        if self.has_secret_data == 0:
            raise RuntimeError('Not a session initiallized as signer.')
        if self.msg_is_set == 0:
            raise RuntimeError('The message is missing.')
        if self.fin_nonce is None:
            raise RuntimeError('The combined nonce is missing.')

        k = [self.secnonces[0], self.secnonces[1]]
        if self.fin_nonce_parity is True:
            k[0] = curve.n - k[0]
            k[1] = curve.n - k[1]
        s = (((k[1] * self.nonce_coefficient) + k[0]) + (self.challenge * int_from_bytes(self.seckey))) % curve.n
        return bytes_from_int(s)


    def partial_sig_verify(self, sig, pubkey, i):
        """Validate a signature with a public key."""

        if self.nonce_is_set == 0:
            raise RuntimeError('The combined nonce is missing.')
        if (self.signers[i]['present'] != 1):
            raise RuntimeError('Nonce is missing from session participant.')
        if len(sig) != 32:
            raise ValueError('The signature must be a 32-byte array.')
        if len(pubkey) != 32:
            raise ValueError('The public key must be a 32-byte array.')

        R0 = point_from_bytes_xy(self.signers[i]['pubnonces'][0])
        R1 = point_from_bytes_xy(self.signers[i]['pubnonces'][1])
        Ri = point_mul(R1, self.nonce_coefficient)
        Ri = point_add(Ri, R0)
        coefficient = 1 if self.pre_session['second_pk'] == pubkey else \
            CombinedPubkey.key_agg_coefficient(self.pre_session['pk_hash'], pubkey)
        e = (self.challenge * coefficient) % curve.n
        if self.pre_session['pk_parity'] != (not has_even_y(point_from_bytes_xy(self.combined_pk64))) :
            e = curve.n - e
        s = int_from_bytes(sig)
        if is_secret_overflow(s):
            raise ScalarOverflowError('The signature is outside of the group order.')
        s = curve.n - s
        Si = point_mul(curve.G, s)
        Pi = point_from_bytes(pubkey)
        RP = point_add(Si, point_mul(Pi, e))
        # This is needed for the combined nonce only. It's the opposite action to signing process.
        Ri = (x(Ri), curve.p - y(Ri)) if self.fin_nonce_parity is True else Ri
        SUM = point_add(RP, Ri)
        return is_infinity(SUM)

    def partial_sig_combine(self, sigs):
        """
        Compute the sum of all signature from an array of partial signatures.

        s_sum = s[0] + s[1] + ...  + s[n]
        """

        if self.fin_nonce is None:
            raise RuntimeError('The combined nonce is missing.')
        if len(sigs) != self.n_signers:
            raise ValueError('The number of signatures is not equal the signing parties.')
        s_sum = self.s_part
        for i in range(len(sigs)):
            if len(sigs[i]) != 32:
                raise ValueError('The signature must be a 32-byte array. index: {}'.format(i))
            s = int_from_bytes(sigs[i])
            if is_secret_overflow(s):
                raise ScalarOverflowError('The signature is outside of the group order. index: {}'.format(i))
            s_sum = (s_sum + s) % curve.n
        self.combined_sig = bytes_from_int(s_sum)
        return self.fin_nonce + self.combined_sig

    def partial_sig_adapt(self, sig, secret_adaptor):
        """Compute sig_a' = sig_a + t"""

        if self.nonce_is_set == 0:
            raise RuntimeError('The combined nonce is missing.')
        if len(sig) != 32:
            raise ValueError('The signature must be a 32-byte array.')
        if len(secret_adaptor) != 32:
            raise ValueError('The adaptor secret must be a 32-byte array.')
                             
        s = int_from_bytes(sig)
        if is_secret_overflow(s):
            raise ScalarOverflowError('The signature is outside of the group order.')
        t = int_from_bytes(secret_adaptor)
        if is_secret_overflow(t):
            raise ScalarOverflowError('The adaptor key is outside of the group order.')

        if self.fin_nonce_parity is True:
            t = curve.n - t
        return bytes_from_int((s + t) % curve.n)

    def extract_secret_adaptor(self, partial_sigs, final_sig):
        """Compute s_sum - s[0] - s[1] - ... - s[n] = t"""

        if len(partial_sigs) != self.n_signers:
            raise ValueError('The number of signatures is not equal the signing parties.')
        if len(final_sig) != 64 :
            raise ValueError('The final signature must be a 64-byte array.')
        t = int_from_bytes(final_sig[32:])
        if is_secret_overflow(t):
            raise ScalarOverflowError('The signature is outside of the group order.')
        t = curve.n - t
        
        for i in range(self.n_signers):
            if len(partial_sigs[i]) != 32:
                raise ValueError('The signature must be a 32-byte array. index: {}'.format(i))
            s = int_from_bytes(partial_sigs[i])
            if is_secret_overflow(s):
                raise ScalarOverflowError('The signature is outside of the group order. index: {}'.format(i))
            t = (t + s) % curve.n
            
        if not self.fin_nonce_parity:
            t = curve.n - t
        return bytes_from_int(t)
