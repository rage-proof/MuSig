"""
MuSig Implemenation for Python

This is an implemation of the muSig Proposl for schnorr multisignatures.
Paper: https://eprint.iacr.org/2018/068

Reference C implementation:
https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/musig

Javascript implementation:
https://github.com/guggero/bip-schnorr
""" #kommtin __init__.py

from .schnorr import schnorr_sign, schnorr_verify, schnorr_batch_verify
from .utils import *

MUSIG_TAG = hash_sha256(b'MuSig coefficient')
PRE_SESSION_MAGIC = 0xf4adbbdf7c7dd304


class CombinedPubkey:

    @staticmethod
    def musig_coefficient(ell, idx):
        """Compute r = SHA256(ell, idx). The four bytes of idx are serialized least significant byte first. """
        h = hash_sha256(MUSIG_TAG + MUSIG_TAG + ell + idx.to_bytes(4, byteorder="little"))
        return int_from_bytes(h) % curve.n

    @staticmethod
    def musig_compute_ell(pubkeys: list)-> bytes:
        """Computes ell = SHA256(pk[0], ..., pk[np-1])"""
        #pubkeys.sort(key = int_from_bytes) #wo anders muss das hin
        p = b''
        for pubkey in pubkeys:
            if len(pubkey) != 32:
                raise ValueError('The pubkeys must be a 32-byte array.')
            p += pubkey
        return hash_sha256(p)

    def __init__(self, pubkeys, pk_hash= None, pre_session = None):
        """Compute X = (r[0]*X[0]) + (r[1]*X[1]) + ..., + (r[n]*X[n])"""
        P = None
        ell = pk_hash or CombinedPubkey.musig_compute_ell(pubkeys)
        for i in range(len(pubkeys)):
            P_i = point_from_bytes(pubkeys[i])
            coefficient = CombinedPubkey.musig_coefficient(ell,i)
            summand = point_mul(P_i,coefficient)
            P = point_add(P,summand)
        is_negated = not has_square_y(P)
        self.__combined_pk = bytes_from_point(P)
        self.__pre_session = self.__create_pre_session(PRE_SESSION_MAGIC, ell , is_negated)

    def __create_pre_session(self, pre_session_magic, pk_hash, is_negated, tweak_is_set = 0):
        pre_session = dict()
        pre_session['pre_session_magic'] = pre_session_magic
        pre_session['pk_hash'] = pk_hash
        pre_session['is_negated'] = is_negated
        pre_session['tweak_is_set'] = tweak_is_set
        return pre_session

    def get_key(self):
        return self.__combined_pk

    def get_pre_session(self):
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

    def __init__(self, session_id32, n_signers, my_index, seckey, combined_pk, pre_session, msg32):
        """
        Parameters
        ----------
        session_id32 : 32 byte array
            
        """

        if n_signers == 0:
            raise ValueError('Amount of signers equal 0.')
        if my_index >= n_signers:
            raise ValueError('my_index is bigger that the number of all participants.')
        if n_signers > 2**32:
            raise ValueError('Amount of signers is too large.')
        if pre_session['pre_session_magic'] != PRE_SESSION_MAGIC:
            raise ValueError('Session magic has a wrong value.')
        
        self.msg_is_set = 1
        self.msg = msg32          
        self.combined_pk = combined_pk
        self.pre_session = pre_session
        self.nonce_is_set = 0
        self.has_secret_data = 1
        self.n_signers = n_signers
        self.signers = self.__signers_init(self.n_signers)
        self.nonce_commitments_hash_is_set = 0
        self.nonce_commitments_hash = None
        
        # 1 compute secret key
        coefficient = CombinedPubkey.musig_coefficient(self.pre_session['pk_hash'], my_index)
        X = point_mul(curve.G, int_from_bytes(seckey))
        seckey = curve.n - int_from_bytes(seckey) if not has_square_y(X) else int_from_bytes(seckey)
        self.seckey = (coefficient * seckey) % curve.n
        
        # 2 compute secret nonce
        # DONT use a deterministic nonce! 
        self.secnonce = int_from_bytes(hash_sha256(session_id32 + self.msg + combined_pk + bytes_from_int(seckey))) % curve.n # original no mod
   
        # 3 Compute public nonce and commitment
        R = point_mul(curve.G, self.secnonce) 
        self.secnonce = curve.n - self.secnonce if not has_square_y(R) else self.secnonce        
        self.nonce = bytes_from_point(R)
        self.nonce_commitment = hash_sha256(self.nonce)

    def __signers_init(self, n_signers):
        """Initialize the parties in the MuSig session and set their index number."""
        
        signers = []
        for i in range(n_signers):
            signers.append({'index':i,'present':0})      
        return signers
        
    def get_public_nonce(self, commitments):
        """Receive an array of nonce commitments(H(x(R))) from the other signers and return the public nonce(x(R))."""
        
        if (len(commitments) != self.n_signers or self.has_secret_data == 0):
            raise ValueError('The number of commitments is incomplete.') 
        
        for i in range(self.n_signers):
             if len(commitments[i]) != 32:
                raise ValueError('The commitment of R must be a 32-byte array.')
        
        nonce_commitments = b''
        for i in range(len(commitments)):
            self.signers[i]['nonce_commitment'] = commitments[i]
            nonce_commitments = nonce_commitments + commitments[i]
        nonce_commitments_hash = hash_sha256(nonce_commitments)
        
        if (nonce_commitments_hash != self.nonce_commitments_hash and self.nonce_commitments_hash_is_set == 1):
            raise ValueError('get_public_nonce has called before with a different set of commitments.')
        
        self.nonce_commitments_hash = nonce_commitments_hash
        self.nonce_commitments_hash_is_set = 1
        return self.nonce  
    
    def set_nonce(self, nonces):
        """ """
        
        if len(nonces) != self.n_signers:
            return False
        
        if (self.nonce_commitments_hash_is_set == 0):
            return False
                
        for i in range(len(nonces)):
            if len(nonces[i]) != 32:
                raise ValueError('The nonce (R) must be a 32-byte array.')
            if self.signers[i]['nonce_commitment'] != hash_sha256(nonces[i]):
                return False
            self.signers[i]['nonce'] = nonces[i]
            self.signers[i]['present'] = 1
        return True
        
        
    def combine_nonces(self):
        """Compute R = R[0] + R[1] + ..., + R[n]"""
        
        R0 = None
        for i in range(self.n_signers):
            if self.signers[i]['present'] != 1:
                return False  
            R0 = point_add(R0,point_from_bytes(self.signers[i]['nonce']))

        if not has_square_y(R0):
            self.nonce_is_negated = True
        else:
            self.nonce_is_negated = False 
        self.combined_nonce = bytes_from_point(R0)
        self.nonce_is_set = 1
        return True
    
    
    def partial_sign(self):
        if self.nonce_is_set == 0:
            raise ValueError('The combined nonce is missing.')
        if self.has_secret_data == 0:
            raise ValueError('Not a session initiallized as signer.')
        if self.msg_is_set == 0:
            raise ValueError('The message is missing.')
            
        e = int_from_bytes(hash_sha256(self.combined_nonce + self.combined_pk + self.msg)) % curve.n
        k = curve.n - self.secnonce if self.nonce_is_negated else self.secnonce
        s = (k + (e * self.seckey)) % curve.n
        return bytes_from_int(s)

    
    def partial_sig_verify(self, sig, pubkey, i):
        if self.nonce_is_set == 0:
            raise ValueError('The combined nonce is missing.')          
        if (self.signers[i]['present'] != 1):
            raise RuntimeError('Nonce is missing from party.')
        
        e = int_from_bytes(hash_sha256(self.combined_nonce + self.combined_pk + self.msg)) % curve.n
        coefficient = CombinedPubkey.musig_coefficient(self.pre_session['pk_hash'], self.signers[i]['index'])
        Ri = point_from_bytes(self.signers[i]['nonce'])    
        Si = point_mul(curve.G, int_from_bytes(sig))
        Pi = point_from_bytes(pubkey)
        RP = point_add(Si, point_mul(Pi, curve.n - ((e * coefficient) % curve.n)))
        # this is needed for the combined nonce only. it's the opposite action to signing
        RP = (x(RP), curve.p - y(RP)) if not self.nonce_is_negated else RP
        SUM = point_add(RP, Ri)
        if not is_infinity(SUM):
            return False
        return True
   
    
    def partial_sig_combine(self, sigs, pubkeys):
        for i in range(len(sigs)):
            if not self.partial_sig_verify(sigs[i], pubkeys[i], i):
                raise RuntimeError('Signature could not be verified. Index: ',i)
        s_sum = 0
        for i in range(len(sigs)):
            s_sum = (s_sum + int_from_bytes(sigs[i])) % curve.n
        self.combined_sig = bytes_from_int(s_sum)
        return self.combined_nonce + self.combined_sig
        
