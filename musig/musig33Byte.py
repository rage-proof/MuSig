
from .schnorr import schnorr_sign, schnorr_verify, schnorr_batch_verify
from .utils33Byte import *

MUSIG_TAG = hash_sha256(b'MuSig coefficient')

def musig_compute_ell(pubkeys: list)-> bytes:
    """Computes ell = SHA256(pk[0], ..., pk[np-1])"""
    p = b''
    for pubkey in pubkeys:
        p += pubkey
    return hash_sha256(p)


def musig_coefficient(ell, idx):
    """Compute r = SHA256(ell, idx). The four bytes of idx are serialized least significant byte first. """
    h = hash_sha256(MUSIG_TAG + MUSIG_TAG + ell + idx.to_bytes(4, byteorder="little"))
    return int_from_bytes(h) % curve.n # checken


def musig_pubkey_combine(pubkeys, pubkey_hash = None):
    """Compute X = (r[0]*X[0]) + (r[1]*X[1]) + ..., + (r[n]*X[n])"""
    P = None
    ell = pubkey_hash or musig_compute_ell(pubkeys)
    for i in range(len(pubkeys)):
        P_i = point_from_bytes(pubkeys[i])
        coefficient = musig_coefficient(ell,i)
        summand = point_mul(P_i,coefficient)
        P = point_add(P,summand)
    return bytes_from_point(P)
        

class MuSigSession:

    @staticmethod
    def musig_signers_init(n_signers):
        """Initialize the parties in the MuSig session and set their index number."""
        signers = []
        for i in range(n_signers):
            signers.append({'index':i,'present':0})      
        return signers
    
    def __init__(self, session_id32, n_signers, my_index, seckey, combined_pk, pk_hash32, msg32 = None):

        if n_signers == 0:
             raise ValueError('Amount of signers equal 0.')
        if my_index > n_signers:
             raise ValueError('my_index is bigger that the number of all participants.')
        if n_signers >= 2**32:
             raise ValueError('Amount of signers is too large.')
        
        if (msg32 is not None):
            self.msg_is_set = 1
            self.msg = msg32
        else:
            self.msg_is_set = 0
            self.msg = None
            
        self.combined_pk = combined_pk
        self.pk_hash = pk_hash32
        self.nonce_is_set = 0
        self.has_secret_data = 1
        self.n_signers = n_signers
        self.signers = self.musig_signers_init(self.n_signers)
        self.nonce_commitments_hash_is_set = 0
        self.nonce_commitments_hash = None
        
        # 1 compute secret key
        coefficient = musig_coefficient(pk_hash32, my_index)
        self.seckey = (coefficient * int_from_bytes(seckey)) % curve.n
        
        # 2 compute secret nonce
        self.secnonce = int_from_bytes(\
                        hash_sha256(session_id32 + (self.msg if (self.msg is not None) else b'') + combined_pk + seckey)\
                                      ) % curve.n
   
        # 3 Compute public nonce and commitment
        R = point_mul(curve.G, self.secnonce) #
        #self.secnonce = curve.n - self.secnonce if not has_square_y(R) else self.secnonce #        
        self.nonce = bytes_from_point(R)
        self.nonce_commitment = hash_sha256(self.nonce)
        
        

        
    def get_public_nonce(self, commitments):
        
        if (len(commitments) != self.n_signers or self.has_secret_data == 0):
            raise ValueError('The commitments are wrong.')
        
        for i in range(len(commitments)):
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
    
    
    def set_msg(self, msg32):    
        if self.msg_is_set == 1:
            return False
        self.msg = msg32
        self.msg_is_set = 1
        return True
    
    
    def set_nonce(self, nonces):   
        if len(nonces) != self.n_signers:
            return False
        if (self.nonce_commitments_hash_is_set == 0):
            return False
                
        for i in range(len(nonces)):
            if self.signers[i]['nonce_commitment'] != hash_sha256(nonces[i]):
                return False
            self.signers[i]['nonce'] = nonces[i]
            self.signers[i]['present'] = 1
        return True
        
        
    def combine_nonces(self):
        R0 = None
        for i in range(self.n_signers):
            if self.signers[i]['present'] != 1:
                return False  
            R0 = point_add(R0,point_from_bytes(self.signers[i]['nonce']))

        if not has_square_y(R0):
            R = [x(R0), curve.p - y(R0)]
            self.nonce_is_negated = True
        else:
            R = R0
            self.nonce_is_negated = False
        self.combined_nonce = bytes_from_point(R)
        self.nonce_is_set = 1
        return True
    
    
    def partial_sign(self):
        if self.nonce_is_set == 0:
            raise ValueError('The combined nonce is missing.')
        if self.has_secret_data == 0:
            raise ValueError('Not a session initiallized as signer.')
        if self.msg_is_set == 0:
            raise ValueError('The message is missing.')
            
        e = int_from_bytes(hash_sha256(self.combined_nonce[1:33] + self.combined_pk + self.msg))
        k = curve.n - self.secnonce if self.nonce_is_negated else self.secnonce
        s = (k + (e * self.seckey)) % curve.n
        return s

    
    def partial_sig_verify(self, sigs, pubkeys):
        if self.nonce_is_set == 0:
            raise ValueError('The combined nonce is missing.')
            
        if (len(sigs) != self.n_signers) or (len(sigs) != len(pubkeys)):
            return False
        
        e = int_from_bytes(hash_sha256(self.combined_nonce[1:33] + self.combined_pk + self.msg))
        for i in range(self.n_signers):
            if (self.signers[i]['present'] != 1):
                return False  #throw error

            coefficient = musig_coefficient(self.pk_hash, self.signers[i]['index'])
            Ri = point_from_bytes(self.signers[i]['nonce'])
            
            Si = point_mul(curve.G, sigs[i])
            Pi = point_from_bytes(pubkeys[i])          
            RP = point_add(Si, point_mul(Pi, curve.n - ((e * coefficient) % curve.n)))
            RP = (x(RP), curve.p - y(RP)) if not self.nonce_is_negated else RP
            SUM = point_add(RP, Ri)
            if not is_infinity(SUM):
                return False
        return True
    
    
    def partial_sig_combine(self, sigs, pubkeys):
        if not self.partial_sig_verify(sigs, pubkeys):
            raise RuntimeError('At least one signatur is wrong.')          
        s_sum = 0
        for i in range(len(sigs)):
            s_sum = (s_sum + sigs[i]) % curve.n
        self.combined_sig = bytes_from_int(s_sum)
        return self.combined_nonce[1:33] + self.combined_sig 
        
