MUSIG_TAG = hash_sha256(b'MuSig coefficient')


def secp256k1_musig_compute_ell(pubkeys: list)-> bytes:
    """Computes ell = SHA256(pk[0], ..., pk[np-1])"""
    pubkeys.sort(key = int_from_bytes) #wo anders muss das hin
    p = b''
    for pubkey in pubkeys:
        if len(pubkey) != 32:
            raise ValueError('The pubkeys must be a 32-byte array.')
        p += pubkey
    return hash_sha256(p)


def secp256k1_musig_coefficient(ell, idx):
    """Compute r = SHA256(ell, idx). The four bytes of idx are serialized least significant byte first. """
    h = hash_sha256(MUSIG_TAG + MUSIG_TAG + ell + bytes_from_int(idx))
    return int_from_bytes(h) % curve.n


def secp256k1_musig_pubkey_combine(pubkeys, pubkey_hash = None):
    """Compute X = (r[0]*X[0]) + (r[1]*X[1]) + ..., + (r[n]*X[n])"""
    P = None
    ell = pubkey_hash or secp256k1_musig_compute_ell(pubkeys)
    for i in range(len(pubkeys)):
        P_i = point_from_bytes(pubkeys[i])
        coefficient = secp256k1_musig_coefficient(ell,i)
        summand = point_mul(P_i,coefficient)
        P = point_add(P,summand)
    return bytes_from_point(P)
        

def secp256k1_musig_signers_init(n_signers):
    signers = []
    for i in range(n_signers):
        signers.append({'index':i,'present':0})      
    return signers
    

class MuSig:
    
    
    def __init__(self, session_id32, n_signers, my_index, seckey, combined_pk, pk_hash32, msg32 = None):

        if n_signers == 0:
             raise ValueError('Amount of signers equal 0.')
        if my_index > n_signers:
             raise ValueError('my_index is bigger that the number of all participants.')
        if n_signers >= 2**32:
             raise ValueError('Amount of signers is too big.')
        
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
        self.signers = secp256k1_musig_signers_init(self.n_signers)
        self.nonce_commitments_hash_is_set = 0
        self.nonce_commitments_hash = None
        
        # compute secret key
        coefficient = secp256k1_musig_coefficient(pk_hash32, my_index)
        self.seckey = (coefficient * seckey) % curve.n
        
        # compute secret nonce
        self.secnonce = int_from_bytes(\
                        hash_sha256(session_id32 + (self.msg if (self.msg is not None) else b'') + combined_pk + bytes_from_int(seckey))\
                                      ) % curve.n # original kein mod
   
        # Compute public nonce and commitment
    
        R = point_mul(curve.G, self.secnonce) #
        self.secnonce = curve.n - self.secnonce if (jacobi(R[1]) != 1) else self.secnonce #
        
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
            if len(nonces[i]) != 32:
                raise ValueError('The nonce (R) must be a 32-byte.')
            if self.signers[i]['nonce_commitment'] != hash_sha256(nonces[i]):
                return False
            self.signers[i]['nonce'] = nonces[i]
            self.signers[i]['present'] = 1
        return True
        
        
    def combine_nonces(self):
        R = None
        for i in range(self.n_signers):
            if self.signers[i]['present'] != 1:
                return False  
            R = point_add(R,point_from_bytes(self.signers[i]['nonce']))
               
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
            
        e = int_from_bytes(hash_sha256(self.combined_nonce + self.combined_pk + self.msg))
        s = (self.secnonce + (e * self.seckey)) % curve.n
        return s

    
    def partial_sig_verify(self, sigs, pubkeys):
        if self.nonce_is_set == 0:
            raise ValueError('The combined nonce is missing.')
            
        if (len(sigs) != self.n_signers) or (len(sigs) != len(pubkeys)):
            return False
        
        e = int_from_bytes(hash_sha256(self.combined_nonce + self.combined_pk + self.msg))
        
        for i in range(self.n_signers):
            
            if (self.signers[i]['present'] != 1):
                return False  #throw error
            
            coefficient = secp256k1_musig_coefficient(self.pk_hash, self.signers[i]['index'])
            Ri = point_from_bytes(self.signers[i]['nonce'])
            Si = point_mul(curve.G, sigs[i])
            Pi = point_from_bytes(pubkeys[i])
            
            RP = point_add(Si, point_mul(Pi, curve.n - ((e * coefficient) % curve.n)))
            
            sig = point_add(point_mul(Pi, (e * coefficient) % curve.n), Ri)
            
            print('right ', sig)
            print('left ', Si)
            
    


def main3():
    N_SIGNERS = 3
    seckeys = []
    pubkeys = []
    msg32 = hash_sha256(b'Test')
    for _ in range(N_SIGNERS):
        seckey,pubkey = create_key_pair()
        seckeys.append(seckey)
        pubkeys.append(pubkey)

    ell = secp256k1_musig_compute_ell(pubkeys)
    combined_pk = secp256k1_musig_pubkey_combine(pubkeys,ell)
    
    sessions = []
    nonce_commitments = []
    for i in range(N_SIGNERS):
        session_id32 = os.urandom(32)
        session = MuSig(session_id32, N_SIGNERS, i, seckeys[i], combined_pk, pk_hash32=ell, msg32=msg32)
        sessions.append(session)
        nonce_commitments.append(session.nonce_commitment)
        
    print(nonce_commitments) #communicate the commitments
    
    nonces = []
    #1 Set nonce commitments in the signer data and get the own public nonce
    for i in range(N_SIGNERS):
        nonces.append(sessions[i].get_public_nonce(nonce_commitments))
    
    sig = []
    #2 exchanges nonces
    for i in range(N_SIGNERS):
        if not sessions[i].set_nonce(nonces):
            raise ValueError('Failed.')
            
        if not sessions[i].combine_nonces():
            raise ValueError('Failed.')
        print(sessions[i].combined_nonce)
        sig.append(sessions[i].partial_sign())
        print(sig[i])
    
    
    #3 exchanges partial sigs
    sessions[0].partial_sig_verify(sig, pubkeys)
    #for i in range(N_SIGNERS):
        #if not sessions[i].partial_sig_verify():
        #    raise RuntimeError('one or more signature where not correct')
        #sessions[i].partial_sig_verify(sig, pubkeys)
    
        
    

    


    

if __name__ == '__main__':
    main3()
    
    
