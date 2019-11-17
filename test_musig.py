import os

from musig import *
from musig.utils import create_key_pair, hash_sha256



def main():
    N_SIGNERS = 3
    seckeys = []
    pubkeys = []
    msg32 = hash_sha256(b'Test')
    print('Starting test of musig multisignature key aggregation session.')
    print()
    print('Signing Parties: {}'.format(N_SIGNERS))
    for _ in range(N_SIGNERS):
        seckey,pubkey = create_key_pair()
        seckeys.append(seckey)
        pubkeys.append(pubkey)

    ell = musig_compute_ell(pubkeys)
    combined_pk = musig_pubkey_combine(pubkeys,ell)
    
    sessions = []
    nonce_commitments = []
    for i in range(N_SIGNERS):
        session_id32 = os.urandom(32)
        session = MuSigSession(session_id32, N_SIGNERS, i, seckeys[i], combined_pk, pk_hash32=ell, msg32=msg32)
        sessions.append(session)
        nonce_commitments.append(session.nonce_commitment) #TODO: method für nonce create
        
    
    nonces = []
    #1 Set nonce commitments in the signer data and get the own public nonce
    for i in range(N_SIGNERS):
        nonces.append(sessions[i].get_public_nonce(nonce_commitments))
    
    sig = []
    #2 Set public nonces for all participants, create a combined nonce and create the own partial signature
    for i in range(N_SIGNERS):
        if not sessions[i].set_nonce(nonces):
            raise ValueError('Setting the public nonce failed.')
            
        if not sessions[i].combine_nonces():
            raise ValueError('Combining all nonces together failed.')
        sig.append(sessions[i].partial_sign())

    final_sigs = [] # for testing the result of the final signature
    #3 exchanges partial sigs and combine them to one
    for i in range(N_SIGNERS):
        if not sessions[i].partial_sig_verify(sig, pubkeys):
            raise RuntimeError('One or more signature were not correct.')
            
        final_sigs.append(sessions[i].partial_sig_combine(sig, pubkeys))

    if final_sigs[0] != final_sigs[1] or final_sigs[1] != final_sigs[2]:
        print('   * Signature aggregation failed.')
    else:
        print('   * Signature aggregation successful.')
        

    

if __name__ == '__main__':
    main()
