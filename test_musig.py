import os

from musig import *
from musig.utils import create_key_pair, hash_sha256, int_from_bytes, curve, point_add, point_mul,point_from_bytes #curve
from musig.schnorr import schnorr_verify


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

    #ell = CombinedPubkey.musig_compute_ell(pubkeys)
    combined_pk = CombinedPubkey(pubkeys)
    sessions = []
    nonce_commitments = []
    for i in range(N_SIGNERS):
        session_id32 = os.urandom(32)
        session = MuSigSession(session_id32, N_SIGNERS, i, seckeys[i], combined_pk.get_key(), combined_pk.get_pre_session(), msg32)
        sessions.append(session)
        nonce_commitments.append(session.nonce_commitment) #TODO: method für nonce create
        
    nonces = []
    #1 Set nonce commitments in the signer data and get the own public nonce
    for i in range(N_SIGNERS):
        nonces.append(sessions[i].get_public_nonce(nonce_commitments))
    
    sigs = []
    #2 Set public nonces for all participants, create a combined nonce and create the own partial signature
    for i in range(N_SIGNERS):
        if not sessions[i].set_nonce(nonces):
            raise ValueError('Setting the public nonce failed.')
            
        if not sessions[i].combine_nonces():
            raise ValueError('Combining all nonces together failed.')
        sigs.append(sessions[i].partial_sign())
    
    final_sigs = [] 
    #3 exchanges partial sigs and combine them to one
    for i in range(N_SIGNERS):
        for j in range(N_SIGNERS):
            if not sessions[i].partial_sig_verify(sigs[j], pubkeys[j], j):
                raise RuntimeError('Signature could not be verified. Index: ',j)
            
        final_sigs.append(sessions[i].partial_sig_combine(sigs, pubkeys))

    if final_sigs[0] != final_sigs[1] or final_sigs[1] != final_sigs[2]:
        print('   * Signature aggregation failed.')
    else:
        print('   * Signature aggregation successful.')
    #print(final_sigs[0],len(final_sigs[0]))

    print(schnorr_verify(msg32,combined_pk.get_key(),final_sigs[0],tag=''))
    
    

if __name__ == '__main__':
    main()
