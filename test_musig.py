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
    print(combined_pk)
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
    
    sig = []
    #2 Set public nonces for all participants, create a combined nonce and create the own partial signature
    for i in range(N_SIGNERS):
        if not sessions[i].set_nonce(nonces):
            raise ValueError('Setting the public nonce failed.')
            
        if not sessions[i].combine_nonces():
            raise ValueError('Combining all nonces together failed.')
        sig.append(sessions[i].partial_sign())
    
    final_sigs = [] 
    #3 exchanges partial sigs and combine them to one
    for i in range(N_SIGNERS):
        for j in range(N_SIGNERS):
            if not sessions[i].partial_sig_verify(sig[j], pubkeys[j], j):
                raise RuntimeError('Signature could not be verified. Index: ',j)
            
        final_sigs.append(sessions[i].partial_sig_combine(sig, pubkeys))

    if final_sigs[0] != final_sigs[1] or final_sigs[1] != final_sigs[2]:
        print('   * Signature aggregation failed.')
    else:
        print('   * Signature aggregation successful.')
    """
    # delete from here
    print()
    print(int_from_bytes(final_sigs[0][0:32]))
    print(point_from_bytes(sessions[0].combined_nonce))
    print()

    Rx = int_from_bytes(final_sigs[0][0:32])
    s = int_from_bytes(sessions[0].combined_sig)#geändert und 50% sind korrekt
    P = point_from_bytes(combined_pk.get_key())
    if (s >= curve.n):
        raise
    e = int_from_bytes(hash_sha256(final_sigs[0][0:32] + combined_pk.get_key() + msg32)) % curve.n
    R = point_add(point_mul(curve.G, s), point_mul(P, curve.n - e))
    print(Rx)
    print(R)
    

    #print(schnorr_verify(msg32, combined_pk, final_sigs[1],""))
    """

   
        

    

if __name__ == '__main__':
    main()
