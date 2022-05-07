#!/usr/bin/env python3
"""
Script for functional testing of a complete MuSig2 multisignature creation.
"""
import os

from pymusig import CombinedPubkey, MuSigSession, schnorr_verify
from pymusig.utils import pubkey_gen, pubkey_gen_xy, hash_sha256

N_SIGNERS = 3

def main():
    seckeys = []
    pubkeys = []
    msg32 = hash_sha256(b'Test')
    print('   Starting test of Musig2 multi-signature key aggregation session.')
    print('\n   Signing Parties: {}'.format(N_SIGNERS))
    for _ in range(N_SIGNERS):
        seckey = os.urandom(32)
        seckeys.append(seckey)
        pubkey = pubkey_gen(seckey)
        pubkeys.append(pubkey)
    print(' * Secret and public key pairs created for different signers.')
    
    combined_pk = CombinedPubkey(pubkeys)
    print(' * Combined public key created from the provided public keys successfully.')
    sessions = []
    pubnonces = []
    for i in range(N_SIGNERS):
        session_id32 = os.urandom(32)
        session = MuSigSession(session_id32, N_SIGNERS, seckeys[i], combined_pk.get_pubkey(),
                               combined_pk.get_pre_session(), msg32)
        print(' * MuSig session initialized for signer: {}.'.format(i+1))

        session.set_msg(msg32)
        session.create_nonces()
        sessions.append(session)
        pubnonces.append(session.get_pubnonces())

    # 1 Set both public nonces for all participants. Create a combined nonce and create the own partial signature.
    sigs = []
    for i in range(N_SIGNERS):
        if not sessions[i].set_nonces(pubnonces):
            raise ValueError(' - Setting the public nonce failed.')
        if not sessions[i].combine_nonces():
            raise ValueError(' - Combining all nonces together failed.')
        sigs.append(sessions[i].partial_sign())
    print('\n * 1st Round: Public nonce exchanged and combined nonce created successfully.')

    # 2 exchanges partial sigs and combine them to one
    final_sigs = []
    for i in range(N_SIGNERS):
        for j in range(N_SIGNERS):
            if not sessions[i].partial_sig_verify(sigs[j], pubkeys[j], j):
                raise RuntimeError(' - Signature could not be verified. Index: ', j)
        final_sigs.append(sessions[i].partial_sig_combine(sigs))
    print(' * 2nd Round: partial signatures created and exchanged successfully.')

    if final_sigs[0] != final_sigs[1] or final_sigs[1] != final_sigs[2]:
        print(' - Signature aggregation failed.')
    else:
        print(' * Signature aggregation successful.')
    if schnorr_verify(msg32, combined_pk.get_xpubkey(), final_sigs[0]):
        print(' * Final signature validation successful.')
    else:
        print(' - Final signature validation failed.')

#################################################################################

    # Test of Adaptor Signature
    print('\n----------------------------------\n')
    print('   Test case Adaptor Signature')
    secret_adaptor = os.urandom(32)
    public_adaptor = pubkey_gen_xy(secret_adaptor)

    sigs = list()
    for i in range(N_SIGNERS):
        if not sessions[i].combine_nonces(public_adaptor):
            raise ValueError('Combining all nonces together with adaptor failed.')
        sigs.append(sessions[i].partial_sign())
    print(' * Combined nonce with adaptor offset creation successful.')
    print(' * Creating partial signatures of every signer.')
    final_sigs = list()
    for  i in range(N_SIGNERS):
        for j in range(N_SIGNERS):
            if not sessions[i].partial_sig_verify(sigs[j], pubkeys[j], j):
                raise RuntimeError('Signature could not be verified. Index: ', j)
        final_sigs.append(sessions[i].partial_sig_combine(sigs))
    
    if final_sigs[0] != final_sigs[1] or final_sigs[1] != final_sigs[2]:
        print(' - Combine signatures failed.')
    else:
        print(' * Combine signatures successful.')
    if schnorr_verify(msg32, combined_pk.get_xpubkey(), final_sigs[2]):
        print(' - Combined signature validation successful. Must not be possible with adaptor.')
    else:
        print(' * Combined signature is invalid now and thats correct.')

    print(' * Bob adds secret adaptor to own signature.')
    alice_id = 0
    bob_id = 1
    adaptor_sig = sessions[bob_id].partial_sig_adapt(sigs[bob_id], secret_adaptor)
    sigs_bob = sigs.copy()
    # replace Bob's partial signature with an adaptor signature
    sigs_bob[bob_id] = adaptor_sig
    # create new combined signature including the secret adaptor
    print(' * Create new combined signature.')
    combined_sig_adapt = sessions[bob_id].partial_sig_combine(sigs_bob)
    
    if schnorr_verify(msg32, combined_pk.get_xpubkey(), combined_sig_adapt):
        print(' * Combined signature validation successful.')
    else:
        print(' - Combined signature validation failed.')

    sec_adaptor_extract = sessions[alice_id].extract_secret_adaptor(sigs, combined_sig_adapt)
    if sec_adaptor_extract == secret_adaptor:
        print(' * Alice extracted the correct adaptor.')
    else:
        print(' - Alice extracted the wrong adaptor.')


if __name__ == '__main__':
    main()

