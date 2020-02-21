"""
Testvectors for MuSig copied from
https://github.com/guggero/bip-schnorr/blob/master/test/test-vectors-mu-sig.json
"""

import csv

from musig import *
from musig.utils import hash_sha256, int_from_bytes, pubkey_gen, bytes_from_int

def main():
    tests = 0
    with open('musig_vectors.csv', 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=';')
        reader.__next__()
        i = 1
        
        for row in reader:
            (session_id_0, session_id_1, secret_key_0, secret_key_1, msg, pubkey_0, pubkey_1, combined_pubkey, \
             nonce_commitment_0, nonce_commitment_1, public_nonce_0, public_nonce_1, combined_nonce, partial_sig_0 \
             ,partial_sig_1, final_sig) = row
            print('\nTest vector #{}:'.format(i))
            i += 1
            
            msg = bytes.fromhex(msg)
            session_id_0 = bytes.fromhex(session_id_0)
            session_id_1 = bytes.fromhex(session_id_1)
            secret_key_0 = bytes.fromhex(secret_key_0)
            secret_key_1 = bytes.fromhex(secret_key_1)
            pubkey_0 = bytes.fromhex(pubkey_0)
            pubkey_1 = bytes.fromhex(pubkey_1)
            combined_pubkey = bytes.fromhex(combined_pubkey)
            nonce_commitment_0 = bytes.fromhex(nonce_commitment_0)
            nonce_commitment_1 = bytes.fromhex(nonce_commitment_1)
            public_nonce_0 = bytes.fromhex(public_nonce_0)
            public_nonce_1 = bytes.fromhex(public_nonce_1)
            combined_nonce = bytes.fromhex(combined_nonce)
            partial_sig_0 = bytes.fromhex(partial_sig_0)
            partial_sig_1 = bytes.fromhex(partial_sig_1)
            final_sig = bytes.fromhex(final_sig)

            pubkey_actual = list()
            pubkey_actual.append(pubkey_gen(secret_key_0))
            pubkey_actual.append(pubkey_gen(secret_key_1))
            if pubkey_actual[0] == pubkey_0 and pubkey_actual[1] == pubkey_1:
                all_passed = True
            else:
                print(' * Failed key generation.')
                all_passed = False
                      
            combined_pk = CombinedPubkey(pubkey_actual)
            combined_pk_actual = combined_pk.get_key()
            pre_session_actual = combined_pk.get_pre_session()
            if combined_pk_actual != combined_pubkey:
                print(' * Failed pubkey aggregation.')
                all_passed = False

            sessions = list()
            nonce_commitments_actual = list()
            sessions.append(MuSigSession(session_id_0, 2, 0, secret_key_0, combined_pk_actual, pre_session_actual, msg))
            sessions.append(MuSigSession(session_id_1, 2, 1, secret_key_1, combined_pk_actual, pre_session_actual, msg))
            nonce_commitments_actual.append(sessions[0].get_nonce_commitment())
            nonce_commitments_actual.append(sessions[1].get_nonce_commitment())
            if nonce_commitments_actual[0] != nonce_commitment_0 or nonce_commitments_actual[1] != nonce_commitment_1:
                print(' * Failed nonce commitment creation.')               
                all_passed = False

            nonces_actual = list()
            nonces_actual.append(sessions[0].get_public_nonce(nonce_commitments_actual))
            nonces_actual.append(sessions[1].get_public_nonce(nonce_commitments_actual))
            if nonces_actual[0] != public_nonce_0 or nonces_actual[1] != public_nonce_1:
                print(' * Failed public nonce creation.')
                all_passed = False

            sessions[0].set_nonce(nonces_actual)
            sessions[1].set_nonce(nonces_actual)
            sessions[0].combine_nonces()
            sessions[1].combine_nonces()
            partial_sigs_actual = list()
            partial_sigs_actual.append(sessions[0].partial_sign())
            partial_sigs_actual.append(sessions[1].partial_sign())
            if partial_sigs_actual[0] != partial_sig_0 or partial_sigs_actual[1] != partial_sig_1:
                print(' * Failed partial_sig creation.')
                all_passed = False
            
            final_sig_actual = sessions[0].partial_sig_combine(partial_sigs_actual)
            if final_sig_actual != final_sig:
                print(' * Failed combine final signature.')
                all_passed = False
            if all_passed:
                print(' * Passed all tests.')
            
          

if __name__ == '__main__':
    main()
