"""
Testvectors for MuSig copied from
https://github.com/guggero/bip-schnorr/blob/master/test/test-vectors-mu-sig.json

!!!
They are still using 33 Bytes Public Keys.
The Version with 32 Bytes Public Keys will create different results.
!!!
"""
import os
import json

from musig.musig33Byte import *
from musig.utils33Byte import hash_sha256, int_from_bytes, pubkey_gen, bytes_from_int

def main():
    tests = 0
    with open('test-vectors-mus-sig.json', 'r') as f:
        musig_vectors = json.load(f)
    
    for example in musig_vectors:
        print('\nTest vector #{}:'.format(tests))

        passed = True
        pub_keys = [bytes.fromhex(p) for p in example['pubKeys'] ]
        private_keys = [bytes.fromhex(p) for p in example['privKeys'] ]
        pub_key_combined = bytes.fromhex(example['pubKeyCombined'])
        msg = bytes.fromhex(example['message'])
        sessions = [bytes.fromhex(p) for p in example['sessionIds']]
        commitments = [bytes.fromhex(p) for p in example['commitments']]
        secret_keys = [bytes.fromhex(p) for p in example['secretKeys']]
        secret_nonces = [bytes.fromhex(p) for p in example['secretNonces']]
        nonce_combined = bytes.fromhex(example['nonceCombined'])
        partial_sigs = [bytes.fromhex(p) for p in example['partialSigs']]
        signature = bytes.fromhex(example['signature'])
        n_signers = len(sessions)
        
        for i in range(n_signers):
            actual_pubkey = pubkey_gen(private_keys[i])
            if actual_pubkey != pub_keys[i]:
                print(' * Failed PubKey generation test.')
                passed = False
        if passed is True:
            print(' * Passed PubKey generation.')
        else:
            passed = True
    
        actual_combined_pub_key = musig_pubkey_combine(pub_keys)    
        if actual_combined_pub_key != pub_key_combined:
            print(' * Failed combining pub keys.')
        else:
            print(' * Passed combining pub keys.')

        musig_sessions = []
        public_nonces = []
        for i in range(n_signers):
            musig_sessions.append(MuSigSession(sessions[i], len(sessions), i, private_keys[i], \
                                   actual_combined_pub_key, musig_compute_ell(pub_keys),\
                                   msg))
            if bytes_from_int(musig_sessions[i].seckey) != secret_keys[i]:
                print(' * Failed secret key calculation test. index:{}'.format(i))
                passed = False
                
            if bytes_from_int(musig_sessions[i].secnonce) != secret_nonces[i]:
                print(' * Failed secret nonce calculation test. index:{} '.format(i))
                passed = False
                
            if musig_sessions[i].nonce_commitment != commitments[i]:
                print(' * Failed nonce commitment calculation test. index:{}'.format(i))
                passed = False

            public_nonces.append(musig_sessions[i].get_public_nonce(commitments))
            
        if passed is True:
            print(' * Passed session setup test.')
        else:
            passed = True
            
        actual_part_sigs = []
        for i in range(n_signers):
            if not musig_sessions[i].set_nonce(public_nonces):
                print(' * Failed setting the public nonce. index:{}'.format(i))
                passed = False
            if not musig_sessions[i].combine_nonces():
                print(' * Failed creating a combined nonce. index:{}'.format(i))
                passed = False
            if musig_sessions[i].combined_nonce != nonce_combined:
                print(' * Failed nonce combining. index:{}'.format(i))
                passed = False
            actual_part_sigs.append(musig_sessions[i].partial_sign())
            if bytes_from_int(actual_part_sigs[i]) != partial_sigs[i]:
                print(' * Failed partial signature. index:{}'.format(i))
                passed = False
                
        if passed is True:
            print(' * Passed nonce combining test.')
        else:
            passed = True
            
        #every participant needs to receive all signature up front
        for i in range(n_signers):
            if musig_sessions[i].partial_sig_combine(actual_part_sigs,pub_keys) != signature:
                print(' * Failed creating combined signature. index:{}'.format(i))
                passed = False
                
        if passed is True:
            print(' * Passed signature combining test.')
        else:
            passed = True

              
        tests += 1


if __name__ == '__main__':
    main()
