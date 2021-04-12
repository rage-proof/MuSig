#!/usr/bin/env python3
"""
test vectors for schnorr signatures copied from:
https://github.com/sipa/bips/tree/bip-schnorr/bip-schnorr
"""
from pymusig import schnorr_sign, schnorr_verify, schnorr_batch_verify
from pymusig.utils import pubkey_gen
import csv


def test_vectors():
    all_passed = True
    with open('schnorr-vectors.csv', newline='') as csvfile:
        reader = csv.reader(csvfile)
        reader.__next__()
        sigs = []
        pubs = []
        msgs = []
        for row in reader:
            (index, seckey, pubkey, msg, sig, result, comment) = row
            pubkey = bytes.fromhex(pubkey)
            msg = bytes.fromhex(msg)
            sig = bytes.fromhex(sig)
            result = result == 'TRUE'
            print('\nTest vector #%-3i: ' % int(index))
            if seckey != '':
                seckey = bytes.fromhex(seckey)
                pubkey_actual = pubkey_gen(seckey)
                if pubkey != pubkey_actual:
                    print(' * Failed key generation.')
                    print('   Expected key:', pubkey.hex().upper())
                    print('     Actual key:', pubkey_actual.hex().upper())
                sig_actual = schnorr_sign(msg, seckey)
                if sig == sig_actual:
                    print(' * Passed signing test.')
                else:
                    print(' * Failed signing test.')
                    print('   Expected signature:', sig.hex().upper())
                    print('     Actual signature:', sig_actual.hex().upper())
                    all_passed = False
            result_actual = schnorr_verify(msg, pubkey, sig)        
            if result == result_actual:
                print(' * Passed verification test.')
            else:
                print(' * Failed verification test.')
                print('   Expected verification result:', result)
                print('     Actual verification result:', result_actual)
                if comment:
                    print('   Comment:', comment)
                all_passed = False
            if result == True:
                pubs.append(pubkey)
                sigs.append(sig)
                msgs.append(msg)
    results_all = schnorr_batch_verify(msgs, pubs, sigs)
    if results_all == True:
        print('\n****Batch verification test passed.****')
    else:
        print('\n****Batch verification test failed.****')
        all_passed = False
    if all_passed:
        print('\nAll test vectors passed.')
    else:
        print('\nSome test vectors failed.')
    return all_passed

if __name__ == '__main__':
    test_vectors()
