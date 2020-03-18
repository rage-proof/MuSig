# MuSig multisignatures for Python

This is a Python implementation of the [MuSig](https://eprint.iacr.org/2018/068) multisignature scheme, proposed by several Bitcoin contributors.
It's aiming to create, in combination with Schnorr signatures, a scheme in that the participants can securly and trustless create aggregated multisignatures.
Changes that will happen in the future to the draft or the reference implementation will be taken over.

The schnorr specification is defined in BIP-340 and the code and test vectors are used from [here](https://github.com/bitcoin/bips/tree/master/bip-0340).

The MuSig code is following the implementation for libsecp256k1 as well as the test vectors are extracted from that [implementation](https://github.com/jonasnick/secp256k1-zkp).

**Note: Use this package only for testing and learning, but not for live use cases.**
**Don't risk funds, probably errors exist.**


## Installing
Python 3 is required.

**Github:**

```sh
git clone git://github.com/rage-proof/MuSig.git
cd MuSig
python3 setup.py install
```

**or PyPI:**

```sh
pip3 install pymusig
```

## Usage


```Python

# multiple signer can create aggregated signature on a combined public key
# signer Alice and Bob have todo the same steps individually with params

#Alice:
import os
from pymusig import CombinedPubkey, MuSigSession, schnorr_verify
N_SIGNERS = 2
i_alice = 0

#create session
#WARNING:every session needs a new random session ID, otherwise a malicious signer can extract the secret key
session_id_alice = os.urandom(32)

#set the message and list of pubkeys
pubkeys = [pubkey_alice, pubkey_bob]
msg = sha256(b'Some Message')

#create combined pubkey
combined_pk = CombinedPubkey(pubkeys)

#create session
session_alice = MuSigSession(session_id_alice, N_SIGNERS, i_alice, seckey_alice, combined_pk.get_key(), combined_pk.get_pre_session(), msg)

#Three rounds of communication are necessary
#1. Round: receive and exchange Nonce commitments
nonce_commitment_alice = session_alice.get_nonce_commitment()
nonce_commitments = [nonce_commitment_alice, nonce_commitment_bob]

#2. Round: receive and exchange Nonces
nonce_alice = session_alice.get_public_nonce(nonce_commitments)
nonces = [nonce_alice, nonce_bob]
if session_alice.set_nonce(nonces)

#create combined Nonce and partial signature for Alice
if session_alice.combine_nonces()
signature_alice = session_alice.partial_sign()

#3. Round: validate partial signatures and create a combines signature
if session_alice.partial_sig_verify(signature_bob, pubkey_bob, i_bob)
sigs = [signature_alice, signature_bob]
final_sig = session_alice(partial_sig_combine(sigs))

#verify the schnorr signature
if schnorr_verify(msg, combined_pk.get_key(), final_sig)

```
A detailed example of a signature with three parties is stored in `/tests/test_musig.py`
