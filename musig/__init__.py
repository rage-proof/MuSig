"""
MuSig Implemenation for Python

This is an implemation of the muSig Proposl for schnorr multisignatures.
Paper: https://eprint.iacr.org/2018/068

Reference C implementation:
https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/musig

Javascript implementation:
https://github.com/guggero/bip-schnorr
"""
from .musig import CombinedPubkey, MuSigSession

from .schnorr import schnorr_sign, schnorr_verify, schnorr_batch_verify

__version__ = '0.1'
