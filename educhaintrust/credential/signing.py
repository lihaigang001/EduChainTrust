# SPDX-License-Identifier: MIT
"""Project-level Ed25519 proof, not a W3C Data Integrity cryptosuite."""
import base64
import binascii
from copy import deepcopy
from datetime import datetime, timezone
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from educhaintrust.privacy.canonical import canonicalize
from .vc import _utc_datetime

PROOF_TYPE = "EduChainTrustEd25519Signature2026"
PROOF_PURPOSE = "assertionMethod"
DEFAULT_METHOD = "urn:educhaintrust:key:issuer"
PROOF_FIELDS = {"type", "created", "verificationMethod", "proofPurpose", "proofValue"}


def _b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64u(value, *, allow_noncanonical=False):
    if not isinstance(value, str) or not value or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in value):
        raise ValueError("invalid base64url proof")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if len(raw) != 64 or (not allow_noncanonical and _b64u(raw) != value):
        raise ValueError("invalid or noncanonical Ed25519 proof")
    return raw


class Ed25519CredentialSigner:
    @staticmethod
    def generate_keypair():
        private = Ed25519PrivateKey.generate()
        return private, private.public_key()

    @staticmethod
    def sign(credential, private_key, verification_method=DEFAULT_METHOD):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be Ed25519PrivateKey")
        if not isinstance(credential, dict) or "proof" in credential:
            raise ValueError("credential must be an unsigned object")
        if not isinstance(verification_method, str) or not verification_method:
            raise ValueError("verification_method must be non-empty")
        signed = deepcopy(credential)
        signed["proof"] = {
            "type": PROOF_TYPE,
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "verificationMethod": verification_method,
            "proofPurpose": PROOF_PURPOSE,
        }
        signature = private_key.sign(canonicalize(signed))
        signed["proof"]["proofValue"] = _b64u(signature)
        return signed

    @staticmethod
    def verify(credential, public_key, verification_method=DEFAULT_METHOD, *, allow_legacy_encoding=False):
        if not isinstance(credential, dict) or not isinstance(public_key, Ed25519PublicKey):
            return False
        proof = credential.get("proof")
        if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS:
            return False
        if proof.get("type") != PROOF_TYPE or proof.get("proofPurpose") != PROOF_PURPOSE:
            return False
        if proof.get("verificationMethod") != verification_method or _utc_datetime(proof.get("created")) is None:
            return False
        unsigned_proof_value = deepcopy(credential)
        unsigned_proof_value["proof"].pop("proofValue")
        try:
            signature = _unb64u(proof["proofValue"], allow_noncanonical=allow_legacy_encoding)
            public_key.verify(signature, canonicalize(unsigned_proof_value))
            return True
        except (InvalidSignature, ValueError, TypeError, OverflowError, binascii.Error):
            return False
