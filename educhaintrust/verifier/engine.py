# SPDX-License-Identifier: MIT
from educhaintrust.credential.vc import VerifiableCredential
from educhaintrust.credential.vc import _utc_datetime
from educhaintrust.credential.signing import Ed25519CredentialSigner
from educhaintrust.privacy.hashing import generate_hash
import hmac
from datetime import datetime, timezone

class VerificationEngine:
    def verify(self, credential, store, tx_hash, trusted_issuers=None):
        """Separate local integrity from issuer authenticity."""
        structure = VerifiableCredential.validate(credential)
        issuer = credential.get("issuer") if isinstance(credential, dict) else None
        trust = trusted_issuers.get(issuer) if isinstance(trusted_issuers, dict) and isinstance(issuer, str) else None
        if isinstance(trust, dict) and "keys" not in trust and isinstance(trust.get("verification_method"), str):
            trust = {"keys": {trust["verification_method"]: trust}}
        trusted = isinstance(trust, dict) and isinstance(trust.get("keys"), dict)
        method = credential.get("proof", {}).get("verificationMethod") if isinstance(credential, dict) and isinstance(credential.get("proof"), dict) else None
        key = trust["keys"].get(method) if trusted and isinstance(method, str) else None
        record = store.record(tx_hash)
        try:
            legacy_match = bool(record and record.get("credential_id") is None and
                                hmac.compare_digest(record["digest"], generate_hash(credential)))
        except (TypeError, ValueError, OverflowError):
            legacy_match = False
        signature = bool(isinstance(key, dict) and structure["valid"] and Ed25519CredentialSigner.verify(
            credential, key.get("public_key"), method, allow_legacy_encoding=legacy_match))
        now = datetime.now(timezone.utc)
        start = _utc_datetime(credential.get("validFrom")) if isinstance(credential, dict) else None
        end = _utc_datetime(credential.get("validUntil")) if isinstance(credential, dict) and "validUntil" in credential else None
        time_valid = bool(start and start <= now and (end is None or now < end) and
                          (not isinstance(credential, dict) or "validUntil" not in credential or end is not None))
        try:
            integrity = bool(record and hmac.compare_digest(record["digest"], generate_hash(credential)))
        except (TypeError, ValueError, OverflowError):
            integrity = False
        issuer_anchor_matched = bool(record and record.get("issuer") == issuer)
        status = store.status(tx_hash)
        return {"verified": bool(structure["valid"] and trusted and signature and time_valid and integrity and issuer_anchor_matched and status == "active"),
                "structure_valid": structure["valid"], "validation_errors": structure["errors"],
                "issuer_trusted": bool(trusted), "signature_valid": signature, "time_valid": time_valid,
                "integrity_matched": integrity, "issuer_anchor_matched": issuer_anchor_matched, "status": status}
