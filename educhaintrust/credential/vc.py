# SPDX-License-Identifier: MIT
"""A deliberately local VC 2.0-style educational credential profile."""
from datetime import datetime, timezone
import uuid


def _utc_datetime(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


class VerifiableCredential:
    CONTEXT = "https://www.w3.org/ns/credentials/v2"

    @staticmethod
    def create(issuer, holder, claim, credential_type="EducationalCredential", valid_until=None):
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("issuer must be a non-empty string")
        if not isinstance(holder, str) or not holder.strip():
            raise ValueError("holder must be a non-empty string")
        if not isinstance(credential_type, str) or not credential_type.strip():
            raise ValueError("credential_type must be a non-empty string")
        if not isinstance(claim, dict) or not claim or "id" in claim:
            raise ValueError("claim must be a non-empty object without reserved key 'id'")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        credential = {"@context": [VerifiableCredential.CONTEXT],
                "id": "urn:uuid:" + str(uuid.uuid4()),
                "type": ["VerifiableCredential", credential_type],
                "issuer": issuer, "validFrom": now,
                "credentialSubject": {"id": holder, **claim}}
        if valid_until is not None:
            credential["validUntil"] = valid_until
        result = VerifiableCredential.validate(credential)
        if not result["valid"]:
            raise ValueError("; ".join(result["errors"]))
        return credential

    @staticmethod
    def validate(c):
        errors = []
        if not isinstance(c, dict):
            return {"valid": False, "errors": ["credential must be an object"]}
        context = c.get("@context")
        if not isinstance(context, list) or not context or context[0] != VerifiableCredential.CONTEXT:
            errors.append("VC 2.0 context must be the first context")
        if isinstance(context, list) and any(not isinstance(item, (str, dict)) or (isinstance(item, str) and not item.strip()) for item in context):
            errors.append("context entries must be non-empty strings or objects")
        kinds = c.get("type")
        if not isinstance(kinds, list) or "VerifiableCredential" not in kinds or not all(
                isinstance(k, str) and k for k in kinds):
            errors.append("type must be a non-empty string list including VerifiableCredential")
        try:
            ident = c.get("id")
            if not isinstance(ident, str) or not ident.startswith("urn:uuid:") or str(uuid.UUID(ident[9:])) != ident[9:]:
                raise ValueError
        except (ValueError, AttributeError):
            errors.append("id must be a canonical urn:uuid string")
        if not isinstance(c.get("issuer"), str) or not c["issuer"].strip():
            errors.append("issuer must be a non-empty string")
        if _utc_datetime(c.get("validFrom")) is None:
            errors.append("validFrom must be a timezone-aware ISO 8601 timestamp")
        if "validUntil" in c:
            if _utc_datetime(c["validUntil"]) is None:
                errors.append("validUntil must be a timezone-aware ISO 8601 timestamp")
            elif _utc_datetime(c.get("validFrom")) and _utc_datetime(c["validUntil"]) <= _utc_datetime(c["validFrom"]):
                errors.append("validUntil must be later than validFrom")
        subject = c.get("credentialSubject")
        if not isinstance(subject, dict) or len(subject) < 2 or not isinstance(subject.get("id"), str) or not subject["id"].strip():
            errors.append("credentialSubject must contain a holder id and at least one claim")
        return {"valid": not errors, "errors": errors}
