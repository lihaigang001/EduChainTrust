# SPDX-License-Identifier: MIT
"""Authenticated local research API, with server-held issuer signing keys."""
from contextlib import asynccontextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import Depends, FastAPI, Header, HTTPException
from starlette.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from educhaintrust.analytics.evidence import EvidenceScore
from educhaintrust.blockchain.sqlitechain import SQLiteEvidenceStore
from educhaintrust.credential.signing import Ed25519CredentialSigner, _unb64u
from educhaintrust.credential.vc import VerifiableCredential
from educhaintrust.identity.did import DIDManager
from educhaintrust.privacy.hashing import generate_hash
from educhaintrust.privacy.canonical import MAX_NESTING
from educhaintrust.verifier.engine import VerificationEngine

MAX_BODY_BYTES = 256 * 1024


def _exceeds_json_depth(body):
    depth = 0
    quoted = escaped = False
    for char in body:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (123, 91):
            depth += 1
            if depth > MAX_NESTING:
                return True
        elif char in (125, 93):
            depth -= 1
    return False


class RequestBoundsMiddleware:
    """Bound a complete local JSON request before FastAPI parses it."""

    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.application(scope, receive, send)
        headers = dict(scope["headers"])
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = 0
        if declared > MAX_BODY_BYTES:
            return await JSONResponse({"detail": "Request body exceeds limit"}, status_code=413)(scope, receive, send)
        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return await JSONResponse({"detail": "Request body exceeds limit"}, status_code=413)(scope, receive, send)
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        if _exceeds_json_depth(body):
            return await JSONResponse({"detail": "JSON nesting limit exceeded"}, status_code=422)(scope, receive, send)
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.application(scope, replay, send)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class IdentityRequest(StrictModel):
    entity_type: str = Field(min_length=1)
    name: str = Field(min_length=1)
    institution: str = Field(min_length=1)


class CredentialRequest(StrictModel):
    issuer: str = Field(min_length=1)
    holder: str = Field(min_length=1)
    claim: dict[str, Any]
    valid_until: str | None = None


class CredentialBody(StrictModel):
    credential: dict[str, Any]


class VerifyRequest(CredentialBody):
    tx_hash: str = Field(min_length=1)


class TxRequest(StrictModel):
    tx_hash: str = Field(min_length=1)


class ScoreRequest(StrictModel):
    completion: float = Field(ge=0, le=1, allow_inf_nan=False)
    assessment: float = Field(ge=0, le=1, allow_inf_nan=False)
    time: float = Field(ge=0, le=1, allow_inf_nan=False)
    interaction: float = Field(ge=0, le=1, allow_inf_nan=False)


def _read_local_file(path, label, private=False):
    """Inspect and read through checked directory and file descriptors on POSIX."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    trusted_owners = {0, os.geteuid()} if os.name == "posix" else set()
    configured_uid = os.getenv("EDUCHAINTRUST_TRUSTED_CONFIG_UID")
    if os.name == "posix" and configured_uid is not None:
        if not configured_uid.isascii() or not configured_uid.isdecimal():
            raise RuntimeError("EDUCHAINTRUST_TRUSTED_CONFIG_UID must be a numeric UID")
        trusted_owners.add(int(configured_uid))
    directory_fd = None
    try:
        if os.name == "posix":
            path = Path(path).absolute()
            directory_flags = flags | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_fd = os.open(os.sep, directory_flags)
            for part in path.parts[1:-1]:
                child = os.open(part, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child
                info = os.fstat(directory_fd)
                trusted_sticky = bool(info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
                if info.st_uid not in trusted_owners:
                    raise RuntimeError(f"{label} parent directory has an untrusted owner")
                if info.st_mode & 0o022 and not trusted_sticky:
                    raise RuntimeError(f"{label} must use protected parent directories")
            fd = os.open(path.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        else:
            fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} must point to a provisioned regular file") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"{label} must point to a provisioned regular file")
        if os.name == "posix" and info.st_uid not in trusted_owners:
            raise RuntimeError(f"{label} file has an untrusted owner")
        if private and os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError(f"{label} must not be group/world accessible (use chmod 600)")
        stream = os.fdopen(fd, "rb")
        fd = None
        with stream:
            return stream.read()
    finally:
        if fd is not None:
            os.close(fd)


def _read_config(path):
    """Load local secrets through checked descriptors on POSIX."""
    file = Path(path).absolute()
    config = json.loads(_read_local_file(file, "EDUCHAINTRUST_CONFIG", private=True).decode("utf-8"))
    issuers = {}
    for issuer, record in config.get("issuers", {}).items():
        if not isinstance(issuer, str) or not issuer or not isinstance(record, dict):
            raise RuntimeError("invalid issuer configuration")
        # Accept the v1.3 single-key file to keep local installations usable.
        records = record.get("keys") if "keys" in record else {record.get("verification_method"): record}
        if not isinstance(records, dict):
            raise RuntimeError("invalid issuer key registry")
        keys = {}
        for method, key_record in records.items():
            if not isinstance(method, str) or not method or not isinstance(key_record, dict):
                raise RuntimeError("invalid issuer key record")
            if ("private_key_file" in key_record) == ("public_key_file" in key_record):
                raise RuntimeError("each key requires exactly one PEM file")
            filename = key_record.get("private_key_file", key_record.get("public_key_file"))
            if not isinstance(filename, str) or not filename:
                raise RuntimeError("invalid key path")
            key_path = (file.parent / filename).absolute()
            if "private_key_file" in key_record:
                private = serialization.load_pem_private_key(
                    _read_local_file(key_path, "issuer private key", private=True), password=None)
                if not isinstance(private, Ed25519PrivateKey):
                    raise RuntimeError("issuer key must be Ed25519")
                keys[method] = {"private_key": private, "public_key": private.public_key()}
            else:
                public = serialization.load_pem_public_key(_read_local_file(key_path, "issuer public key"))
                if not isinstance(public, Ed25519PublicKey):
                    raise RuntimeError("issuer key must be Ed25519")
                keys[method] = {"public_key": public}
        issuers[issuer] = {"active_method": record.get("active_method", record.get("verification_method")),
                           "keys": keys}
    return config.get("tokens", {}), issuers


def _check_config(tokens, issuers):
    if not isinstance(tokens, dict) or not tokens or not isinstance(issuers, dict) or not issuers:
        raise RuntimeError("at least one API token and trusted issuer are required")
    for token, principal in tokens.items():
        if not isinstance(token, str) or len(token) < 24 or not isinstance(principal, dict):
            raise RuntimeError("invalid API token configuration")
        if principal.get("role") not in {"issuer", "verifier", "admin"}:
            raise RuntimeError("invalid API role")
        if principal["role"] == "issuer" and principal.get("issuer") not in issuers:
            raise RuntimeError("issuer token must name a trusted issuer")
    normalized = {}
    for issuer, record in issuers.items():
        if not isinstance(issuer, str) or not issuer or not isinstance(record, dict):
            raise RuntimeError("invalid trusted issuer")
        if "keys" not in record:
            method = record.get("verification_method")
            record = {"active_method": method, "keys": {method: {k: record[k] for k in ("public_key", "private_key") if k in record}}}
        keys = record.get("keys")
        active = record.get("active_method")
        if not isinstance(keys, dict) or not keys or not isinstance(active, str) or active not in keys:
            raise RuntimeError("issuer requires a registered active method")
        for method, key in keys.items():
            if not isinstance(method, str) or not method or not isinstance(key, dict) or not isinstance(key.get("public_key"), Ed25519PublicKey):
                raise RuntimeError("invalid trusted issuer key")
            if "private_key" in key and (not isinstance(key["private_key"], Ed25519PrivateKey) or
                    key["private_key"].public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    != key["public_key"].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)):
                raise RuntimeError("issuer private/public key mismatch")
        normalized[issuer] = {"active_method": active, "keys": keys}
    return normalized


def create_app(db_path=None, api_tokens=None, issuer_keys=None):
    @asynccontextmanager
    async def lifespan(application):
        tokens, issuers = (api_tokens, issuer_keys) if api_tokens is not None and issuer_keys is not None else _read_config(
            os.getenv("EDUCHAINTRUST_CONFIG", ""))
        issuers = _check_config(tokens, issuers)
        application.state.tokens = tokens
        application.state.issuers = issuers
        application.state.store = SQLiteEvidenceStore(db_path or os.getenv("EDUCHAINTRUST_DB", "educhaintrust_evidence.sqlite3"))
        yield
        application.state.store.close()

    application = FastAPI(title="EduChainTrust research API", version="1.12.0", lifespan=lifespan)
    application.add_middleware(RequestBoundsMiddleware)

    def principal(x_api_key: str | None = Header(default=None)):
        if not x_api_key:
            raise HTTPException(status_code=401, detail="API key required")
        for token, candidate in application.state.tokens.items():
            if secrets.compare_digest(x_api_key.encode("utf-8"), token.encode("utf-8")):
                return candidate
        raise HTTPException(status_code=401, detail="Invalid API key")

    def require_issuer(user=Depends(principal)):
        if user["role"] != "issuer":
            raise HTTPException(status_code=403, detail="Issuer role required")
        return user

    def store():
        return application.state.store

    @application.get("/")
    def index():
        return {"software": "EduChainTrust", "version": "1.12.0", "scope": "research"}

    @application.get("/health")
    def health():
        return {"status": "ok"}

    @application.post("/v1/identities")
    def identity(q: IdentityRequest, user=Depends(require_issuer)):
        if q.institution != user["issuer"]:
            raise HTTPException(403, "Issuer cannot create another institution's identity")
        return DIDManager().create_identity(q.entity_type, q.name, q.institution)

    @application.post("/v1/credentials")
    def credential(q: CredentialRequest, user=Depends(require_issuer)):
        if q.issuer != user["issuer"]:
            raise HTTPException(403, "Issuer mismatch")
        issuer = application.state.issuers[q.issuer]
        method = issuer["active_method"]
        key = issuer["keys"][method]
        if "private_key" not in key:
            raise HTTPException(403, "Issuer signing key unavailable")
        try:
            unsigned = VerifiableCredential.create(q.issuer, q.holder, q.claim, valid_until=q.valid_until)
            result = VerifiableCredential.validate(unsigned)
            if not result["valid"]:
                raise ValueError("; ".join(result["errors"]))
            signed = Ed25519CredentialSigner.sign(unsigned, key["private_key"], method)
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"credential": signed, "validation": result}

    @application.post("/v1/evidence/anchor")
    def anchor(q: CredentialBody, user=Depends(require_issuer), evidence=Depends(store)):
        credential = q.credential
        if credential.get("issuer") != user["issuer"]:
            raise HTTPException(403, "Issuer mismatch")
        result = VerifiableCredential.validate(credential)
        proof = credential.get("proof")
        method = proof.get("verificationMethod") if isinstance(proof, dict) else None
        keys = application.state.issuers[user["issuer"]]["keys"]
        key = keys.get(method) if isinstance(method, str) else None
        if not result["valid"] or not key or not Ed25519CredentialSigner.verify(
                credential, key["public_key"], method):
            raise HTTPException(422, "Invalid credential structure or issuer signature")
        if method != application.state.issuers[user["issuer"]]["active_method"]:
            raise HTTPException(409, "Only the active signing method may create new evidence")
        digest = generate_hash(credential)
        # Earlier releases accepted equivalent noncanonical final base64url digits.
        # Probe all equivalent encodings to locate a pre-upgrade record, atomically.
        signature = proof["proofValue"]
        raw = _unb64u(signature)
        variants = []
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for char in alphabet:
            candidate = signature[:-1] + char
            try:
                if _unb64u(candidate, allow_noncanonical=True) == raw:
                    old = deepcopy(credential)
                    old["proof"]["proofValue"] = candidate
                    variants.append(generate_hash(old))
            except ValueError:
                pass
        try:
            tx_hash = evidence.anchor(digest, user["issuer"], credential_id=credential["id"], legacy_digests=variants)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"tx_hash": tx_hash, "sha256": digest}

    @application.post("/v1/credentials/verify")
    def verify(q: VerifyRequest, user=Depends(principal), evidence=Depends(store)):
        if evidence.status(q.tx_hash) == "unknown":
            raise HTTPException(404, "Evidence transaction not found")
        return VerificationEngine().verify(q.credential, evidence, q.tx_hash, application.state.issuers)

    @application.post("/v1/evidence/revoke")
    def revoke(q: TxRequest, user=Depends(principal), evidence=Depends(store)):
        record = evidence.record(q.tx_hash)
        if record is None:
            raise HTTPException(404, "Evidence transaction not found")
        if user["role"] != "admin" and not (user["role"] == "issuer" and user["issuer"] == record["issuer"]):
            raise HTTPException(403, "Revocation requires owning issuer or administrator")
        if not evidence.revoke(q.tx_hash, user.get("issuer", user["role"])):
            raise HTTPException(409, "Already revoked")
        return {"tx_hash": q.tx_hash, "status": "revoked"}

    @application.get("/v1/evidence/{tx_hash}/status")
    def status(tx_hash: str, user=Depends(principal), evidence=Depends(store)):
        return {"tx_hash": tx_hash, "status": evidence.status(tx_hash)}

    @application.post("/v1/analytics/evidence-score")
    def score(q: ScoreRequest, user=Depends(principal)):
        return {"score": EvidenceScore.calculate(q.completion, q.assessment, q.time, q.interaction)}

    return application


app = create_app()
