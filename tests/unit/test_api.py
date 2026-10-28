from copy import deepcopy
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
import os
import stat
import subprocess
import sys
from cryptography.hazmat.primitives import serialization

import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from tools import generate_local_config
from api.main import MAX_BODY_BYTES, create_app
from educhaintrust.credential.signing import Ed25519CredentialSigner
from educhaintrust.credential.vc import VerifiableCredential


ISSUER = "i" * 32
OTHER_ISSUER = "o" * 32
VERIFIER = "v" * 32
ADMIN = "a" * 32


@pytest.fixture
def configured(tmp_path):
    private, public = Ed25519CredentialSigner.generate_keypair()
    other_private, other_public = Ed25519CredentialSigner.generate_keypair()
    tokens = {ISSUER: {"role": "issuer", "issuer": "U"},
              OTHER_ISSUER: {"role": "issuer", "issuer": "Other-U"},
              VERIFIER: {"role": "verifier"}, ADMIN: {"role": "admin"}}
    issuers = {"U": {"private_key": private, "public_key": public, "verification_method": "urn:educhaintrust:u:key-1"},
               "Other-U": {"private_key": other_private, "public_key": other_public,
                           "verification_method": "urn:educhaintrust:other:key-1"}}
    return create_app(tmp_path / "api.sqlite3", tokens, issuers)


def hdr(token):
    return {"X-API-Key": token}


def issue(client):
    response = client.post("/v1/credentials", headers=hdr(ISSUER),
                           json={"issuer": "U", "holder": "did:edu:alice", "claim": {"course": "AI"}})
    assert response.status_code == 200, response.text
    return response.json()["credential"]


def test_authenticated_signed_lifecycle(configured):
    with TestClient(configured) as client:
        identity = client.post("/v1/identities", headers=hdr(ISSUER),
                               json={"entity_type": "student", "name": "Alice", "institution": "U"})
        assert identity.status_code == 200
        credential = issue(client)
        assert "proofValue" in credential["proof"]
        tx = client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": credential}).json()["tx_hash"]
        assert client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": credential}).status_code == 409
        verified = client.post("/v1/credentials/verify", headers=hdr(VERIFIER),
                               json={"credential": credential, "tx_hash": tx}).json()
        assert verified["verified"] and verified["signature_valid"] and verified["issuer_anchor_matched"]
        assert client.post("/v1/evidence/revoke", headers=hdr(VERIFIER), json={"tx_hash": tx}).status_code == 403
        assert client.post("/v1/evidence/revoke", headers=hdr(OTHER_ISSUER), json={"tx_hash": tx}).status_code == 403
        assert client.post("/v1/evidence/revoke", headers=hdr(ISSUER), json={"tx_hash": tx}).status_code == 200
        revoked = client.post("/v1/credentials/verify", headers=hdr(VERIFIER),
                              json={"credential": credential, "tx_hash": tx}).json()
        assert not revoked["verified"] and revoked["integrity_matched"] and revoked["status"] == "revoked"
        assert client.post("/v1/evidence/revoke", headers=hdr(ISSUER), json={"tx_hash": tx}).status_code == 409


def test_no_anonymous_writes_or_reads(configured):
    with TestClient(configured) as client:
        assert client.post("/v1/credentials", json={"issuer": "U", "holder": "Alice", "claim": {"course": "AI"}}).status_code == 401
        assert client.post("/v1/evidence/anchor", json={"credential": {"issuer": "U"}}).status_code == 401
        assert client.get("/v1/evidence/sqlite:arbitrary/status").status_code == 401
        assert client.post("/v1/evidence/revoke", json={"tx_hash": "sqlite:arbitrary"}).status_code == 401
        assert client.get("/health").status_code == 200


def test_issuer_cannot_impersonate_another(configured):
    with TestClient(configured) as client:
        response = client.post("/v1/credentials", headers=hdr(ISSUER),
                               json={"issuer": "Other-U", "holder": "Alice", "claim": {"course": "AI"}})
        assert response.status_code == 403
        credential = issue(client)
        assert client.post("/v1/evidence/anchor", headers=hdr(OTHER_ISSUER), json={"credential": credential}).status_code == 403


def test_unsigned_and_proof_tampered_cannot_anchor(configured):
    with TestClient(configured) as client:
        unsigned = VerifiableCredential.create("U", "did:edu:alice", {"degree": "PhD"})
        assert client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": unsigned}).status_code == 422
        credential = issue(client)
        changed = deepcopy(credential)
        changed["proof"]["verificationMethod"] = "urn:attacker:key"
        assert client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": changed}).status_code == 422


def test_bad_claim_and_malformed_requests(configured):
    with TestClient(configured) as client:
        assert client.post("/v1/credentials", headers=hdr(ISSUER),
                           json={"issuer": "U", "holder": "Alice", "claim": {"id": "attacker"}}).status_code == 422
        assert client.post("/v1/evidence/anchor", headers=hdr(ISSUER),
                           json={"credential": {"issuer": "U", "@context": []}}).status_code == 422
        assert client.post("/v1/analytics/evidence-score", headers=hdr(VERIFIER),
                           json={"completion": 2, "assessment": .5, "time": .5, "interaction": .5}).status_code == 422


def test_json_depth_and_body_size_are_bounded(configured):
    nested = {}
    for _ in range(70):
        nested = {"item": nested}
    with TestClient(configured) as client:
        payload = {"issuer": "U", "holder": "Alice", "claim": nested}
        response = client.post("/v1/credentials", headers=hdr(ISSUER), json=payload)
        assert response.status_code == 422 and "nesting limit" in response.text
        response = client.post("/v1/credentials",
                               content=json.dumps({"issuer": "U", "holder": "Alice",
                                                   "claim": {"text": "a" * MAX_BODY_BYTES}}),
                               headers={**hdr(ISSUER), "Content-Type": "application/json"})
        assert response.status_code == 413
        # Brackets in JSON string values do not count toward structural depth.
        response = client.post("/v1/credentials", headers=hdr(ISSUER),
                               json={"issuer": "U", "holder": "Alice",
                                     "claim": {"text": "[" * 100 + "\\\"{"}})
        assert response.status_code == 200


def test_unknown_tx_and_admin_revoke(configured):
    with TestClient(configured) as client:
        credential = issue(client)
        assert client.post("/v1/credentials/verify", headers=hdr(VERIFIER),
                           json={"credential": credential, "tx_hash": "sqlite:missing"}).status_code == 404
        tx = client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": credential}).json()["tx_hash"]
        assert client.post("/v1/evidence/revoke", headers=hdr(ADMIN), json={"tx_hash": tx}).status_code == 200


def test_missing_configuration_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("EDUCHAINTRUST_CONFIG", raising=False)
    with pytest.raises(RuntimeError, match="EDUCHAINTRUST_CONFIG"):
        with TestClient(create_app(tmp_path / "missing.sqlite3")):
            pass


def test_provisioned_file_config_and_authenticated_issue(tmp_path, monkeypatch):
    generator = Path(__file__).resolve().parents[2] / "tools" / "generate_local_config.py"
    directory = tmp_path / "local-config"
    subprocess.run([sys.executable, str(generator), "--out-dir", str(directory), "--issuer", "U"],
                   check=True, capture_output=True, text=True)
    config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
    token = next(k for k, v in config["tokens"].items() if v["role"] == "issuer")
    monkeypatch.setenv("EDUCHAINTRUST_CONFIG", str(directory / "config.json"))
    with TestClient(create_app(tmp_path / "configured.sqlite3")) as client:
        response = client.post("/v1/credentials", headers=hdr(token),
                               json={"issuer": "U", "holder": "did:edu:alice", "claim": {"course": "AI"}})
        assert response.status_code == 200 and "proofValue" in response.json()["credential"]["proof"]


def test_api_optional_expiration(configured):
    future = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    with TestClient(configured) as client:
        payload = {"issuer": "U", "holder": "did:edu:alice", "claim": {"course": "AI"}}
        response = client.post("/v1/credentials", headers=hdr(ISSUER), json={**payload, "valid_until": future})
        assert response.status_code == 200
        c = response.json()["credential"]
        assert c["validUntil"] == future
        tx = client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": c}).json()["tx_hash"]
        assert client.post("/v1/credentials/verify", headers=hdr(VERIFIER), json={"credential": c, "tx_hash": tx}).json()["verified"]
        for bad in (past, "not-a-date"):
            assert client.post("/v1/credentials", headers=hdr(ISSUER),
                               json={**payload, "valid_until": bad}).status_code == 422


def test_key_rotation_preserves_old_signature_then_distrusts_it(tmp_path):
    old_private, old_public = Ed25519CredentialSigner.generate_keypair()
    new_private, new_public = Ed25519CredentialSigner.generate_keypair()
    old_method, new_method = "urn:educhaintrust:u:key-old", "urn:educhaintrust:u:key-new"
    keys = {old_method: {"public_key": old_public},
            new_method: {"private_key": new_private, "public_key": new_public}}
    old_credential = Ed25519CredentialSigner.sign(
        VerifiableCredential.create("U", "did:edu:alice", {"course": "Old"}), old_private, old_method)
    db = tmp_path / "rotation.sqlite3"
    tokens = {ISSUER: {"role": "issuer", "issuer": "U"}}
    with TestClient(create_app(db, tokens, {"U": {"active_method": old_method,
                               "keys": {old_method: {"private_key": old_private, "public_key": old_public}}}})) as client:
        old_tx = client.post("/v1/evidence/anchor", headers=hdr(ISSUER),
                             json={"credential": old_credential}).json()["tx_hash"]
    trust = {"U": {"active_method": new_method, "keys": keys}}
    with TestClient(create_app(db, tokens, trust)) as client:
        assert client.post("/v1/credentials/verify", headers=hdr(ISSUER),
                           json={"credential": old_credential, "tx_hash": old_tx}).json()["verified"]
        late_old = Ed25519CredentialSigner.sign(
            VerifiableCredential.create("U", "did:edu:bob", {"course": "Late"}), old_private, old_method)
        denied = client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": late_old})
        assert denied.status_code == 409 and "active signing method" in denied.text
        new_credential = issue(client)
        assert new_credential["proof"]["verificationMethod"] == new_method
        new_tx = client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": new_credential}).json()["tx_hash"]
        assert client.post("/v1/credentials/verify", headers=hdr(ISSUER),
                           json={"credential": new_credential, "tx_hash": new_tx}).json()["verified"]
    with TestClient(create_app(db, {ISSUER: {"role": "issuer", "issuer": "U"}},
                               {"U": {"active_method": new_method, "keys": {new_method: keys[new_method]}}})) as client:
        outcome = client.post("/v1/credentials/verify", headers=hdr(ISSUER),
                              json={"credential": old_credential, "tx_hash": old_tx}).json()
        assert outcome["issuer_trusted"] and not outcome["signature_valid"] and not outcome["verified"]
        assert client.post("/v1/credentials/verify", headers=hdr(ISSUER),
                           json={"credential": new_credential, "tx_hash": new_tx}).json()["verified"]


@pytest.mark.parametrize("bad_issuer", [[], {}, ["U"]])
def test_verify_malformed_unhashable_issuer_is_negative(configured, bad_issuer):
    with TestClient(configured) as client:
        credential = issue(client)
        tx = client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": credential}).json()["tx_hash"]
        malformed = {**credential, "issuer": bad_issuer}
        response = client.post("/v1/credentials/verify", headers=hdr(VERIFIER),
                               json={"credential": malformed, "tx_hash": tx})
        assert response.status_code == 200
        result = response.json()
        assert not result["verified"] and not result["structure_valid"] and not result["issuer_trusted"]


def test_invalid_rotation_registry_fails_closed(tmp_path):
    _, public = Ed25519CredentialSigner.generate_keypair()
    with pytest.raises(RuntimeError, match="registered active method"):
        with TestClient(create_app(tmp_path / "bad.sqlite3", {ISSUER: {"role": "issuer", "issuer": "U"}},
                                   {"U": {"active_method": "unknown", "keys": {"known": {"public_key": public}}}})):
            pass


def test_restricted_container_context(tmp_path):
    root = Path(__file__).resolve().parents[2]
    ignore = (root / ".dockerignore").read_text()
    dockerfile = (root / "docker/Dockerfile").read_text()
    assert ignore.startswith("*\n") and "!local-config" not in ignore
    assert "COPY . ." not in dockerfile and "COPY educhaintrust/" in dockerfile


def test_file_registry_retains_public_only_old_key(tmp_path, monkeypatch):
    config_dir = tmp_path / "keys"
    config_dir.mkdir()
    old_private, old_public = Ed25519CredentialSigner.generate_keypair()
    new_private, _ = Ed25519CredentialSigner.generate_keypair()
    old_method, new_method = "urn:educhaintrust:u:old", "urn:educhaintrust:u:new"
    (config_dir / "old.pub").write_bytes(old_public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    (config_dir / "old.pem").write_bytes(old_private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (config_dir / "new.pem").write_bytes(new_private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (config_dir / "old.pem").chmod(0o600)
    (config_dir / "new.pem").chmod(0o600)
    config = {"tokens": {ISSUER: {"role": "issuer", "issuer": "U"}},
              "issuers": {"U": {"active_method": new_method,
                                "keys": {old_method: {"public_key_file": "old.pub"},
                                         new_method: {"private_key_file": "new.pem"}}}}}
    old_config = {"tokens": config["tokens"], "issuers": {"U": {"active_method": old_method,
                  "keys": {old_method: {"private_key_file": "old.pem"}}}}}
    (config_dir / "config.json").write_text(json.dumps(old_config))
    (config_dir / "config.json").chmod(0o600)
    monkeypatch.setenv("EDUCHAINTRUST_CONFIG", str(config_dir / "config.json"))
    old = Ed25519CredentialSigner.sign(VerifiableCredential.create("U", "did:edu:alice", {"course": "Old"}),
                                       old_private, old_method)
    with TestClient(create_app(tmp_path / "file-registry.sqlite3")) as client:
        tx = client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": old}).json()["tx_hash"]
    (config_dir / "config.json").write_text(json.dumps(config))
    with TestClient(create_app(tmp_path / "file-registry.sqlite3")) as client:
        assert client.post("/v1/credentials/verify", headers=hdr(ISSUER),
                           json={"credential": old, "tx_hash": tx}).json()["verified"]
        other_old = Ed25519CredentialSigner.sign(VerifiableCredential.create("U", "did:edu:bob", {"course": "Old"}),
                                                old_private, old_method)
        assert client.post("/v1/evidence/anchor", headers=hdr(ISSUER), json={"credential": other_old}).status_code == 409
        assert issue(client)["proof"]["verificationMethod"] == new_method


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission-bit policy")
def test_insecure_config_permissions_rejected(tmp_path, monkeypatch):
    generator = Path(__file__).resolve().parents[2] / "tools" / "generate_local_config.py"
    directory = tmp_path / "local-config"
    subprocess.run([sys.executable, str(generator), "--out-dir", str(directory), "--issuer", "U"],
                   check=True, capture_output=True, text=True)
    config_path = directory / "config.json"
    config_path.chmod(0o644)
    monkeypatch.setenv("EDUCHAINTRUST_CONFIG", str(config_path))
    with pytest.raises(RuntimeError, match="EDUCHAINTRUST_CONFIG must not be group/world accessible"):
        with TestClient(create_app(tmp_path / "unsafe-config.sqlite3")):
            pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission-bit policy")
def test_insecure_issuer_private_key_permissions_rejected(tmp_path, monkeypatch):
    generator = Path(__file__).resolve().parents[2] / "tools" / "generate_local_config.py"
    directory = tmp_path / "local-config"
    subprocess.run([sys.executable, str(generator), "--out-dir", str(directory), "--issuer", "U"],
                   check=True, capture_output=True, text=True)
    (directory / "issuer-key.pem").chmod(0o640)
    monkeypatch.setenv("EDUCHAINTRUST_CONFIG", str(directory / "config.json"))
    with pytest.raises(RuntimeError, match="issuer private key must not be group/world accessible"):
        with TestClient(create_app(tmp_path / "unsafe-key.sqlite3")):
            pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow descriptor policy")
def test_local_config_and_key_symlinks_rejected(tmp_path):
    generator = Path(__file__).resolve().parents[2] / "tools" / "generate_local_config.py"
    directory = tmp_path / "local-config"
    subprocess.run([sys.executable, str(generator), "--out-dir", str(directory), "--issuer", "U"],
                   check=True, capture_output=True, text=True)
    config_path = directory / "config.json"
    config_link = directory / "config-link.json"
    config_link.symlink_to(config_path)
    with pytest.raises(RuntimeError, match="EDUCHAINTRUST_CONFIG must point to a provisioned regular file"):
        api_main._read_config(config_link)
    key_link = directory / "alias.pem"
    key_link.symlink_to(directory / "issuer-key.pem")
    record = json.loads(config_path.read_text())
    issuer = record["issuers"]["U"]
    issuer["keys"][issuer["active_method"]]["private_key_file"] = key_link.name
    config_path.write_text(json.dumps(record))
    with pytest.raises(RuntimeError, match="issuer private key must point to a provisioned regular file"):
        api_main._read_config(config_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor replacement test")
def test_config_read_uses_checked_descriptor_after_path_replacement(tmp_path, monkeypatch):
    generator = Path(__file__).resolve().parents[2] / "tools" / "generate_local_config.py"
    directory = tmp_path / "local-config"
    subprocess.run([sys.executable, str(generator), "--out-dir", str(directory), "--issuer", "U"],
                   check=True, capture_output=True, text=True)
    config_path = directory / "config.json"
    original = json.loads(config_path.read_text())
    replacement = directory / "replacement.json"
    replacement.write_text(json.dumps({**original, "tokens": {"changed-token": {"role": "admin"}}}))
    replacement.chmod(0o644)
    real_open = os.open
    def swap_after_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if path == config_path.name and kwargs.get("dir_fd") is not None:
            os.replace(replacement, config_path)
        return fd
    monkeypatch.setattr(api_main.os, "open", swap_after_open)
    tokens, _ = api_main._read_config(config_path)
    assert tokens == original["tokens"]
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o644


@pytest.mark.skipif(os.name != "posix", reason="POSIX protected directory policy")
def test_writable_parent_and_parent_symlink_rejected(tmp_path):
    generator = Path(__file__).resolve().parents[2] / "tools" / "generate_local_config.py"
    directory = tmp_path / "private"
    subprocess.run([sys.executable, str(generator), "--out-dir", str(directory), "--issuer", "U"],
                   check=True, capture_output=True, text=True)
    directory.chmod(0o777)
    with pytest.raises(RuntimeError, match="protected parent directories"):
        api_main._read_config(directory / "config.json")
    directory.chmod(0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(RuntimeError, match="provisioned regular file"):
        api_main._read_config(alias / "config.json")


def test_generator_does_not_delete_competing_key(tmp_path, monkeypatch):
    directory = tmp_path / "config"
    key = directory / "issuer-key.pem"
    original_open = os.open
    raced = False

    def concurrent_create(path, flags, *args, **kwargs):
        nonlocal raced
        if path == key and not raced:
            raced = True
            fd = original_open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(b"OTHER PROCESS")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(generate_local_config.os, "open", concurrent_create)
    monkeypatch.setattr(sys, "argv", ["generate_local_config.py", "--out-dir", str(directory)])
    with pytest.raises(FileExistsError):
        generate_local_config.main()
    assert raced and key.read_bytes() == b"OTHER PROCESS"


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner policy")
def test_untrusted_directory_or_key_owner_rejected(tmp_path, monkeypatch):
    directory = tmp_path / "config"
    directory.mkdir()
    key = directory / "private.pem"
    key.write_bytes(b"SYNTHETIC")
    key.chmod(0o600)
    monkeypatch.delenv("EDUCHAINTRUST_TRUSTED_CONFIG_UID", raising=False)
    original_fstat = os.fstat

    def untrusted_owner(fd):
        result = original_fstat(fd)
        if result.st_ino == directory.stat().st_ino and result.st_dev == directory.stat().st_dev:
            fields = list(result)
            fields[4] = 424242
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(api_main.os, "fstat", untrusted_owner)
    with pytest.raises(RuntimeError, match="parent directory has an untrusted owner"):
        api_main._read_local_file(key, "key", private=True)
    monkeypatch.setattr(api_main.os, "fstat", original_fstat)

    def untrusted_key(fd):
        result = original_fstat(fd)
        if result.st_ino == key.stat().st_ino and result.st_dev == key.stat().st_dev:
            fields = list(result)
            fields[4] = 424242
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(api_main.os, "fstat", untrusted_key)
    with pytest.raises(RuntimeError, match="file has an untrusted owner"):
        api_main._read_local_file(key, "key", private=True)
    monkeypatch.setenv("EDUCHAINTRUST_TRUSTED_CONFIG_UID", "424242")
    assert api_main._read_local_file(key, "key", private=True) == b"SYNTHETIC"
