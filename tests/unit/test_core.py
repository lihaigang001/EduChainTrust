from copy import deepcopy
import math
import sqlite3
import os
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor

import pytest

from educhaintrust.analytics.evidence import EvidenceScore
from educhaintrust.blockchain.mockchain import MockBlockchain
from educhaintrust.blockchain.sqlitechain import SQLiteEvidenceStore
from educhaintrust.credential.signing import Ed25519CredentialSigner
from educhaintrust.credential.vc import VerifiableCredential
from educhaintrust.identity.did import DIDManager
from educhaintrust.privacy.canonical import canonicalize
from educhaintrust.privacy.hashing import generate_hash
from educhaintrust.verifier.engine import VerificationEngine


def _competing_anchor(path, digest, barrier):
    store = SQLiteEvidenceStore(path)
    barrier.wait(timeout=15)
    try:
        return os.getpid(), store.anchor(digest, "University-A") is not None
    except ValueError:
        return os.getpid(), False


def _competing_revoke(path, tx, barrier):
    barrier.wait(timeout=15)
    return os.getpid(), SQLiteEvidenceStore(path).revoke(tx, "University-A")


def _competing_legacy_migration(path, barrier):
    barrier.wait(timeout=15)
    store = SQLiteEvidenceStore(path)
    return os.getpid(), store.record("sqlite:old")["issuer"]


def test_nested_json_has_defined_failure():
    value = {}
    for _ in range(1000):
        value = {"nested": value}
    with pytest.raises(ValueError, match="nesting limit"):
        canonicalize(value)


def test_non_json_tuple_cannot_bypass_depth_bound():
    value = 1
    for _ in range(100):
        value = (value,)
    with pytest.raises(TypeError, match="Only JSON"):
        canonicalize(value)


def _race_processes(path, action, value):
    # Pipes coordinate two real subprocesses without a local Manager socket.
    import subprocess, sys, json
    script = """import sys, json, os
from educhaintrust.blockchain.sqlitechain import SQLiteEvidenceStore
path, action, value = sys.argv[1:]
print('ready', flush=True)
sys.stdin.readline()
if action == 'migrate':
    result = SQLiteEvidenceStore(path).record('sqlite:old')['issuer']
elif action == 'anchor':
    try: result = bool(SQLiteEvidenceStore(path).anchor(value, 'University-A'))
    except ValueError: result = False
else: result = SQLiteEvidenceStore(path).revoke(value, 'University-A')
print(json.dumps([os.getpid(), result]), flush=True)
"""
    procs = [subprocess.Popen([sys.executable, '-c', script, str(path), action, value],
             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    for proc in procs:
        assert proc.stdout.readline().strip() == 'ready'
    for proc in procs:
        proc.stdin.write('go\n'); proc.stdin.flush()
    results = []
    for proc in procs:
        out, err = proc.communicate(timeout=30)
        assert proc.returncode == 0, err
        results.append(json.loads(out))
    return results


def test_two_processes_cannot_duplicate_anchor_or_revoke(tmp_path):
    path = tmp_path / 'concurrent.sqlite3'
    digest = 'a' * 64
    attempts = _race_processes(path, 'anchor', digest)
    assert sum(ok for _, ok in attempts) == 1
    assert len({pid for pid, _ in attempts}) == 2
    with sqlite3.connect(path) as connection:
        rows = connection.execute('SELECT tx FROM evidence WHERE digest=?', (digest,)).fetchall()
    assert len(rows) == 1
    revocations = _race_processes(path, 'revoke', rows[0][0])
    assert sum(ok for _, ok in revocations) == 1
    assert len({pid for pid, _ in revocations}) == 2
    assert SQLiteEvidenceStore(path).status(rows[0][0]) == 'revoked'


def test_two_processes_can_start_from_one_legacy_database(tmp_path):
    for index in range(3):
        path = tmp_path / f'legacy-{index}.sqlite3'
        with sqlite3.connect(path) as con:
            con.execute('CREATE TABLE evidence(tx TEXT PRIMARY KEY,digest TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)')
            con.execute("INSERT INTO evidence VALUES('sqlite:old',?,0)", ('a' * 64,))
        outcomes = _race_processes(path, 'migrate', '-')
        assert len({pid for pid, _ in outcomes}) == 2
        assert [issuer for _, issuer in outcomes] == [None, None]


@pytest.fixture
def issued(tmp_path):
    private, public = Ed25519CredentialSigner.generate_keypair()
    issuer = "University-A"
    method = "urn:educhaintrust:university-a:key-1"
    unsigned = VerifiableCredential.create(issuer, "did:edu:alice", {"course": "AI"})
    signed = Ed25519CredentialSigner.sign(unsigned, private, method)
    store = SQLiteEvidenceStore(tmp_path / "evidence.sqlite3")
    tx = store.anchor(generate_hash(signed), issuer)
    trust = {issuer: {"public_key": public, "verification_method": method}}
    return unsigned, signed, store, tx, trust


def test_valid_issued_credential(issued):
    _, credential, store, tx, trust = issued
    result = VerificationEngine().verify(credential, store, tx, trust)
    assert result["verified"] and result["signature_valid"] and result["issuer_anchor_matched"]


def test_unsigned_self_anchored_credential_never_verifies(tmp_path, issued):
    unsigned, _, _, _, trust = issued
    store = SQLiteEvidenceStore(tmp_path / "attacker.sqlite3")
    tx = store.anchor(generate_hash(unsigned), "University-A")
    result = VerificationEngine().verify(unsigned, store, tx, trust)
    assert result["integrity_matched"] and not result["signature_valid"] and not result["verified"]


@pytest.mark.parametrize("field,value", [
    ("created", "1990-01-01T00:00:00Z"),
    ("verificationMethod", "urn:educhaintrust:key:attacker"),
    ("proofPurpose", "authentication"),
    ("type", "UnknownProof"),
    ("proofValue", "not-the-signature"),
])
def test_proof_metadata_is_signed(issued, field, value):
    _, credential, store, tx, trust = issued
    changed = deepcopy(credential)
    changed["proof"][field] = value
    assert not VerificationEngine().verify(changed, store, tx, trust)["verified"]


def test_credential_tampering_wrong_key_and_untrusted_issuer(issued):
    _, credential, store, tx, trust = issued
    changed = deepcopy(credential)
    changed["credentialSubject"]["course"] = "Medicine"
    assert not VerificationEngine().verify(changed, store, tx, trust)["verified"]
    assert not VerificationEngine().verify(credential, store, tx, {})["verified"]
    _, wrong = Ed25519CredentialSigner.generate_keypair()
    bad_trust = {"University-A": {"public_key": wrong, "verification_method": trust["University-A"]["verification_method"]}}
    assert not VerificationEngine().verify(credential, store, tx, bad_trust)["verified"]


def test_anchor_issuer_binding(issued, tmp_path):
    _, credential, _, _, trust = issued
    store = SQLiteEvidenceStore(tmp_path / "wrong-issuer.sqlite3")
    tx = store.anchor(generate_hash(credential), "Other-U")
    result = VerificationEngine().verify(credential, store, tx, trust)
    assert result["signature_valid"] and result["integrity_matched"]
    assert not result["issuer_anchor_matched"] and not result["verified"]


def test_revocation_keeps_integrity_separate_and_records_actor(issued):
    _, credential, store, tx, trust = issued
    assert store.revoke(tx, "University-A")
    result = VerificationEngine().verify(credential, store, tx, trust)
    assert result["integrity_matched"] and result["signature_valid"]
    assert result["status"] == "revoked" and not result["verified"]
    assert store.record(tx)["revoked_by"] == "University-A"
    assert not store.revoke(tx, "University-A")
    with pytest.raises(ValueError, match="already anchored"):
        store.anchor(generate_hash(credential), "University-A")


def test_future_and_expired_credentials_are_not_current(issued, tmp_path):
    _, _, _, _, trust = issued
    private, public = Ed25519CredentialSigner.generate_keypair()
    method = "urn:educhaintrust:time:key"
    local_trust = {"U": {"public_key": public, "verification_method": method}}
    store = SQLiteEvidenceStore(tmp_path / "times.sqlite3")
    for index, valid_from, valid_until in [
        (1, "2099-01-01T00:00:00Z", None),
        (2, "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
    ]:
        item = VerifiableCredential.create("U", f"did:edu:{index}", {"course": "AI"})
        item["validFrom"] = valid_from
        if valid_until:
            item["validUntil"] = valid_until
        signed = Ed25519CredentialSigner.sign(item, private, method)
        tx = store.anchor(generate_hash(signed), "U")
        outcome = VerificationEngine().verify(signed, store, tx, local_trust)
        assert outcome["signature_valid"] and outcome["integrity_matched"]
        assert not outcome["time_valid"] and not outcome["verified"]


def test_sqlite_reopen_and_legacy_unsigned_migration(issued, tmp_path):
    _, credential, store, tx, trust = issued
    reopened = SQLiteEvidenceStore(store.path)
    assert VerificationEngine().verify(credential, reopened, tx, trust)["verified"]
    legacy = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(legacy) as con:
        con.execute("CREATE TABLE evidence(tx TEXT PRIMARY KEY,digest TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)")
        con.execute("INSERT INTO evidence VALUES(?,?,0)", ("sqlite:old", generate_hash(credential)))
    migrated = SQLiteEvidenceStore(legacy)
    assert migrated.record("sqlite:old")["issuer"] is None
    assert not VerificationEngine().verify(credential, migrated, "sqlite:old", trust)["verified"]


def test_mock_backend_uses_same_verification_contract(issued):
    _, credential, _, _, trust = issued
    chain = MockBlockchain()
    tx = chain.anchor(generate_hash(credential), "University-A")
    assert VerificationEngine().verify(credential, chain, tx, trust)["verified"]
    assert chain.revoke(tx, "University-A")
    assert not VerificationEngine().verify(credential, chain, tx, trust)["verified"]


@pytest.mark.parametrize("bad", [{"@context": []}, {"@context": None},
                                 {"issuer": ""}, {"credentialSubject": {}},
                                 {"validFrom": "not-a-date"}])
def test_invalid_vc_is_reported_not_crashed(issued, bad):
    _, credential, _, _, _ = issued
    changed = {**credential, **bad}
    assert not VerifiableCredential.validate(changed)["valid"]


def test_claim_cannot_override_subject():
    with pytest.raises(ValueError):
        VerifiableCredential.create("U", "did:edu:alice", {"id": "did:edu:attacker"})


def test_did_local_identity_and_invalid_fields():
    result = DIDManager().create_identity("student", "Alice", "U")
    assert result["did"].startswith("did:edu:") and len(result["did"].split(":")[-1]) == 32
    with pytest.raises(ValueError):
        DIDManager().create_identity("student", "", "U")


def test_canonicalization_order_unicode_and_nan():
    assert canonicalize({"b": "教育", "a": 1}) == canonicalize({"a": 1, "b": "教育"})
    with pytest.raises(ValueError):
        canonicalize({"x": math.nan})


@pytest.mark.parametrize("bad", [-0.1, 1.1, math.nan, math.inf])
def test_score_rejects_invalid_values(bad):
    with pytest.raises(ValueError):
        EvidenceScore.calculate(bad, .5, .5, .5)


def test_score_normal_case():
    assert EvidenceScore.calculate(.8, .9, .7, .6) == pytest.approx(.75)
