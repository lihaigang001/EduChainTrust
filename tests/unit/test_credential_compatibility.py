from copy import deepcopy
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from api.main import create_app
from educhaintrust.blockchain.sqlitechain import SQLiteEvidenceStore
from educhaintrust.credential.signing import Ed25519CredentialSigner, _unb64u
from educhaintrust.credential.vc import VerifiableCredential
from educhaintrust.privacy.hashing import generate_hash
from educhaintrust.verifier.engine import VerificationEngine

TOKEN = 'x' * 32
METHOD = 'urn:test:key'

def pair():
    private = Ed25519PrivateKey.generate()
    c = Ed25519CredentialSigner.sign(VerifiableCredential.create('U', 'holder', {'course': 'AI'}), private, METHOD)
    value = c['proof']['proofValue']; raw = _unb64u(value)
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    alt = next(x for x in alphabet if x != value[-1] and _unb64u(value[:-1]+x, allow_noncanonical=True) == raw)
    variant = deepcopy(c); variant['proof']['proofValue'] = value[:-1]+alt
    return private, c, variant

def app_for(db, private):
    return create_app(db, {TOKEN: {'role':'issuer','issuer':'U'}}, {'U': {'private_key': private, 'public_key': private.public_key(), 'verification_method': METHOD}})

def anchor(client, credential):
    return client.post('/v1/evidence/anchor', headers={'X-API-Key':TOKEN}, json={'credential':credential})

def test_api_rejects_signature_variants_and_reissued_same_id(tmp_path):
    private, c, variant = pair()
    with TestClient(app_for(tmp_path/'api.db', private)) as client:
        first = anchor(client,c); assert first.status_code == 200
        tx = first.json()['tx_hash']
        assert client.post('/v1/evidence/revoke',headers={'X-API-Key':TOKEN},json={'tx_hash':tx}).status_code == 200
        assert anchor(client,variant).status_code == 422
        unsigned = deepcopy(c); unsigned.pop('proof')
        unsigned['credentialSubject']['course'] = 'Different signed content'
        another = Ed25519CredentialSigner.sign(unsigned,private,METHOD)
        assert anchor(client,another).status_code == 409

def test_old_noncanonical_revoked_record_blocks_canonical_anchor_and_verifies(tmp_path):
    private,c,variant=pair(); db=tmp_path/'old.db'
    # Emulate a v1.11 row, which has no credential_id column.
    with sqlite3.connect(db) as con:
        con.execute('CREATE TABLE evidence(tx TEXT PRIMARY KEY,digest TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,issuer TEXT,created_at TEXT,revoked_at TEXT,revoked_by TEXT)')
        con.execute('INSERT INTO evidence(tx,digest,revoked,issuer) VALUES(?,?,?,?)',('old',generate_hash(variant),0,'U'))
    with TestClient(app_for(db,private)) as client:
        result=client.post('/v1/credentials/verify', headers={'X-API-Key':TOKEN},json={'credential':variant,'tx_hash':'old'}).json()
        assert result['verified']
        assert anchor(client,c).status_code == 409
        assert client.post('/v1/evidence/revoke',headers={'X-API-Key':TOKEN},json={'tx_hash':'old'}).status_code == 200
        assert anchor(client,c).status_code == 409
        assert not client.post('/v1/credentials/verify',headers={'X-API-Key':TOKEN},json={'credential':variant,'tx_hash':'old'}).json()['verified']

def test_encoding_requires_exact_length_and_canonical_bits():
    private,c,variant=pair()
    assert Ed25519CredentialSigner.verify(c,private.public_key(),METHOD)
    assert not Ed25519CredentialSigner.verify(variant,private.public_key(),METHOD)
    with pytest.raises(ValueError): _unb64u('AA')

def test_structure_uuid_and_context():
    c = VerifiableCredential.create('U','holder',{'course':'AI'})
    c['id']='urn:uuid:not-a-uuid'
    assert not VerifiableCredential.validate(c)['valid']
    c=VerifiableCredential.create('U','holder',{'course':'AI'}); c['@context'].append(42)
    assert not VerifiableCredential.validate(c)['valid']

def test_two_processes_race_for_same_credential_identity(tmp_path):
    db=tmp_path/'race.db'; SQLiteEvidenceStore(db)
    script='''import sys\nfrom educhaintrust.blockchain.sqlitechain import SQLiteEvidenceStore\ns=SQLiteEvidenceStore(sys.argv[1])\ntry:\n s.anchor(sys.argv[2],"U",credential_id="urn:uuid:550e8400-e29b-41d4-a716-446655440000")\n print("success")\nexcept ValueError:\n print("duplicate")\n'''
    args=[sys.executable,'-c',script,str(db)]
    a=subprocess.Popen(args+['a'*64],stdout=subprocess.PIPE,text=True)
    b=subprocess.Popen(args+['b'*64],stdout=subprocess.PIPE,text=True)
    out=[a.communicate(timeout=20)[0].strip(),b.communicate(timeout=20)[0].strip()]
    assert sorted(out)==['duplicate','success'] and a.returncode==b.returncode==0

def test_two_process_api_competition_rejects_noncanonical_variant(tmp_path):
    from cryptography.hazmat.primitives import serialization
    private,c,variant=pair(); db=tmp_path/'race-api.db'; SQLiteEvidenceStore(db)
    pem=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).hex()
    script='''import sys,json
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from api.main import create_app
key=serialization.load_pem_private_key(bytes.fromhex(sys.argv[2]),password=None)
app=create_app(sys.argv[1],{'x'*32:{'role':'issuer','issuer':'U'}},{'U':{'private_key':key,'public_key':key.public_key(),'verification_method':'urn:test:key'}})
with TestClient(app) as client:
 print('ready',flush=True)
 c=json.loads(sys.stdin.readline())
 print(client.post('/v1/evidence/anchor',headers={'X-API-Key':'x'*32},json={'credential':c}).status_code,flush=True)
'''
    ps=[subprocess.Popen([sys.executable,'-c',script,str(db),pem],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
    for p in ps: assert p.stdout.readline().strip()=='ready'
    for p,obj in zip(ps,(c,variant)): p.stdin.write(json.dumps(obj)+'\n');p.stdin.flush()
    outputs=[]
    for p in ps:
        out,err=p.communicate(timeout=30);assert p.returncode==0,err;outputs.append(int(out.strip()))
    assert sorted(outputs)==[200,422]
    assert len(sqlite3.connect(db).execute('select tx from evidence').fetchall())==1
