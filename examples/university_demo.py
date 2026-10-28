# SPDX-License-Identifier: MIT
import tempfile
from pathlib import Path
from educhaintrust.identity.did import DIDManager
from educhaintrust.credential.vc import VerifiableCredential
from educhaintrust.credential.signing import Ed25519CredentialSigner
from educhaintrust.privacy.hashing import generate_hash
from educhaintrust.blockchain.sqlitechain import SQLiteEvidenceStore
from educhaintrust.verifier.engine import VerificationEngine
from educhaintrust.analytics.evidence import EvidenceScore
student=DIDManager().create_identity("student","Alice","University-A")
c=VerifiableCredential.create("University-A",student["did"],{"course":"Artificial Intelligence"})
private,public=Ed25519CredentialSigner.generate_keypair(); signed=Ed25519CredentialSigner.sign(c,private)
with tempfile.TemporaryDirectory() as directory:
    path=Path(directory)/"evidence.sqlite3"
    store=SQLiteEvidenceStore(path); tx=store.anchor(generate_hash(signed),"University-A")
    print("VC 2.0 validation:",VerifiableCredential.validate(signed))
    print("Signature verified:",Ed25519CredentialSigner.verify(signed,public))
    trust={"University-A":{"public_key":public,"verification_method":"urn:educhaintrust:key:issuer"}}
    print("Trusted verification:",VerificationEngine().verify(signed,store,tx,trust))
    print("Status:",store.status(tx))
    print("Evidence score:",EvidenceScore.calculate(.8,.9,.7,.6))
