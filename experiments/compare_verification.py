# SPDX-License-Identifier: MIT
"""Reproducible synthetic controls; baselines are deliberately narrow, not external products."""
import json
import tempfile
from copy import deepcopy
from pathlib import Path
import hmac

from educhaintrust.blockchain.sqlitechain import SQLiteEvidenceStore
from educhaintrust.credential.signing import Ed25519CredentialSigner
from educhaintrust.credential.vc import VerifiableCredential
from educhaintrust.privacy.hashing import generate_hash
from educhaintrust.verifier.engine import VerificationEngine

METHOD = 'urn:educhaintrust:comparison:key-1'
ISSUER = 'Synthetic-University'


def run():
    private, public = Ed25519CredentialSigner.generate_keypair()
    rogue_private, rogue_public = Ed25519CredentialSigner.generate_keypair()
    trust = {ISSUER: {'verification_method': METHOD, 'public_key': public}}
    signed = Ed25519CredentialSigner.sign(VerifiableCredential.create(ISSUER, 'did:edu:synthetic-learner', {'course': 'AI'}), private, METHOD)
    expired_unsigned = VerifiableCredential.create(ISSUER, 'did:edu:synthetic-learner', {'course': 'AI'})
    expired_unsigned['validFrom'] = '2020-01-01T00:00:00Z'
    expired_unsigned['validUntil'] = '2021-01-01T00:00:00Z'
    expired = Ed25519CredentialSigner.sign(expired_unsigned, private, METHOD)
    rogue = Ed25519CredentialSigner.sign(VerifiableCredential.create('Untrusted-Issuer', 'did:edu:synthetic-learner', {'course': 'AI'}), rogue_private, METHOD)
    cases = [
        ('Active trusted', signed, signed, public, ISSUER, False),
        ('Revoked', signed, signed, public, ISSUER, True),
        ('Untrusted issuer', rogue, rogue, rogue_public, 'Untrusted-Issuer', False),
        ('Altered claim', signed, deepcopy(signed), public, ISSUER, False),
        ('Expired', expired, expired, public, ISSUER, False),
        ('Mismatched anchor issuer', signed, signed, public, 'Other-University', False),
    ]
    cases[3][2]['credentialSubject']['course'] = 'Changed claim'
    result = []
    with tempfile.TemporaryDirectory() as directory:
        for i, (name, anchored, submitted, candidate_key, attributed_issuer, revoke) in enumerate(cases):
            store = SQLiteEvidenceStore(Path(directory) / f'case-{i}.sqlite3')
            tx = store.anchor(generate_hash(anchored), attributed_issuer)
            if revoke:
                store.revoke(tx, 'synthetic-issuer')
            row = store.record(tx)
            # Deliberately only compares digest, ignoring issuer, signature, time and status.
            digest = hmac.compare_digest(row['digest'], generate_hash(submitted))
            # Deliberately verifies the presented key, without trusting its source, time or status.
            signature = Ed25519CredentialSigner.verify(submitted, candidate_key, METHOD)
            detail = VerificationEngine().verify(submitted, store, tx, trust)
            result.append({'case': name, 'digest_only': digest, 'signature_only': signature,
                           'educhaintrust': detail['verified'],
                           'checks': {k: detail[k] for k in ('structure_valid','issuer_trusted','signature_valid','time_valid','integrity_matched','issuer_anchor_matched','status')}})
    return {'software_version': '1.12.0', 'scope': 'synthetic local behavior; narrow baselines are not external tools',
            'baseline_definitions': {'digest_only': 'compare the submitted object digest against the stored digest; no status, time, attribution or signature',
                                     'signature_only': 'verify against a supplied candidate public key; no issuer trust, status, time or digest'},
            'cases': result}


if __name__ == '__main__':
    record = run()
    out = Path(__file__).with_name('comparison_results_v1.12.0.json')
    out.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record, indent=2))
