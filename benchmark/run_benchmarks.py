# SPDX-License-Identifier: MIT
"""In-process research benchmark; batch measurements are not deployment throughput."""
import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

from fastapi import __version__ as fastapi_version
from fastapi.testclient import TestClient
from cryptography import __version__ as cryptography_version

from api.main import create_app
from educhaintrust.blockchain.sqlitechain import SQLiteEvidenceStore
from educhaintrust.credential.signing import Ed25519CredentialSigner
from educhaintrust.credential.vc import VerifiableCredential
from educhaintrust.privacy.hashing import generate_hash
from educhaintrust.verifier.engine import VerificationEngine


ISSUER = "Benchmark-U"
TOKEN = "benchmark-local-only-token-000000000001"
METHOD = "urn:educhaintrust:benchmark:key-1"


def credential(index, private):
    unsigned = VerifiableCredential.create(ISSUER, f"did:edu:synthetic-{index}", {"course": "AI", "index": index})
    return Ed25519CredentialSigner.sign(unsigned, private, METHOD)


def measure(fn, repeats, warmup=2):
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    ordered = sorted(samples)
    p95 = ordered[min(len(ordered) - 1, int((len(ordered) - 1) * .95 + .5))]
    return {"raw_batch_ms": samples, "mean_batch_ms": statistics.mean(samples),
            "median_batch_ms": statistics.median(samples), "p95_batch_ms": p95,
            "stdev_batch_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--out", default="benchmark/single_run_local.json")
    args = parser.parse_args()
    if args.n < 1 or args.repeats < 2:
        parser.error("n must be >=1 and repeats >=2")
    private, public = Ed25519CredentialSigner.generate_keypair()
    trust = {ISSUER: {"private_key": private, "public_key": public, "verification_method": METHOD}}
    generation = measure(lambda: [credential(i, private) for i in range(args.n)], args.repeats)
    with tempfile.TemporaryDirectory() as directory:
        store = SQLiteEvidenceStore(Path(directory) / "persistent.sqlite3")
        credentials = [credential(i, private) for i in range(args.n)]
        transactions = [store.anchor(generate_hash(c), ISSUER) for c in credentials]
        verifier = VerificationEngine()

        def verify_batch():
            results = [verifier.verify(c, store, tx, trust) for c, tx in zip(credentials, transactions)]
            assert all(item["verified"] for item in results)

        verification = measure(verify_batch, args.repeats)
        counter = 0

        def api_roundtrip():
            nonlocal counter
            # Each batch uses a clean SQLite database and includes app startup.
            counter += 1
            db = Path(directory) / f"api-{counter}.sqlite3"
            app = create_app(db, {TOKEN: {"role": "issuer", "issuer": ISSUER}}, trust)
            with TestClient(app) as client:
                headers = {"X-API-Key": TOKEN}
                for i in range(args.n):
                    issued = client.post("/v1/credentials", headers=headers,
                                         json={"issuer": ISSUER, "holder": f"did:edu:synthetic-{i}",
                                               "claim": {"course": "AI", "index": i}})
                    assert issued.status_code == 200, issued.text
                    c = issued.json()["credential"]
                    anchored = client.post("/v1/evidence/anchor", headers=headers, json={"credential": c})
                    assert anchored.status_code == 200, anchored.text
                    checked = client.post("/v1/credentials/verify", headers=headers,
                                          json={"credential": c, "tx_hash": anchored.json()["tx_hash"]})
                    assert checked.status_code == 200 and checked.json()["verified"], checked.text

        api = measure(api_roundtrip, args.repeats, warmup=1)
    result = {
        "software_version": "1.12.0",
        "scope": "synthetic in-process research benchmark; no network or public ledger",
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(),
                        "cpu_count": os.cpu_count(), "fastapi": fastapi_version,
                        "cryptography": cryptography_version},
        "workload_per_batch": args.n, "repeats": args.repeats,
        "signed_credential_generation": generation,
        "trusted_persistent_verification": verification,
        "authenticated_api_issue_anchor_verify": api,
    }
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
