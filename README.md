# EduChainTrust v1.12.0

[![DOI](https://zenodo.org/badge/1437173226.svg)](https://doi.org/10.5281/zenodo.23750199)

EduChainTrust is a Python **research prototype** for local educational credential evidence. It creates a VC Data Model 2.0-style dictionary, signs the credential and proof metadata with a project-specific Ed25519 profile, stores only a digest and issuer ID in SQLite, and evaluates structure, signature, trusted issuer key, issuer/anchor attribution, time validity, digest match, and revocation separately.

The project-specific signature is **not** W3C Data Integrity conformance. `did:edu` has no registered method resolver. SQLite is not a blockchain. The authentication and key-file setup below is intended for local synthetic demonstrations, not public deployment or a real institution's credential authority. No selective disclosure or cross-implementation interoperability is claimed.

## Installation

Python 3.11 or later:

```bash
python -m pip install -e '.[all]'
```

For core-only installation, use `python -m pip install -e .`; for the API, use `python -m pip install -e ".[api]"`. The package also includes a dashboard, synthetic data, benchmark tools, tests, and a user manual.

## First run using synthetic data

```bash
python examples/university_demo.py
python tools/generate_local_config.py --issuer University-A
export EDUCHAINTRUST_CONFIG="$PWD/local-config/config.json"
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

The provisioning script prints random issuer, verifier, and administrator `X-API-Key` values once. It writes unencrypted local demonstration key material in `local-config/` with restrictive Unix permissions and refuses to overwrite an existing key. On failure, it only removes files it created; a competing file is not deleted. On POSIX, the API walks the complete path through directory descriptors, refusing symlink components and group/other writable directories except root-owned sticky temporary directories. Every parent and the final file must be owned by root or the service UID; an operator may explicitly add one trusted UID with `EDUCHAINTRUST_TRUSTED_CONFIG_UID`. The final opened regular file rejects group/other access to token configuration and private keys, and is read through the checked descriptor. Use `chmod 700 local-config` and `chmod 600` for configuration and private keys after copying or editing. These checks do not inspect Windows ACLs or protect against another process with the same user identity. Keep secrets out of version control. The API will **fail at startup** when a trusted issuer and API tokens are not configured. The `/docs` page documents endpoint bodies; call protected endpoints with the appropriate `X-API-Key` header.

The issuer token can create local identities, issue signed credentials, anchor its own signed credentials, and revoke its own evidence. The verifier token can read status and verify. The administrator token can revoke any record. Authentication is token based for a local test environment; this release does not implement a production identity provider, institutional key custody, rate limiting, or a complete privacy governance workflow.

Credential JSON requests are limited to 256 KiB and 64 nested JSON containers. Larger bodies receive HTTP 413 and excessive depth receives HTTP 422. The deterministic JSON encoder applies the same depth bound to direct library calls and rejects non-JSON containers such as tuples. These limits prevent one class of accidental or hostile recursive input; they do not replace network controls or rate limiting.

`POST /v1/credentials` optionally accepts `valid_until` as a timezone-aware ISO 8601 timestamp after issuance; the signed credential then contains `validUntil`. The configuration generator produces a `keys` registry per issuer and an `active_method`. To rotate locally, add a new PEM key under a distinct verification-method identifier, set `active_method` to it, and retain the former public key in `keys` while its previously anchored credentials should remain verifiable. After switching the active method, the API rejects any new anchor signed with the former method, including a credential issued but not yet anchored before rotation. Anchor pending credentials before switching or reissue them with the new method. Removing a former method withdraws trust in its signatures, including old anchored records. Back up and edit local configuration securely, then restart the API; it reads configuration at startup. The v1.3 single-key file format is accepted for migration. This is manual local key history, not an institutional rotation service or a revocation mechanism for individual credentials.

```bash
streamlit run dashboard/app.py --server.address=127.0.0.1
```

The dashboard creates ephemeral session keys and uses an in-memory mock ledger; it does not communicate with the SQLite API and must not be mistaken for a university issuer.

## Verification result

`verified` is true only if `structure_valid`, `issuer_trusted`, `signature_valid`, `time_valid`, `integrity_matched`, and `issuer_anchor_matched` are true and `status` is `active`. The API rejects unsigned or malformed anchoring. For newly anchored API credentials, the issuer and credential ID are unique, including after revocation. The API rejects noncanonical signature encodings. It also checks all equivalent signature encodings against historic digests. Historic rows have no credential IDs; their IDs cannot be reconstructed from hashes, so a newly signed different object reusing an old ID cannot always be recognized. Direct low-level store users must supply credential_id and equivalent digests themselves; the API enforces this policy. A separate newly issued credential has a different ID and signature. Legacy v1.2.4 SQLite evidence rows are migrated without deleting data, but their absent issuer attribution prevents a trusted v1.12.0 verification result.

Issuer trust is configured out of band by the local API operator. The digest proves equality to bytes represented by this project's deterministic JSON profile; it does not by itself prove who created the credential. This profile does not claim RFC 8785 equivalence. The store contains digests, issuer IDs, and lifecycle metadata, while API requests and dashboard sessions still handle full claim content. Use only synthetic data in this release.

## Tests and benchmarks

```bash
python -m pytest -q -W error::ResourceWarning --cov=educhaintrust --cov=api --cov-fail-under=85
python benchmark/run_campaign.py --n 100 --runs 3 --repeats-per-run 10
python benchmark/plot_results.py --input benchmark/results_v1.12.0.json --out benchmark/figure3_v1.12.0.png
```

The v1.12.0 benchmark measures batches of 100 **signed** credential generations, trusted SQLite verifications, and in-process authenticated API issue/anchor/verify cycles. The last workflow includes app startup and a new SQLite file in every batch. Three independent Python processes produce 30 recorded batches and retain per-run and aggregate samples, dispersion, and environment metadata. It is not a network throughput, public ledger, cross-system comparison, or deployment latency result.


## Synthetic comparison of verification checks

Run `python experiments/compare_verification.py` after installing the project. Six reproducible local cases compare deliberately narrow digest-only and signature-only checks with the composite verifier. These checks are illustrative baselines rather than external software products. The script saves its outputs under `experiments/`; see its README for definitions and limitations.

## Container demonstration

Provision `local-config/` first, then run `EDUCHAINTRUST_TRUSTED_CONFIG_UID=$(id -u) docker compose up --build` on POSIX when the bind-mounted files belong to the host operator. This explicitly trusts that UID inside the root-run research container. If the files are root-owned, `docker compose up --build` works with the default UID 0. The `.dockerignore` build context permits only application source and packaging files; the Dockerfile copies those paths explicitly, so `local-config/` and locally generated files are excluded from the image. Compose mounts configuration read-only, binds ports only to `127.0.0.1`, and keeps SQLite in a named volume. This is a local demonstration. The hosted CI workflow configures a synthetic Compose issue-anchor-verify-revoke smoke job. No container smoke-test evidence is claimed until that job runs on a Docker-capable machine.

MIT license terms are in `LICENSE`. Report vulnerabilities privately to the maintainer at lihaigang02292@qqhru.edu.cn; do not include learner records in reports.

## Authors

- **Haonan Zhang** — College of Teacher Education, Qiqihar University, Qiqihar, China 161003 — 2025933211@qqhru.edu.cn
- **Haigang Li** (maintainer) — College of Teacher Education, Qiqihar University, Qiqihar, China 161003 — lihaigang02292@qqhru.edu.cn
