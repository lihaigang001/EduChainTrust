# Synthetic verification comparison

After installing the project and API dependencies, run:

```bash
python experiments/compare_verification.py
```

The experiment creates temporary signing keys, synthetic credentials and six independent temporary SQLite stores. It records Boolean outcomes and diagnostic flags in comparison_results_v1.12.0.json. No learner data or private keys are saved.

The digest-only baseline compares the submitted object to the stored digest, without signature, issuer, validity time or revocation checks. The signature-only baseline checks an Ed25519 signature against a supplied candidate public key, without establishing that the key is trusted, or checking digest, time or revocation. These narrowly defined baselines are illustrative functions, not named external software products and not comprehensive verifiers. The aggregate EduChainTrust result checks the configured issuer, signature, time, digest, issuer attribution and status. In the mismatched-anchor example, the full result rejects despite successful cryptographic signature and digest matching.

The example demonstrates behavior for six synthetic cases; it does not demonstrate real-world adoption, educational impact, interoperability, clinical validity, general accuracy rates or production security. Performance measurements are separate in benchmark/.
