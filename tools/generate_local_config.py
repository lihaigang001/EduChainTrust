# SPDX-License-Identifier: MIT
"""Provision local-only demonstration secrets; never commit the generated files."""
import argparse
import json
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="local-config")
    parser.add_argument("--issuer", default="University-A")
    args = parser.parse_args()
    directory = Path(args.out_dir).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_file, key_file = directory / "config.json", directory / "issuer-key.pem"
    if config_file.exists() or key_file.exists():
        raise SystemExit("Refusing to overwrite existing local keys or configuration")
    private = Ed25519PrivateKey.generate()
    key_bytes = private.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
    role_tokens = {role: secrets.token_urlsafe(32) for role in ("issuer", "verifier", "admin")}
    method = "urn:educhaintrust:" + secrets.token_hex(12) + ":key-1"
    config = {"tokens": {role_tokens["issuer"]: {"role": "issuer", "issuer": args.issuer},
                         role_tokens["verifier"]: {"role": "verifier"},
                         role_tokens["admin"]: {"role": "admin"}},
              "issuers": {args.issuer: {"active_method": method,
                                        "keys": {method: {"private_key_file": key_file.name}}}}}
    created = []
    try:
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created.append(key_file)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key_bytes)
        fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created.append(config_file)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    print("Local research issuer:", args.issuer)
    print("Configuration:", config_file)
    for role, token in role_tokens.items():
        print(role + " X-API-Key (shown once):", token)
    print("Keep the local key and tokens private; this script does not configure a production authority.")


if __name__ == "__main__":
    main()
