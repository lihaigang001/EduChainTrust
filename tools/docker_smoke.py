# SPDX-License-Identifier: MIT
"""Local synthetic HTTP smoke check for a running Compose API."""
import json
import os
from pathlib import Path
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

BASE = os.getenv('EDUCHAINTRUST_SMOKE_URL', 'http://127.0.0.1:8000')
CONFIG = Path(os.getenv('EDUCHAINTRUST_CONFIG', 'local-config/config.json'))


def request(path, token=None, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {'Content-Type': 'application/json'} if data else {}
    if token:
        headers['X-API-Key'] = token
    with urlopen(Request(BASE + path, data=data, headers=headers), timeout=5) as response:
        return json.loads(response.read())


def main():
    config = json.loads(CONFIG.read_text(encoding='utf-8'))
    token, identity = next((key, value) for key, value in config['tokens'].items()
                           if value['role'] == 'issuer')
    issuer = identity['issuer']
    for attempt in range(30):
        try:
            if request('/health')['status'] == 'ok':
                break
        except (OSError, URLError, ValueError):
            pass
        time.sleep(1)
    else:
        raise RuntimeError('API health check did not become ready')
    credential = request('/v1/credentials', token, {'issuer': issuer, 'holder': 'did:edu:ci-synthetic',
                                                     'claim': {'course': 'Synthetic CI'}})['credential']
    tx = request('/v1/evidence/anchor', token, {'credential': credential})['tx_hash']
    checked = request('/v1/credentials/verify', token, {'credential': credential, 'tx_hash': tx})
    assert checked['verified'] and checked['status'] == 'active'
    request('/v1/evidence/revoke', token, {'tx_hash': tx})
    revoked = request('/v1/credentials/verify', token, {'credential': credential, 'tx_hash': tx})
    assert not revoked['verified'] and revoked['status'] == 'revoked'
    print('Synthetic Compose API issue-anchor-verify-revoke smoke PASS')


if __name__ == '__main__':
    main()
