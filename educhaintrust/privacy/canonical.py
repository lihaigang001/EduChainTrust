# SPDX-License-Identifier: MIT
import json
import math

MAX_NESTING = 64

def canonicalize(data)->bytes:
    """Deterministic EduChainTrust JSON profile; not claimed as full RFC 8785."""
    pending = [(data, 1)]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite numbers are not permitted")
        if isinstance(value, (dict, list)):
            if depth > MAX_NESTING:
                raise ValueError("JSON nesting limit exceeded")
            if isinstance(value, dict):
                for key, item in value.items():
                    if not isinstance(key, str):
                        raise TypeError("JSON object keys must be strings")
                    pending.append((item, depth + 1))
            else:
                pending.extend((item, depth + 1) for item in value)
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise TypeError("Only JSON object, array, string, number, boolean and null are permitted")
    return json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")
