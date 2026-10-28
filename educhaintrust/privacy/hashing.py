# SPDX-License-Identifier: MIT
import hashlib
from .canonical import canonicalize
def generate_hash(data): return hashlib.sha256(canonicalize(data)).hexdigest()
