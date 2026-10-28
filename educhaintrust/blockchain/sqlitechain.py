# SPDX-License-Identifier: MIT
"""Local SQLite evidence backend. Not a distributed ledger."""
from datetime import datetime, timezone
from contextlib import closing
import re
import sqlite3
import uuid
from .adapter import BlockchainAdapter


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SQLiteEvidenceStore(BlockchainAdapter):
    """Short-lived connections and a migration for unsigned v1.2.4 records."""

    def __init__(self, path="educhaintrust_evidence.sqlite3"):
        if path == ":memory:":
            raise ValueError("a file path is required for short-lived SQLite connections")
        self.path = str(path)
        self._execute("CREATE TABLE IF NOT EXISTS evidence("
                      "tx TEXT PRIMARY KEY,digest TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,"
                      "issuer TEXT,created_at TEXT,revoked_at TEXT,revoked_by TEXT)")
        with closing(self._connect()) as con:
            with con:
                # Serialize the schema inspection and alteration across processes.
                con.execute("BEGIN IMMEDIATE")
                columns = {row[1] for row in con.execute("PRAGMA table_info(evidence)")}
                for column in ("issuer", "created_at", "revoked_at", "revoked_by", "credential_id"):
                    if column not in columns:
                        con.execute(f"ALTER TABLE evidence ADD COLUMN {column} TEXT")
                con.execute("CREATE UNIQUE INDEX IF NOT EXISTS evidence_digest_issuer_unique "
                            "ON evidence(digest,issuer) WHERE issuer IS NOT NULL")
                con.execute("CREATE UNIQUE INDEX IF NOT EXISTS evidence_id_issuer_unique ON evidence(issuer,credential_id) WHERE credential_id IS NOT NULL")
            # Historical rows retain NULL IDs: hashes cannot recover original IDs.

    def _connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def _execute(self, sql, params=()):
        with closing(self._connect()) as con:
            with con:
                cur = con.execute(sql, params)
                return cur.rowcount

    def _fetchone(self, sql, params=()):
        with closing(self._connect()) as con:
            return con.execute(sql, params).fetchone()

    def anchor(self, data_hash, issuer, credential_id=None, legacy_digests=()):
        if not isinstance(data_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", data_hash):
            raise ValueError("data_hash must be a lowercase SHA-256 hex digest")
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("issuer is required")
        tx = "sqlite:" + uuid.uuid4().hex
        if credential_id is not None and (not isinstance(credential_id, str) or not credential_id):
            raise ValueError("credential_id must be non-empty")
        digests = set(legacy_digests) | {data_hash}
        if any(not isinstance(d, str) or not re.fullmatch(r"[0-9a-f]{64}", d) for d in digests):
            raise ValueError("invalid legacy digest")
        try:
            with closing(self._connect()) as con:
                with con:
                    con.execute("BEGIN IMMEDIATE")
                    # Check all equivalent old encodings atomically with insertion.
                    if any(con.execute("SELECT 1 FROM evidence WHERE issuer=? AND digest=?", (issuer, d)).fetchone() for d in digests):
                        raise ValueError("credential already anchored; revoked evidence cannot be reactivated")
                    con.execute("INSERT INTO evidence(tx,digest,revoked,issuer,created_at,credential_id) VALUES(?,?,0,?,?,?)",
                                (tx, data_hash, issuer, _now(), credential_id))
        except sqlite3.IntegrityError as exc:
            raise ValueError("credential already anchored; revoked evidence cannot be reactivated") from exc
        return tx

    def record(self, tx_hash):
        row = self._fetchone("SELECT digest,issuer,revoked,created_at,revoked_at,revoked_by,credential_id FROM evidence WHERE tx=?", (tx_hash,))
        if row is None:
            return None
        return {"digest": row[0], "issuer": row[1], "status": "revoked" if row[2] else "active",
                "created_at": row[3], "revoked_at": row[4], "revoked_by": row[5], "credential_id": row[6]}

    def verify(self, tx_hash, data_hash):
        row = self.record(tx_hash)
        return bool(row and row["digest"] == data_hash and row["status"] == "active")

    def revoke(self, tx_hash, actor):
        if not isinstance(actor, str) or not actor:
            raise ValueError("revocation actor is required")
        return self._execute("UPDATE evidence SET revoked=1,revoked_at=?,revoked_by=? "
                             "WHERE tx=? AND revoked=0", (_now(), actor, tx_hash)) == 1

    def status(self, tx_hash):
        record = self.record(tx_hash)
        return record["status"] if record else "unknown"

    def close(self):
        """Compatibility hook; every connection is already closed."""
        return None
