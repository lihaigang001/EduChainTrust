# SPDX-License-Identifier: MIT
import uuid
from .adapter import BlockchainAdapter
class MockBlockchain(BlockchainAdapter):
    def __init__(self): self.ledger = {}
    def anchor(self, data_hash: str, issuer: str) -> str:
        if not issuer: raise ValueError("issuer is required")
        if any(row["digest"]==data_hash and row["issuer"]==issuer for row in self.ledger.values()):
            raise ValueError("credential already anchored")
        tx = "0x" + uuid.uuid4().hex
        self.ledger[tx] = {"digest":data_hash,"issuer":issuer,"status":"active"}
        return tx
    def verify(self, tx_hash: str, data_hash: str) -> bool:
        row=self.ledger.get(tx_hash)
        return bool(row and row["status"]=="active" and row["digest"]==data_hash)
    def record(self, tx_hash: str):
        row=self.ledger.get(tx_hash)
        return dict(row) if row else None
    def status(self, tx_hash: str) -> str:
        row=self.ledger.get(tx_hash)
        return row["status"] if row else "unknown"
    def revoke(self, tx_hash: str, actor: str) -> bool:
        row=self.ledger.get(tx_hash)
        if not row or row["status"]!="active": return False
        row["status"]="revoked"
        row["revoked_by"]=actor
        return True
