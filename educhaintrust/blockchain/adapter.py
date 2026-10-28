# SPDX-License-Identifier: MIT
from abc import ABC, abstractmethod
class BlockchainAdapter(ABC):
    @abstractmethod
    def anchor(self, data_hash: str, issuer: str) -> str: raise NotImplementedError
    @abstractmethod
    def verify(self, tx_hash: str, data_hash: str) -> bool: raise NotImplementedError
    @abstractmethod
    def record(self, tx_hash: str) -> dict | None: raise NotImplementedError
    @abstractmethod
    def status(self, tx_hash: str) -> str: raise NotImplementedError
    @abstractmethod
    def revoke(self, tx_hash: str, actor: str) -> bool: raise NotImplementedError
