# SPDX-License-Identifier: MIT
import uuid

class DIDManager:
    def create_identity(self, entity_type:str, name:str, institution:str)->dict:
        if any(not isinstance(value, str) or not value.strip() for value in (entity_type, name, institution)):
            raise ValueError("identity fields must be non-empty strings")
        return {
            "did":"did:edu:"+uuid.uuid4().hex,
            "type":entity_type,
            "name":name,
            "institution":institution
        }
