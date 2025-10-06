from typing import Dict

from better_auth.interfaces.crypto import IVerificationKey
from better_auth.interfaces.storage import IVerificationKeyStore


class VerificationKeyStore(IVerificationKeyStore):
    def __init__(self) -> None:
        self._keys: Dict[str, IVerificationKey] = {}

    def add(self, identity: str, key: IVerificationKey) -> None:
        self._keys[identity] = key

    async def get(self, identity: str) -> IVerificationKey:
        if identity not in self._keys:
            raise ValueError(f"Key not found for identity: {identity}")
        return self._keys[identity]
