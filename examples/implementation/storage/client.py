"""Client-side storage implementations for better-auth.

This module provides in-memory implementations of client storage interfaces
for testing and reference purposes.
"""

from __future__ import annotations

from typing import Optional

from better_auth.interfaces.crypto import IHasher, ISigningKey
from better_auth.interfaces.storage import IClientRotatingKeyStore, IClientValueStore

from ..crypto.hash import Hasher
from ..crypto.secp256r1 import Secp256r1


class ClientRotatingKeyStore(IClientRotatingKeyStore):
    """In-memory implementation of rotating key storage for clients.

    This class manages three signing keys (current, next, and future) and supports
    key rotation with hash chain validation. The identity is derived from the
    current public key, next key's rotation hash, and optional extra data.

    Attributes:
        _current_key: The current signing key used for authentication.
        _next_key: The next signing key to be used after rotation.
        _future_key: The future signing key, prepared during next() operation.
        _hasher: Hasher instance for computing rotation hashes.
    """

    def __init__(self) -> None:
        """Initialize the rotating key store."""
        self._current_key: Optional[ISigningKey] = None
        self._next_key: Optional[ISigningKey] = None
        self._future_key: Optional[ISigningKey] = None
        self._hasher: IHasher = Hasher()

    async def initialize(self, extra_data: str | None = None) -> tuple[str, str, str]:
        """Initialize the key store and generate initial key pair.

        Generates both current and next signing keys, computes the rotation hash
        of the next key's public key, and derives an identity from the current
        public key, rotation hash, and optional extra data.

        Args:
            extra_data: Optional extra data to include in identity computation.

        Returns:
            A tuple containing:
                - identity: Hash of (public_key + rotation_hash + extra_data)
                - public_key: CESR-encoded current public key
                - rotation_hash: Hash of the next public key

        Raises:
            Exception: If key generation fails.
        """
        current = Secp256r1()
        next_key = Secp256r1()

        await current.generate()
        await next_key.generate()

        self._current_key = current
        self._next_key = next_key

        suffix = ""
        if extra_data is not None:
            suffix = extra_data

        public_key = await current.public()
        rotation_hash = await self._hasher.sum(await next_key.public())
        identity = await self._hasher.sum(public_key + rotation_hash + suffix)

        return (identity, public_key, rotation_hash)

    async def next(self) -> tuple[ISigningKey, str]:
        """Get the next signing key and rotation hash.

        This prepares the future key if it doesn't exist yet, and returns
        the next key along with the hash of the future key.

        Returns:
            A tuple containing:
                - key: The next signing key to use
                - rotation_hash: Hash of the future public key

        Raises:
            RuntimeError: If initialize() has not been called first.
        """
        if self._next_key is None:
            raise RuntimeError("call initialize() first")

        if self._future_key is None:
            key = Secp256r1()
            await key.generate()
            self._future_key = key

        rotation_hash = await self._hasher.sum(await self._future_key.public())

        return (self._next_key, rotation_hash)

    async def rotate(self) -> None:
        """Commit the key rotation.

        Promotes next key to current, future key to next, and clears future key.

        Raises:
            RuntimeError: If initialize() or next() has not been called first.
        """
        if self._next_key is None:
            raise RuntimeError("call initialize() first")

        if self._future_key is None:
            raise RuntimeError("call next() first")

        self._current_key = self._next_key
        self._next_key = self._future_key
        self._future_key = None

    async def signer(self) -> ISigningKey:
        """Get the current signing key for authentication.

        Returns:
            The current signing key instance.

        Raises:
            RuntimeError: If initialize() has not been called first.
        """
        if self._current_key is None:
            raise RuntimeError("call initialize() first")

        return self._current_key


class ClientValueStore(IClientValueStore):
    """In-memory implementation of value storage for clients.

    This class provides simple key-value storage for a single string value,
    typically used for storing session tokens or other client-side state.

    Attributes:
        _value: The stored value, if any.
    """

    def __init__(self) -> None:
        """Initialize the value store."""
        self._value: Optional[str] = None

    async def store(self, value: str) -> None:
        """Store a value.

        Args:
            value: The value to store.
        """
        self._value = value

    async def get(self) -> str:
        """Get the stored value.

        Returns:
            The stored value.

        Raises:
            RuntimeError: If no value has been stored.
        """
        if self._value is None:
            raise RuntimeError("nothing to get")

        return self._value
