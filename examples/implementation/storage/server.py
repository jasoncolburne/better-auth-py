"""Server-side storage implementations for better-auth.

This module provides in-memory implementations of server storage interfaces
for testing and reference purposes.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, Set

from better_auth.interfaces.crypto import IHasher, INoncer
from better_auth.interfaces.storage import (
    IServerAuthenticationKeyStore,
    IServerAuthenticationNonceStore,
    IServerRecoveryHashStore,
    IServerTimeLockStore,
)

from ..crypto.hash import Hasher
from ..crypto.nonce import Noncer


class ServerAuthenticationKeyStore(IServerAuthenticationKeyStore):
    """In-memory implementation of authentication key storage for servers.

    This class manages public keys and rotation hashes for client devices,
    supporting key rotation with forward secrecy validation. Keys are indexed
    by identity+device combinations.

    Attributes:
        _data_by_token: Maps (identity+device) to (public_key, rotation_hash) tuples.
        _hasher: Hasher instance for validating rotation hashes.
        _identities: Set of registered identity strings.
    """

    def __init__(self) -> None:
        """Initialize the authentication key store."""
        self._data_by_token: Dict[str, tuple[str, str]] = {}
        self._hasher: IHasher = Hasher()
        self._identities: Set[str] = set()

    async def register(
        self,
        identity: str,
        device: str,
        public_key: str,
        rotation_hash: str,
        existing_identity: bool,
    ) -> None:
        """Register a new device key for an identity.

        Validates that the identity existence matches the existing_identity flag
        and that the identity+device combination doesn't already exist.

        Args:
            identity: The identity to register the key for.
            device: The device identifier.
            public_key: The CESR-encoded public key.
            rotation_hash: The rotation hash for key rotation validation.
            existing_identity: Whether the identity should already exist.

        Raises:
            RuntimeError: If identity already registered but existing_identity is False.
            RuntimeError: If identity not found but existing_identity is True.
            RuntimeError: If identity+device combination already exists.
        """
        has_identity = identity in self._identities

        if not existing_identity and has_identity:
            raise RuntimeError("identity already registered")

        if existing_identity and not has_identity:
            raise RuntimeError("identity not found")

        token = identity + device
        bundle = self._data_by_token.get(token)

        if bundle is not None:
            raise RuntimeError("already exists")

        self._identities.add(identity)
        self._data_by_token[token] = (public_key, rotation_hash)

    async def rotate(self, identity: str, device: str, current: str, rotation_hash: str) -> None:
        """Rotate a key for an identity and device.

        Validates that the current public key matches the hash of the previously
        stored rotation hash, ensuring forward secrecy in the key rotation chain.

        Args:
            identity: The identity to rotate keys for.
            device: The device identifier.
            current: The new current public key.
            rotation_hash: The new rotation hash.

        Raises:
            RuntimeError: If identity+device combination not found.
            RuntimeError: If the current key hash doesn't match the stored rotation hash.
        """
        token = identity + device
        bundle = self._data_by_token.get(token)

        if bundle is None:
            raise RuntimeError("not found")

        cesr_hash = await self._hasher.sum(current)

        if bundle[1] != cesr_hash:
            raise RuntimeError("invalid forward secret")

        self._data_by_token[token] = (current, rotation_hash)

    async def public(self, identity: str, device: str) -> str:
        """Get the current public key for an identity and device.

        Args:
            identity: The identity to get the key for.
            device: The device identifier.

        Returns:
            The CESR-encoded current public key.

        Raises:
            RuntimeError: If identity+device combination not found.
        """
        token = identity + device
        bundle = self._data_by_token.get(token)

        if bundle is None:
            raise RuntimeError("not found")

        return bundle[0]

    async def revoke_device(self, identity: str, device: str) -> None:
        """Revoke a specific device for an identity.

        Args:
            identity: The identity to revoke the device for.
            device: The device identifier to revoke.

        Raises:
            RuntimeError: If identity+device combination not found.
        """
        token = identity + device
        bundle = self._data_by_token.get(token)

        if bundle is None:
            raise RuntimeError("not found")

        del self._data_by_token[token]

    async def revoke_devices(self, identity: str) -> None:
        """Revoke all devices for an identity.

        Args:
            identity: The identity to revoke all devices for.

        Raises:
            RuntimeError: If identity not found.
        """
        if identity not in self._identities:
            raise RuntimeError("identity not found")

        # Remove all device tokens for this identity
        tokens_to_remove = [token for token in self._data_by_token if token.startswith(identity)]
        for token in tokens_to_remove:
            del self._data_by_token[token]


class ServerRecoveryHashStore(IServerRecoveryHashStore):
    """In-memory implementation of recovery hash storage for servers.

    This class manages recovery key hashes for identities, used for account
    recovery mechanisms. Each identity can have one recovery hash.

    Attributes:
        _data_by_identity: Maps identity strings to recovery hash strings.
    """

    def __init__(self) -> None:
        """Initialize the recovery hash store."""
        self._data_by_identity: Dict[str, str] = {}

    async def register(self, identity: str, key_hash: str) -> None:
        """Register a recovery hash for an identity.

        Args:
            identity: The identity to register the hash for.
            key_hash: The recovery key hash.

        Raises:
            RuntimeError: If identity already has a recovery hash.
        """
        stored = self._data_by_identity.get(identity)

        if stored is not None:
            raise RuntimeError("already exists")

        self._data_by_identity[identity] = key_hash

    async def validate(self, identity: str, key_hash: str) -> None:
        """Validate a recovery hash for an identity.

        Args:
            identity: The identity to validate.
            key_hash: The recovery key hash to validate.

        Raises:
            RuntimeError: If identity not found.
            RuntimeError: If hash doesn't match.
        """
        stored = self._data_by_identity.get(identity)

        if stored is None:
            raise RuntimeError("not found")

        if stored != key_hash:
            raise RuntimeError("incorrect hash")


class ServerAuthenticationNonceStore(IServerAuthenticationNonceStore):
    """In-memory implementation of authentication nonce storage for servers.

    This class generates and validates time-limited nonces for authentication
    challenges. Nonces expire after a configurable lifetime.

    Attributes:
        _lifetime_in_seconds: The lifetime of nonces in seconds.
        _data_by_nonce: Maps nonce strings to identity strings.
        _nonce_expirations: Maps nonce strings to expiration timestamps.
        _noncer: Noncer instance for generating random nonces.
    """

    def __init__(self, lifetime_in_seconds: int) -> None:
        """Initialize the authentication nonce store.

        Args:
            lifetime_in_seconds: How long nonces remain valid.
        """
        self._lifetime_in_seconds = lifetime_in_seconds
        self._data_by_nonce: Dict[str, str] = {}
        self._nonce_expirations: Dict[str, datetime] = {}
        self._noncer: INoncer = Noncer()

    @property
    def lifetime_in_seconds(self) -> int:
        """The lifetime of nonces in seconds.

        Returns:
            The configured lifetime in seconds.
        """
        return self._lifetime_in_seconds

    async def generate(self, identity: str) -> str:
        """Generate a nonce for an identity.

        Creates a new random nonce, associates it with the identity, and sets
        its expiration time based on the configured lifetime.

        Args:
            identity: The identity to generate a nonce for.

        Returns:
            The CESR-encoded generated nonce.
        """
        expiration = datetime.now() + timedelta(seconds=self._lifetime_in_seconds)

        nonce = await self._noncer.generate128()
        self._data_by_nonce[nonce] = identity
        self._nonce_expirations[nonce] = expiration

        return nonce

    async def validate(self, nonce: str) -> str:
        """Validate a nonce and return the associated identity.

        Checks that the nonce exists and has not expired.

        Args:
            nonce: The nonce to validate.

        Returns:
            The identity associated with the nonce.

        Raises:
            RuntimeError: If nonce not found.
            RuntimeError: If nonce has expired.
        """
        identity = self._data_by_nonce.get(nonce)
        expiration = self._nonce_expirations.get(nonce)

        if identity is None or expiration is None:
            raise RuntimeError("not found")

        now = datetime.now()

        if now > expiration:
            raise RuntimeError("expired nonce")

        return identity


class ServerTimeLockStore(IServerTimeLockStore):
    """In-memory implementation of time-lock storage for servers.

    This class implements rate limiting by reserving values for a configurable
    time period. Attempts to reserve a value that is already reserved and not
    yet expired will fail.

    Attributes:
        _lifetime_in_seconds: The lifetime of reservations in seconds.
        _nonces: Maps reserved values to their expiration timestamps.
    """

    def __init__(self, lifetime_in_seconds: int) -> None:
        """Initialize the time-lock store.

        Args:
            lifetime_in_seconds: How long values remain reserved.
        """
        self._lifetime_in_seconds = lifetime_in_seconds
        self._nonces: Dict[str, datetime] = {}

    @property
    def lifetime_in_seconds(self) -> int:
        """The lifetime of time-locked values in seconds.

        Returns:
            The configured lifetime in seconds.
        """
        return self._lifetime_in_seconds

    async def reserve(self, value: str) -> None:
        """Reserve a value in the time-lock store.

        If the value has been reserved before, checks if it has expired.
        Only allows reservation if the value is not currently reserved.

        Args:
            value: The value to reserve.

        Raises:
            RuntimeError: If value is still reserved (not yet expired).
        """
        valid_at = self._nonces.get(value)

        if valid_at is not None:
            now = datetime.now()
            if now < valid_at:
                raise RuntimeError("value reserved too recently")

        new_valid_at = datetime.now() + timedelta(seconds=self._lifetime_in_seconds)

        self._nonces[value] = new_valid_at
