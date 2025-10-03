"""Storage interfaces for better-auth.

This module defines protocols for client and server storage operations,
including key stores, nonce stores, and time-lock stores.
"""

from __future__ import annotations

from typing import Protocol

from .crypto import ISigningKey


# Client interfaces


class IClientValueStore(Protocol):
    """Interface for client-side value storage."""

    async def store(self, value: str) -> None:
        """Store a value.

        Args:
            value: The value to store.
        """
        ...

    async def get(self) -> str:
        """Get the stored value.

        Returns:
            The stored value.

        Raises:
            Exception: If nothing has been stored.
        """
        ...


class IClientRotatingKeyStore(Protocol):
    """Interface for client-side rotating key storage."""

    async def initialize(self, extra_data: str | None = None) -> tuple[str, str, str]:
        """Initialize the key store and return identity information.

        Args:
            extra_data: Optional extra data for initialization.

        Returns:
            A tuple of (identity, public_key, rotation_hash).
        """
        ...

    async def rotate(self) -> tuple[str, str]:
        """Rotate the keys.

        Returns:
            A tuple of (public_key, rotation_hash).

        Raises:
            Exception: If no keys exist.
        """
        ...

    async def signer(self) -> ISigningKey:
        """Get a signing key handle.

        Returns:
            A signing key instance.
        """
        ...


# Server interfaces


class IServerAuthenticationNonceStore(Protocol):
    """Interface for server-side authentication nonce storage."""

    @property
    def lifetime_in_seconds(self) -> int:
        """The lifetime of nonces in seconds."""
        ...

    async def generate(self, identity: str) -> str:
        """Generate a nonce for an identity.

        Probably want to implement exponential backoff delay on generation,
        per identity.

        Args:
            identity: The identity to generate a nonce for.

        Returns:
            The generated nonce.
        """
        ...

    async def validate(self, nonce: str) -> str:
        """Validate a nonce and return the associated identity.

        Args:
            nonce: The nonce to validate.

        Returns:
            The identity associated with the nonce.

        Raises:
            Exception: If nonce is not in the store.
        """
        ...


class IServerAuthenticationKeyStore(Protocol):
    """Interface for server-side authentication key storage."""

    async def register(
        self,
        identity: str,
        device: str,
        public_key: str,
        rotation_hash: str,
        existing_identity: bool,
    ) -> None:
        """Register a new key for an identity and device.

        Args:
            identity: The identity to register.
            device: The device identifier.
            public_key: The public key to register.
            rotation_hash: The rotation hash for key rotation.
            existing_identity: Whether the identity already exists.

        Raises:
            Exception: If identity exists bool is set and identity is not found
                in data store.
            Exception: If identity exists bool is unset and identity is found
                in data store.
            Exception: If identity and device combination already exists.
        """
        ...

    async def rotate(self, identity: str, device: str, public_key: str, rotation_hash: str) -> None:
        """Rotate a key for an identity and device.

        Args:
            identity: The identity to rotate keys for.
            device: The device identifier.
            current: The current public key.
            rotation_hash: The new rotation hash.

        Raises:
            Exception: If identity and device combination does not exist.
            Exception: If previous next hash doesn't match current hash.
        """
        ...

    async def public(self, identity: str, device: str) -> str:
        """Get the public key for an identity and device.

        Args:
            identity: The identity to get the key for.
            device: The device identifier.

        Returns:
            The encoded public key.
        """
        ...

    async def revoke_device(self, identity: str, device: str) -> None:
        """Revoke a specific device for an identity.

        Args:
            identity: The identity to revoke the device for.
            device: The device identifier to revoke.

        Raises:
            Exception: If identity and device combination does not exist.
        """
        ...

    async def revoke_devices(self, identity: str) -> None:
        """Revoke all devices for an identity.

        Args:
            identity: The identity to revoke all devices for.

        Raises:
            Exception: If identity does not exist.
        """
        ...


class IServerRecoveryHashStore(Protocol):
    """Interface for server-side recovery hash storage."""

    async def register(self, identity: str, key_hash: str) -> None:
        """Register a recovery hash for an identity.

        Args:
            identity: The identity to register the hash for.
            key_hash: The recovery key hash.
        """
        ...

    async def rotate(self, identity: str, old_hash: str, new_hash: str) -> None:
        """Validate a recovery hash for an identity.

        Args:
            identity: The identity to validate.
            key_hash: The recovery key hash to validate.

        Raises:
            Exception: If not found.
            Exception: If hash does not match.
        """
        ...


class IServerTimeLockStore(Protocol):
    """Interface for server-side time-lock storage."""

    @property
    def lifetime_in_seconds(self) -> int:
        """The lifetime of time-locked values in seconds."""
        ...

    async def reserve(self, value: str) -> None:
        """Reserve a value in the time-lock store.

        Args:
            value: The value to reserve.

        Raises:
            Exception: If value is still alive in the store.
        """
        ...
