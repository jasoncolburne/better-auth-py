"""Cryptographic interfaces for better-auth.

This module defines protocols for hashing, nonce generation, verification,
and signing operations.
"""

from __future__ import annotations

from typing import Protocol


class IHasher(Protocol):
    """Interface for cryptographic hashing operations."""

    async def sum(self, message: str) -> str:
        """Compute the hash of a message.

        Args:
            message: The message to hash.

        Returns:
            The hash as a string.
        """
        ...


class INoncer(Protocol):
    """Interface for nonce generation."""

    async def generate128(self) -> str:
        """Generate a nonce with 128 bits of entropy.

        Returns:
            A nonce string with 128 bits of entropy.
        """
        ...


class IVerifier(Protocol):
    """Interface for signature verification."""

    async def verify(self, message: str, signature: str, public_key: str) -> None:
        """Verify a signature against a message using a public key.

        This is typically just a verification algorithm.

        Args:
            message: The message that was signed.
            signature: The signature to verify.
            public_key: The public key to use for verification.

        Raises:
            Exception: When verification fails.
        """
        ...


class IVerificationKey(Protocol):
    """Interface for verification key operations."""

    async def public(self) -> str:
        """Fetch the public key.

        Returns:
            The public key as a string.
        """
        ...

    def verifier(self) -> IVerifier:
        """Return the algorithm verifier.

        Returns:
            The verifier instance.
        """
        ...

    async def verify(self, message: str, signature: str) -> None:
        """Verify a signature using the verifier and public key.

        This is a convenience method.

        Args:
            message: The message that was signed.
            signature: The signature to verify.

        Raises:
            Exception: When verification fails.
        """
        ...


class ISigningKey(IVerificationKey, Protocol):
    """Interface for signing key operations.

    Extends IVerificationKey with signing capabilities.
    """

    async def identity(self) -> str:
        """Fetch the identity (same as public key for secp256r1).

        Returns:
            The identity as a string.
        """
        ...

    async def sign(self, message: str) -> str:
        """Sign a message with the key it represents.

        The key could be backed by an HSM for instance.

        Args:
            message: The message to sign.

        Returns:
            The signature as a string.
        """
        ...
