"""Encoding and timestamp interfaces for better-auth.

This module defines protocols for timestamp operations, token encoding/decoding,
and identity verification.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class ITimestamper(Protocol):
    """Interface for timestamp operations."""

    def format(self, when: datetime) -> str:
        """Format a datetime object as a string.

        Args:
            when: The datetime to format.

        Returns:
            The formatted timestamp string.
        """
        ...

    def parse(self, when: str | datetime) -> datetime:
        """Parse a timestamp string or datetime into a datetime object.

        Args:
            when: The timestamp string or datetime to parse.

        Returns:
            The parsed datetime object.
        """
        ...

    def now(self) -> datetime:
        """Get the current datetime.

        Returns:
            The current datetime.
        """
        ...


class ITokenEncoder(Protocol):
    """Interface for token encoding and decoding operations."""

    async def encode(self, object: str) -> str:
        """Encode an object string into a token.

        Args:
            object: The object string to encode.

        Returns:
            The encoded token.
        """
        ...

    async def decode(self, raw_token: str) -> str:
        """Decode a raw token into an object string.

        Args:
            raw_token: The raw token to decode.

        Returns:
            The decoded object string.
        """
        ...


class IIdentityVerifier(Protocol):
    """Interface for identity verification operations."""

    async def verify(
        self,
        identity: str,
        public_key: str,
        rotation_hash: str,
        extra_data: str | None = None,
    ) -> None:
        """Verify an identity with its public key and rotation hash.

        Args:
            identity: The identity to verify.
            public_key: The public key associated with the identity.
            rotation_hash: The rotation hash for key rotation.
            extra_data: Optional extra data for verification.

        Raises:
            Exception: When verification fails.
        """
        ...
