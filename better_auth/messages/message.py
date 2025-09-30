"""Base message classes for better-auth.

This module defines the foundational message classes that support
serialization, signing, and verification.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from better_auth.interfaces.crypto import ISigningKey, IVerifier


class SerializableMessage(ABC):
    """Abstract base class for messages that can be serialized.

    All message types must be able to convert themselves to a string
    representation for transmission.
    """

    @abstractmethod
    async def serialize(self) -> str:
        """Serialize the message to a string.

        Returns:
            The serialized message as a JSON string.

        Raises:
            Exception: If serialization fails.
        """
        ...


class SignableMessage(SerializableMessage):
    """Abstract base class for messages that can be signed and verified.

    This class extends SerializableMessage with cryptographic capabilities,
    allowing messages to be signed with a private key and verified with a
    public key.

    Attributes:
        payload: The message payload to be signed. Must be set by subclasses.
        signature: The cryptographic signature of the payload.
    """

    def __init__(self) -> None:
        """Initialize a signable message."""
        self.payload: Optional[Dict[str, Any]] = None
        self.signature: Optional[str] = None

    def compose_payload(self) -> str:
        """Compose the payload into a JSON string for signing.

        Returns:
            The JSON-serialized payload.

        Raises:
            RuntimeError: If payload is not defined.
        """
        if self.payload is None:
            raise RuntimeError("payload not defined")

        return json.dumps(self.payload, separators=(",", ":"), sort_keys=False)

    async def serialize(self) -> str:
        """Serialize the message including its signature.

        Returns:
            The serialized message as a JSON string with payload and signature.

        Raises:
            RuntimeError: If signature is None.
        """
        if self.signature is None:
            raise RuntimeError("null signature")

        # Manually construct JSON to maintain exact serialization order
        # Format: {"payload":<payload>,"signature":"<signature>"}
        payload_str = self.compose_payload()
        return f'{{"payload":{payload_str},"signature":"{self.signature}"}}'

    async def sign(self, signer: ISigningKey) -> None:
        """Sign the message payload with a signing key.

        Args:
            signer: The signing key to use for signing.

        Raises:
            RuntimeError: If payload is not defined.
        """
        self.signature = await signer.sign(self.compose_payload())

    async def verify(self, verifier: IVerifier, public_key: str) -> None:
        """Verify the message signature using a verifier and public key.

        Args:
            verifier: The verifier to use for signature verification.
            public_key: The public key to verify against.

        Raises:
            RuntimeError: If signature is None.
            Exception: If verification fails.
        """
        if self.signature is None:
            raise RuntimeError("null signature")

        await verifier.verify(self.compose_payload(), self.signature, public_key)
