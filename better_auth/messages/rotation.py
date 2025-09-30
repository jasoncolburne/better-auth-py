"""Authentication key rotation message types for better-auth.

This module defines the request and response message types for rotating
authentication keys for enhanced security.
"""

from __future__ import annotations

from typing import Any, Dict

from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ServerResponse


class RotateAuthenticationKeyRequest(ClientRequest[Dict[str, Any]]):
    """Request message for rotating authentication keys.

    This message initiates key rotation by providing new authentication
    credentials including a new public key and rotation hash for a specific
    device.

    The request payload structure is:
    {
        "authentication": {
            "device": "<device_id>",
            "identity": "<identity>",
            "publicKey": "<new_public_key>",
            "rotationHash": "<new_rotation_hash>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and authentication data.
        signature: Optional cryptographic signature.
    """

    def __init__(self, request: Dict[str, Any], nonce: str) -> None:
        """Initialize a rotate authentication key request.

        Args:
            request: Dictionary containing authentication data with keys:
                - authentication: Dict containing device, identity, publicKey,
                  and rotationHash.
            nonce: The nonce for replay protection.
        """
        super().__init__(request, nonce)

    @staticmethod
    def parse(message: str) -> RotateAuthenticationKeyRequest:
        """Parse a serialized rotate authentication key request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RotateAuthenticationKeyRequest instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, RotateAuthenticationKeyRequest)


class RotateAuthenticationKeyResponse(ServerResponse[Dict[str, Any]]):
    """Response message for key rotation.

    This message confirms successful key rotation. The response payload
    is an empty dictionary.

    Attributes:
        payload: Dictionary containing access metadata and empty response.
        signature: Optional cryptographic signature.
    """

    def __init__(self, response: Dict[str, Any], response_key_hash: str, nonce: str) -> None:
        """Initialize a rotate authentication key response.

        Args:
            response: Empty dictionary response payload.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> RotateAuthenticationKeyResponse:
        """Parse a serialized rotate authentication key response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RotateAuthenticationKeyResponse instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, RotateAuthenticationKeyResponse)
