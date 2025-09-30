"""Access token refresh message types for better-auth.

This module defines the request and response message types for refreshing
access tokens before they expire.
"""

from __future__ import annotations

from typing import Any, Dict

from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ServerResponse


class RefreshAccessTokenRequest(ClientRequest[Dict[str, Any]]):
    """Request message for refreshing an access token.

    This message requests a new access token using an existing (but not expired)
    access token along with the current public key and rotation hash.

    The request payload structure is:
    {
        "access": {
            "publicKey": "<public_key>",
            "rotationHash": "<rotation_hash>",
            "token": "<current_access_token>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and refresh request data.
        signature: Optional cryptographic signature.
    """

    def __init__(self, request: Dict[str, Any], nonce: str) -> None:
        """Initialize a refresh access token request.

        Args:
            request: Dictionary containing access data with keys:
                - access: Dict containing publicKey, rotationHash, and token.
            nonce: The nonce for replay protection.
        """
        super().__init__(request, nonce)

    @staticmethod
    def parse(message: str) -> RefreshAccessTokenRequest:
        """Parse a serialized refresh access token request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RefreshAccessTokenRequest instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, RefreshAccessTokenRequest)


class RefreshAccessTokenResponse(ServerResponse[Dict[str, Any]]):
    """Response message for access token refresh.

    This message provides the new access token that replaces the previous one.

    The response payload structure is:
    {
        "access": {
            "token": "<new_access_token>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and the new access token.
        signature: Optional cryptographic signature.
    """

    def __init__(self, response: Dict[str, Any], response_key_hash: str, nonce: str) -> None:
        """Initialize a refresh access token response.

        Args:
            response: Dictionary containing the new access token.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> RefreshAccessTokenResponse:
        """Parse a serialized refresh access token response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RefreshAccessTokenResponse instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, RefreshAccessTokenResponse)
