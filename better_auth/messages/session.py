"""Session management message types for better-auth.

This module defines the request and response message types for session
operations including requesting, creating, and refreshing sessions.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from better_auth.messages.message import SerializableMessage
from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ServerResponse


class RequestSessionRequest(SerializableMessage):
    """Request message to start the authentication process.

    This message initiates authentication by providing an access nonce and
    the identity to authenticate. This is a serializable message that doesn't
    require signing.

    The payload structure is:
    {
        "access": {
            "nonce": "<nonce>"
        },
        "request": {
            "authentication": {
                "identity": "<identity>"
            }
        }
    }

    Attributes:
        payload: Dictionary containing access and authentication request data.
    """

    def __init__(self, payload: Dict[str, Dict[str, Any]]) -> None:
        """Initialize a start authentication request.

        Args:
            payload: Dictionary containing the request data with keys:
                - access: Dict containing nonce.
                - request: Dict containing authentication with identity.
        """
        super().__init__()
        self.payload = payload

    async def serialize(self) -> str:
        """Serialize the message to a JSON string.

        Returns:
            The serialized message as a JSON string.
        """
        return json.dumps({"payload": self.payload}, separators=(",", ":"), sort_keys=False)

    @staticmethod
    def parse(message: str) -> RequestSessionRequest:
        """Parse a serialized start authentication request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RequestSessionRequest instance with the parsed data.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        json_data = json.loads(message)
        return RequestSessionRequest(json_data["payload"])


class RequestSessionResponse(ServerResponse[Dict[str, Any]]):
    """Response message for starting authentication.

    This message provides the authentication nonce that must be signed
    by the client to complete authentication.

    The response payload structure is:
    {
        "authentication": {
            "nonce": "<authentication_nonce>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and authentication nonce.
        signature: Optional cryptographic signature.
    """

    def __init__(self, response: Dict[str, Any], response_key_hash: str, nonce: str) -> None:
        """Initialize a start authentication response.

        Args:
            response: Dictionary containing the authentication nonce.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> RequestSessionResponse:
        """Parse a serialized start authentication response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RequestSessionResponse instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, RequestSessionResponse)


class CreateSessionRequest(ClientRequest[Dict[str, Any]]):
    """Request message to complete the authentication process.

    This message completes authentication by providing the signed authentication
    nonce along with access credentials (public key and rotation hash).

    The request payload structure is:
    {
        "access": {
            "publicKey": "<public_key>",
            "rotationHash": "<rotation_hash>"
        },
        "authentication": {
            "device": "<device_id>",
            "nonce": "<signed_authentication_nonce>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and authentication completion data.
        signature: Optional cryptographic signature.
    """

    def __init__(self, request: Dict[str, Any], nonce: str) -> None:
        """Initialize a finish authentication request.

        Args:
            request: Dictionary containing access and authentication data with keys:
                - access: Dict containing publicKey and rotationHash.
                - authentication: Dict containing device and nonce.
            nonce: The nonce for replay protection.
        """
        super().__init__(request, nonce)

    @staticmethod
    def parse(message: str) -> CreateSessionRequest:
        """Parse a serialized finish authentication request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new CreateSessionRequest instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, CreateSessionRequest)


class CreateSessionResponse(ServerResponse[Dict[str, Any]]):
    """Response message for completing authentication.

    This message provides the access token that can be used for subsequent
    authenticated requests.

    The response payload structure is:
    {
        "access": {
            "token": "<access_token>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and the access token.
        signature: Optional cryptographic signature.
    """

    def __init__(self, response: Dict[str, Any], response_key_hash: str, nonce: str) -> None:
        """Initialize a finish authentication response.

        Args:
            response: Dictionary containing the access token.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> CreateSessionResponse:
        """Parse a serialized finish authentication response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new CreateSessionResponse instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, CreateSessionResponse)


class RefreshSessionRequest(ClientRequest[Dict[str, Any]]):
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
    def parse(message: str) -> RefreshSessionRequest:
        """Parse a serialized refresh access token request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RefreshSessionRequest instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, RefreshSessionRequest)


class RefreshSessionResponse(ServerResponse[Dict[str, Any]]):
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
    def parse(message: str) -> RefreshSessionResponse:
        """Parse a serialized refresh access token response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RefreshSessionResponse instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, RefreshSessionResponse)
