"""Device linking message types for better-auth.

This module defines message types for linking additional devices to an
existing account, including the signable link container.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from better_auth.messages.message import SignableMessage
from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ServerResponse


class LinkContainer(SignableMessage):
    """Signable container for device link information.

    This message contains the authentication credentials for a new device
    being linked to an existing account. It must be signed by an existing
    device's private key.

    The payload structure is:
    {
        "authentication": {
            "device": "<device_id>",
            "identity": "<identity>",
            "publicKey": "<public_key>",
            "rotationHash": "<rotation_hash>"
        }
    }

    Attributes:
        payload: Dictionary containing authentication data for the new device.
        signature: Optional cryptographic signature from an existing device.
    """

    def __init__(
        self,
        payload: Dict[str, Dict[str, str]]
    ) -> None:
        """Initialize a link container.

        Args:
            payload: Dictionary containing authentication data with keys:
                - authentication: Dict containing device, identity, publicKey,
                  and rotationHash.
        """
        super().__init__()
        self.payload = payload

    def compose_payload(self) -> str:
        """Compose the payload into a JSON string for signing.

        Returns:
            The JSON-serialized payload.

        Raises:
            RuntimeError: If payload is not defined.
        """
        if self.payload is None:
            raise RuntimeError("payload not defined")

        return json.dumps(self.payload, separators=(',', ':'), sort_keys=False)

    @staticmethod
    def parse(message: str) -> LinkContainer:
        """Parse a serialized link container message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new LinkContainer instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        json_data = json.loads(message)
        result = LinkContainer(json_data["payload"])
        result.signature = json_data.get("signature")
        return result


class LinkDeviceRequest(ClientRequest[Dict[str, Any]]):
    """Request message for linking a new device to an account.

    This message contains both the current device's authentication information
    and a signed link container with the new device's credentials.

    The request payload structure is:
    {
        "authentication": {
            "device": "<current_device_id>",
            "identity": "<identity>"
        },
        "link": {
            "payload": {
                "authentication": {
                    "device": "<new_device_id>",
                    "identity": "<identity>",
                    "publicKey": "<new_public_key>",
                    "rotationHash": "<new_rotation_hash>"
                }
            },
            "signature": "<signature_from_existing_device>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and link request data.
        signature: Optional cryptographic signature.
    """

    def __init__(
        self,
        request: Dict[str, Any],
        nonce: str
    ) -> None:
        """Initialize a link device request.

        Args:
            request: Dictionary containing authentication and link data with keys:
                - authentication: Dict containing current device and identity.
                - link: LinkContainer data with new device credentials.
            nonce: The nonce for replay protection.
        """
        super().__init__(request, nonce)

    @staticmethod
    def parse(message: str) -> LinkDeviceRequest:
        """Parse a serialized link device request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new LinkDeviceRequest instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, LinkDeviceRequest)


class LinkDeviceResponse(ServerResponse[Dict[str, Any]]):
    """Response message for device linking.

    This message confirms successful device linking. The response payload
    is an empty dictionary.

    Attributes:
        payload: Dictionary containing access metadata and empty response.
        signature: Optional cryptographic signature.
    """

    def __init__(
        self,
        response: Dict[str, Any],
        response_key_hash: str,
        nonce: str
    ) -> None:
        """Initialize a link device response.

        Args:
            response: Empty dictionary response payload.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> LinkDeviceResponse:
        """Parse a serialized link device response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new LinkDeviceResponse instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, LinkDeviceResponse)