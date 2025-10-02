"""Message classes for better-auth protocol.

This module provides the base message classes for client-server communication
with cryptographic signing and verification support.
"""

from better_auth.messages.access import AccessRequest, AccessToken
from better_auth.messages.authentication import (
    FinishAuthenticationRequest,
    FinishAuthenticationResponse,
    StartAuthenticationRequest,
    StartAuthenticationResponse,
)
from better_auth.messages.creation import CreationRequest, CreationResponse
from better_auth.messages.linking import (
    LinkContainer,
    LinkDeviceRequest,
    LinkDeviceResponse,
    UnlinkDeviceRequest,
    UnlinkDeviceResponse,
)
from better_auth.messages.message import SerializableMessage, SignableMessage
from better_auth.messages.recovery import RecoverAccountRequest, RecoverAccountResponse
from better_auth.messages.refresh import (
    RefreshAccessTokenRequest,
    RefreshAccessTokenResponse,
)
from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ScannableResponse, ServerResponse
from better_auth.messages.rotation import (
    RotateAuthenticationKeyRequest,
    RotateAuthenticationKeyResponse,
)

__all__ = [
    # Base classes
    "SerializableMessage",
    "SignableMessage",
    "ClientRequest",
    "ServerResponse",
    "ScannableResponse",
    # Access
    "AccessToken",
    "AccessRequest",
    # Authentication
    "StartAuthenticationRequest",
    "StartAuthenticationResponse",
    "FinishAuthenticationRequest",
    "FinishAuthenticationResponse",
    # Creation
    "CreationRequest",
    "CreationResponse",
    # Linking
    "LinkContainer",
    "LinkDeviceRequest",
    "LinkDeviceResponse",
    "UnlinkDeviceRequest",
    "UnlinkDeviceResponse",
    # Recovery
    "RecoverAccountRequest",
    "RecoverAccountResponse",
    # Refresh
    "RefreshAccessTokenRequest",
    "RefreshAccessTokenResponse",
    # Rotation
    "RotateAuthenticationKeyRequest",
    "RotateAuthenticationKeyResponse",
]
