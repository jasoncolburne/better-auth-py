"""Message classes for better-auth protocol.

This module provides the base message classes for client-server communication
with cryptographic signing and verification support.
"""

from better_auth.messages.access import AccessRequest, AccessToken
from better_auth.messages.account import (
    CreateAccountRequest,
    CreateAccountResponse,
    DeleteAccountRequest,
    DeleteAccountResponse,
    RecoverAccountRequest,
    RecoverAccountResponse,
)
from better_auth.messages.device import (
    LinkContainer,
    LinkDeviceRequest,
    LinkDeviceResponse,
    RotateDeviceRequest,
    RotateDeviceResponse,
    UnlinkDeviceRequest,
    UnlinkDeviceResponse,
)
from better_auth.messages.message import SerializableMessage, SignableMessage
from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ScannableResponse, ServerResponse
from better_auth.messages.session import (
    CreateSessionRequest,
    CreateSessionResponse,
    RefreshSessionRequest,
    RefreshSessionResponse,
    RequestSessionRequest,
    RequestSessionResponse,
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
    # Account
    "CreateAccountRequest",
    "CreateAccountResponse",
    "DeleteAccountRequest",
    "DeleteAccountResponse",
    "RecoverAccountRequest",
    "RecoverAccountResponse",
    # Device
    "LinkContainer",
    "LinkDeviceRequest",
    "LinkDeviceResponse",
    "UnlinkDeviceRequest",
    "UnlinkDeviceResponse",
    "RotateDeviceRequest",
    "RotateDeviceResponse",
    # Session
    "RequestSessionRequest",
    "RequestSessionResponse",
    "CreateSessionRequest",
    "CreateSessionResponse",
    "RefreshSessionRequest",
    "RefreshSessionResponse",
]
