"""Recovery protocol messages for better-auth."""

from __future__ import annotations

from dataclasses import dataclass

from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ServerResponse


@dataclass
class ChangeRecoveryKeyRequestData:
    """Data for recovery key change request.

    Attributes:
        device: Device identifier
        identity: Identity identifier
        public_key: Current authentication public key
        recovery_hash: New recovery hash
        rotation_hash: Next rotation hash
    """

    device: str
    identity: str
    public_key: str
    recovery_hash: str
    rotation_hash: str


class ChangeRecoveryKeyRequest(ClientRequest[ChangeRecoveryKeyRequestData]):
    """Request to change recovery key."""

    @classmethod
    def parse(cls, message: str) -> ChangeRecoveryKeyRequest:
        """Parse a serialized message.

        Args:
            message: The serialized message.

        Returns:
            Parsed ChangeRecoveryKeyRequest instance.
        """
        return ClientRequest._parse(message, cls)


@dataclass
class ChangeRecoveryKeyResponseData:
    """Empty response data for recovery key change."""

    pass


class ChangeRecoveryKeyResponse(ServerResponse[ChangeRecoveryKeyResponseData]):
    """Response to recovery key change request."""

    @classmethod
    def parse(cls, message: str) -> ChangeRecoveryKeyResponse:
        """Parse a serialized message.

        Args:
            message: The serialized message.

        Returns:
            Parsed ChangeRecoveryKeyResponse instance.
        """
        return ServerResponse._parse(message, cls)
