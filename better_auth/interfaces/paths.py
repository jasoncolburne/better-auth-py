"""Authentication path configuration interfaces for better-auth.

This module defines protocols for authentication endpoint paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypedDict


class AccountPathsDict(TypedDict):
    """Account endpoint paths."""

    create: str
    recover: str


class SessionPathsDict(TypedDict):
    """Session endpoint paths."""

    request: str
    connect: str
    refresh: str


class DevicePathsDict(TypedDict):
    """Device endpoint paths."""

    rotate: str
    link: str
    unlink: str


class IAuthenticationPaths(Protocol):
    """Interface for authentication path configuration."""

    @property
    def account(self) -> AccountPathsDict:
        """Account endpoint paths.

        Returns:
            Dictionary containing 'create' and 'recover' paths.
        """
        ...

    @property
    def session(self) -> SessionPathsDict:
        """Session endpoint paths.

        Returns:
            Dictionary containing 'request', 'connect', and 'refresh' paths.
        """
        ...

    @property
    def device(self) -> DevicePathsDict:
        """Device endpoint paths.

        Returns:
            Dictionary containing 'rotate', 'link', and 'unlink' paths.
        """
        ...


@dataclass
class AccountPaths:
    """Account endpoint paths.

    Attributes:
        create: Path for account creation.
        recover: Path for account recovery.
    """

    create: str
    recover: str


@dataclass
class SessionPaths:
    """Session endpoint paths.

    Attributes:
        request: Path for session request.
        connect: Path for session connect.
        refresh: Path for session refresh.
    """

    request: str
    connect: str
    refresh: str


@dataclass
class DevicePaths:
    """Device endpoint paths.

    Attributes:
        rotate: Path for device key rotation.
        link: Path for device linking.
        unlink: Path for device unlinking.
    """

    rotate: str
    link: str
    unlink: str


@dataclass
class AuthenticationPaths:
    """Concrete implementation of authentication path configuration.

    Attributes:
        account: Account endpoint paths.
        session: Session endpoint paths.
        device: Device endpoint paths.
    """

    account: AccountPaths
    session: SessionPaths
    device: DevicePaths
