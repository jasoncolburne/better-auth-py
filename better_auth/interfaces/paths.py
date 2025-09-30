"""Authentication path configuration interfaces for better-auth.

This module defines protocols for authentication endpoint paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypedDict


class AuthenticatePathsDict(TypedDict):
    """Authentication endpoint paths."""

    start: str
    finish: str


class RegisterPathsDict(TypedDict):
    """Registration endpoint paths."""

    create: str
    link: str
    recover: str


class RotatePathsDict(TypedDict):
    """Key rotation endpoint paths."""

    authentication: str
    access: str


class IAuthenticationPaths(Protocol):
    """Interface for authentication path configuration."""

    @property
    def authenticate(self) -> AuthenticatePathsDict:
        """Authentication endpoint paths.

        Returns:
            Dictionary containing 'start' and 'finish' paths.
        """
        ...

    @property
    def register(self) -> RegisterPathsDict:
        """Registration endpoint paths.

        Returns:
            Dictionary containing 'create', 'link', and 'recover' paths.
        """
        ...

    @property
    def rotate(self) -> RotatePathsDict:
        """Key rotation endpoint paths.

        Returns:
            Dictionary containing 'authentication' and 'access' paths.
        """
        ...


@dataclass
class AuthenticatePaths:
    """Authentication endpoint paths.

    Attributes:
        start: Path for starting authentication.
        finish: Path for finishing authentication.
    """

    start: str
    finish: str


@dataclass
class RegisterPaths:
    """Registration endpoint paths.

    Attributes:
        create: Path for account creation.
        link: Path for device linking.
        recover: Path for account recovery.
    """

    create: str
    link: str
    recover: str


@dataclass
class RotatePaths:
    """Key rotation endpoint paths.

    Attributes:
        authentication: Path for authentication key rotation.
        access: Path for access token refresh.
    """

    authentication: str
    access: str


@dataclass
class AuthenticationPaths:
    """Concrete implementation of authentication path configuration.

    Attributes:
        authenticate: Authentication endpoint paths.
        register: Registration endpoint paths.
        rotate: Key rotation endpoint paths.
    """

    authenticate: AuthenticatePaths
    register: RegisterPaths
    rotate: RotatePaths
