"""Authentication path configuration interfaces for better-auth.

This module defines protocols for authentication endpoint paths.
"""

from __future__ import annotations

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
