"""Better-auth Python implementation.

This package provides a complete Python implementation of the better-auth protocol,
an agnostic authentication framework that composes cryptographic and storage
interfaces you provide.

Main Components:
    - BetterAuthClient: Client-side authentication
    - BetterAuthServer: Server-side authentication
    - AccessVerifier: Access token verification
    - Interfaces: Protocol definitions for crypto, storage, encoding
    - Messages: Protocol message types

Example:
    >>> from better_auth import BetterAuthClient, BetterAuthServer
    >>> # Configure and use client/server with your crypto and storage backends
"""

from better_auth.api import (
    AccessVerifier,
    BetterAuthClient,
    BetterAuthClientConfig,
    BetterAuthServer,
    BetterAuthServerConfig,
)
from better_auth.exceptions import (
    BetterAuthError,
    ExpiredTokenError,
    FutureRequestError,
    FutureTokenError,
    IncorrectNonceError,
    InvalidDeviceError,
    InvalidHashError,
    InvalidIdentityError,
    InvalidMessageError,
    MismatchedIdentitiesError,
    StaleRequestError,
)

__version__ = "0.1.0"

__all__ = [
    # API
    "BetterAuthClient",
    "BetterAuthServer",
    "AccessVerifier",
    "BetterAuthClientConfig",
    "BetterAuthServerConfig",
    # Exceptions - All 10 kept error types
    "BetterAuthError",
    "InvalidMessageError",
    "InvalidIdentityError",
    "InvalidDeviceError",
    "InvalidHashError",
    "IncorrectNonceError",
    "MismatchedIdentitiesError",
    "ExpiredTokenError",
    "FutureTokenError",
    "StaleRequestError",
    "FutureRequestError",
]
