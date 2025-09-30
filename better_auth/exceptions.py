"""Exception classes for better-auth.

This module defines custom exception types used throughout the better-auth library.
"""


class BetterAuthError(Exception):
    """Base exception class for all better-auth errors."""

    pass


class VerificationError(BetterAuthError):
    """Exception raised when signature or token verification fails."""

    pass


class StorageError(BetterAuthError):
    """Exception raised for storage-related errors."""

    pass


class EncodingError(BetterAuthError):
    """Exception raised for encoding/decoding errors."""

    pass


class AuthenticationError(BetterAuthError):
    """Exception raised for authentication failures."""

    pass


class InvalidMessageError(BetterAuthError):
    """Exception raised when a message is malformed or invalid."""

    pass


class ExpiredTokenError(BetterAuthError):
    """Exception raised when a token has expired."""

    pass


class InvalidNonceError(BetterAuthError):
    """Exception raised when a nonce is invalid or expired."""

    pass